//! WebDAV core methods: OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, COPY, MOVE, DELETE, PROPPATCH
//! (dead properties), LOCK, and UNLOCK, plus path handling and dead-property bookkeeping.

use gono_acceptance::{
    Cred, Ctx, DAV, OC,
    dav::{
        DEAD_NS, LOCKINFO_EXCLUSIVE, PROPFIND_STANDARD, encode_path, propfind_dead,
        proppatch_remove_dead, proppatch_set_dead,
    },
    raw, skip,
};

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[tokio::test]
async fn options_advertises_dav_classes_and_methods() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("file.txt"), "x").await;

    for (rel, methods) in [
        (
            ctx.dir.clone(),
            &[
                "OPTIONS", "PROPFIND", "COPY", "MOVE", "DELETE", "LOCK", "UNLOCK",
            ][..],
        ),
        (
            ctx.path("file.txt"),
            &[
                "OPTIONS", "GET", "HEAD", "PUT", "PROPFIND", "COPY", "MOVE", "DELETE", "LOCK",
                "UNLOCK",
            ][..],
        ),
    ] {
        let response = dav.send(dav.request("OPTIONS", &dav.url(&rel))).await;
        response.expect(&[200, 204]);
        let classes = response
            .header("dav")
            .unwrap_or_else(|| panic!("OPTIONS without DAV header\n{}", response.describe()));
        let classes: Vec<&str> = classes.split(',').map(str::trim).collect();
        assert!(
            classes.contains(&"1") && classes.contains(&"2"),
            "DAV header must advertise classes 1 and 2 (locking)\n{}",
            response.describe()
        );
        let allow = response
            .header("allow")
            .unwrap_or_else(|| panic!("OPTIONS without Allow header\n{}", response.describe()))
            .to_ascii_uppercase();
        let allowed: Vec<&str> = allow.split(',').map(str::trim).collect();
        for method in methods {
            assert!(
                allowed.contains(method),
                "Allow for {rel} lacks {method}\n{}",
                response.describe()
            );
        }
    }
}

#[tokio::test]
async fn requests_without_credentials_are_challenged() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("secret.txt"), "secret").await;

    for (method, rel) in [
        ("PROPFIND", String::new()),
        ("GET", ctx.path("secret.txt")),
        ("PUT", ctx.path("anonymous.txt")),
    ] {
        let request = ctx
            .http
            .request(gono_acceptance::dav::method(method), dav.url(&rel))
            .header("Depth", "0");
        let response = gono_acceptance::dav::send(&ctx.http, request).await;
        response.expect(&[401]);
        let challenge = response.header("www-authenticate").unwrap_or_default();
        assert!(
            challenge.to_ascii_lowercase().starts_with("basic"),
            "401 must carry a Basic challenge\n{}",
            response.describe()
        );
    }
    dav.get(&ctx.path("anonymous.txt")).await.expect(&[404]);
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let Some(ctx) = Ctx::new().await else { return };
    let wrong = Cred::new(&ctx.cfg.full.user, "definitely-not-the-password");
    let response = ctx
        .dav_as(&wrong)
        .propfind(&ctx.dir, "0", PROPFIND_STANDARD)
        .await;
    response.expect(&[401]);
}

#[tokio::test]
async fn propfind_depth_0_returns_only_the_target() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("child.txt"), "child").await;

    let multistatus = dav
        .propfind(&ctx.dir, "0", PROPFIND_STANDARD)
        .await
        .multistatus();
    assert_eq!(multistatus.paths(), vec![dav.href_path(&ctx.dir)]);
    let entry = &multistatus.responses[0];
    assert!(entry.is_collection(), "{entry:?}");
    assert!(entry.text(DAV, "getetag").is_some(), "{entry:?}");

    let root = dav.propfind("", "0", PROPFIND_STANDARD).await.multistatus();
    assert_eq!(root.paths(), vec![dav.href_path("")]);
    assert!(root.responses[0].is_collection());
}

#[tokio::test]
async fn propfind_depth_1_lists_direct_children() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("a.txt"), "hello").await;
    dav.create_dir(&ctx.path("sub")).await;
    dav.write(&ctx.path("sub/deep.txt"), "deep").await;

    let multistatus = dav
        .propfind(&ctx.dir, "1", PROPFIND_STANDARD)
        .await
        .multistatus();
    assert_eq!(
        sorted(multistatus.paths()),
        sorted(vec![
            dav.href_path(&ctx.dir),
            dav.href_path(&ctx.path("a.txt")),
            dav.href_path(&ctx.path("sub")),
        ])
    );
    let file = multistatus.get(&dav.href_path(&ctx.path("a.txt"))).unwrap();
    assert!(!file.is_collection());
    assert_eq!(file.text(DAV, "getcontentlength").as_deref(), Some("5"));
    let sub = multistatus.get(&dav.href_path(&ctx.path("sub"))).unwrap();
    assert!(sub.is_collection());
}

/// Listings of large folders are big XML documents; Nextcloud gzips them for clients that ask,
/// and so does the server. File contents are never compressed.
#[tokio::test]
async fn propfind_is_gzipped_on_request_but_downloads_are_not() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let content = "<?xml version=\"1.0\"?><x>not a listing</x>";
    dav.write(&ctx.path("file.xml"), content).await;

    let listing = dav
        .send(
            dav.request("PROPFIND", &dav.url(&ctx.dir))
                .header("Depth", "1")
                .header("Accept-Encoding", "gzip")
                .body(PROPFIND_STANDARD),
        )
        .await;
    listing.expect(&[207]);
    assert_eq!(
        listing.header("content-encoding").as_deref(),
        Some("gzip"),
        "{}",
        listing.describe()
    );
    assert!(listing.body.starts_with(&[0x1f, 0x8b]), "gzip magic");
    let plain = dav.propfind(&ctx.dir, "1", PROPFIND_STANDARD).await;
    assert_eq!(plain.header("content-encoding"), None);

    let download = dav
        .send(
            dav.request("GET", &dav.url(&ctx.path("file.xml")))
                .header("Accept-Encoding", "gzip"),
        )
        .await;
    download.expect(&[200]);
    assert_eq!(download.header("content-encoding"), None);
    assert_eq!(download.body, content.as_bytes());
}

/// Nextcloud (SabreDAV without `enablePropfindDepthInfinity`) answers `Depth: infinity` like
/// `Depth: 1`. The Nextcloud iOS app lists folders made available offline that way and
/// downloads nothing when it gets an error.
#[tokio::test]
async fn propfind_depth_infinity_is_answered_like_depth_1() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("sub")).await;
    dav.write(&ctx.path("sub/deep.txt"), "deep").await;
    dav.write(&ctx.path("top.txt"), "top").await;
    let multistatus = dav
        .propfind(&ctx.dir, "infinity", PROPFIND_STANDARD)
        .await
        .expect(&[207])
        .multistatus();
    let mut paths = multistatus.paths();
    paths.sort();
    let mut expected = vec![
        dav.href_path(&ctx.dir),
        dav.href_path(&ctx.path("sub")),
        dav.href_path(&ctx.path("top.txt")),
    ];
    expected.sort();
    assert_eq!(paths, expected);
}

#[tokio::test]
async fn propfind_without_body_returns_allprop() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("allprop.txt"), "allprop").await;

    let response = dav
        .send(
            dav.request("PROPFIND", &dav.url(&ctx.path("allprop.txt")))
                .header("Depth", "0"),
        )
        .await;
    let multistatus = response.multistatus();
    let entry = multistatus
        .get(&dav.href_path(&ctx.path("allprop.txt")))
        .unwrap_or_else(|| panic!("no entry\n{}", response.describe()));
    for name in [
        "getetag",
        "getlastmodified",
        "getcontentlength",
        "resourcetype",
    ] {
        assert!(
            entry.prop(DAV, name).is_some(),
            "allprop lacks DAV:{name}\n{}",
            response.describe()
        );
    }
}

#[tokio::test]
async fn propfind_reports_unknown_props_as_404() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("props.txt"), "x").await;

    let response = dav
        .propfind(&ctx.path("props.txt"), "0", &propfind_dead(&["never-set"]))
        .await;
    let multistatus = response.multistatus();
    let entry = multistatus
        .get(&dav.href_path(&ctx.path("props.txt")))
        .unwrap();
    assert_eq!(
        entry.prop_status(DEAD_NS, "never-set"),
        Some(404),
        "{}",
        response.describe()
    );
    assert!(
        entry.text(OC, "fileid").is_some(),
        "{}",
        response.describe()
    );
}

#[tokio::test]
async fn propfind_on_missing_resource_is_404() {
    let Some(ctx) = Ctx::new().await else { return };
    ctx.dav()
        .propfind(&ctx.path("missing"), "0", PROPFIND_STANDARD)
        .await
        .expect(&[404]);
}

#[tokio::test]
async fn put_creates_and_get_returns_content() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let put = dav.put(&ctx.path("hello.txt"), "hello world").await;
    put.expect(&[201]);

    let get = dav.get(&ctx.path("hello.txt")).await;
    get.expect(&[200]);
    assert_eq!(get.body, b"hello world");
    assert_eq!(get.header("content-length").as_deref(), Some("11"));
    assert!(get.header("etag").is_some(), "{}", get.describe());
    assert!(get.header("last-modified").is_some(), "{}", get.describe());
}

#[tokio::test]
async fn put_overwrite_replaces_content() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.put(&ctx.path("file.txt"), "first version")
        .await
        .expect(&[201]);
    dav.put(&ctx.path("file.txt"), "second")
        .await
        .expect(&[204]);
    assert_eq!(dav.read(&ctx.path("file.txt")).await, b"second");
}

#[tokio::test]
async fn put_empty_body_creates_empty_file() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.put(&ctx.path("empty.txt"), "").await.expect(&[201]);
    let get = dav.get(&ctx.path("empty.txt")).await;
    get.expect(&[200]);
    assert!(get.body.is_empty());
    let entry = dav.stat(&ctx.path("empty.txt")).await;
    assert_eq!(entry.text(DAV, "getcontentlength").as_deref(), Some("0"));
}

#[tokio::test]
async fn put_large_body_roundtrips() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let body: Vec<u8> = (0..(3 * 1024 * 1024 + 17))
        .map(|index: u32| (index.wrapping_mul(31) % 251) as u8)
        .collect();
    dav.put(&ctx.path("large.bin"), body.clone())
        .await
        .expect(&[201]);
    assert_eq!(dav.read(&ctx.path("large.bin")).await, body);
}

#[tokio::test]
async fn head_returns_metadata_without_body() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("head.txt"), "twelve bytes").await;

    let head = dav.head(&ctx.path("head.txt")).await;
    head.expect(&[200]);
    assert!(head.body.is_empty(), "{}", head.describe());
    assert_eq!(
        head.header("content-length").as_deref(),
        Some("12"),
        "{}",
        head.describe()
    );
    assert!(head.header("etag").is_some(), "{}", head.describe());

    dav.head(&ctx.path("missing.txt")).await.expect(&[404]);
}

/// The web login and the admin UI share the server's origin, so a user's HTML must never run
/// there: file contents are attachments, and the responses are sandboxed.
#[tokio::test]
async fn downloads_are_sandboxed_attachments() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("page.html");
    dav.write(&rel, "<html><script>document.title = 'x'</script></html>")
        .await;
    let response = dav.get(&rel).await;
    response.expect(&[200]);
    assert_eq!(
        response.header("content-disposition").as_deref(),
        Some("attachment; filename*=UTF-8''page.html"),
        "{}",
        response.describe()
    );
    assert!(
        response
            .header("content-security-policy")
            .is_some_and(|csp| csp.contains("sandbox")),
        "{}",
        response.describe()
    );
    assert_eq!(
        response.header("x-content-type-options").as_deref(),
        Some("nosniff"),
        "{}",
        response.describe()
    );
}

#[tokio::test]
async fn get_on_missing_resource_is_404() {
    let Some(ctx) = Ctx::new().await else { return };
    ctx.dav().get(&ctx.path("missing.txt")).await.expect(&[404]);
}

#[tokio::test]
async fn put_into_missing_parent_is_409() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.put(&ctx.path("missing/parent/file.txt"), "x")
        .await
        .expect(&[409]);
    dav.get(&ctx.path("missing")).await.expect(&[404]);
}

#[tokio::test]
async fn put_onto_collection_is_rejected() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("dir")).await;
    let response = dav.put(&ctx.path("dir"), "not a directory").await;
    assert!(
        response.status.is_client_error(),
        "PUT onto a collection must fail with 4xx\n{}",
        response.describe()
    );
    assert!(dav.stat(&ctx.path("dir")).await.is_collection());
}

#[tokio::test]
async fn mkcol_creates_collection() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.mkcol(&ctx.path("new-dir")).await.expect(&[201]);
    assert!(dav.stat(&ctx.path("new-dir")).await.is_collection());
    dav.write(&ctx.path("new-dir/inside.txt"), "inside").await;
}

#[tokio::test]
async fn mkcol_on_existing_resource_is_405() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("dir")).await;
    dav.write(&ctx.path("file.txt"), "x").await;
    dav.mkcol(&ctx.path("dir")).await.expect(&[405]);
    dav.mkcol(&ctx.path("file.txt")).await.expect(&[405]);
}

#[tokio::test]
async fn mkcol_with_missing_parent_is_409() {
    let Some(ctx) = Ctx::new().await else { return };
    ctx.dav()
        .mkcol(&ctx.path("missing/child"))
        .await
        .expect(&[409]);
}

#[tokio::test]
async fn delete_file_removes_it() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("doomed.txt"), "x").await;
    dav.delete(&ctx.path("doomed.txt")).await.expect(&[204]);
    dav.get(&ctx.path("doomed.txt")).await.expect(&[404]);
    dav.delete(&ctx.path("doomed.txt")).await.expect(&[404]);
}

#[tokio::test]
async fn delete_collection_removes_descendants() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir_all(&ctx.path("tree/a/b")).await;
    dav.write(&ctx.path("tree/a/b/leaf.txt"), "leaf").await;
    dav.write(&ctx.path("tree/top.txt"), "top").await;

    dav.delete(&ctx.path("tree")).await.expect(&[204]);
    for rel in ["tree", "tree/top.txt", "tree/a", "tree/a/b/leaf.txt"] {
        dav.propfind(&ctx.path(rel), "0", PROPFIND_STANDARD)
            .await
            .expect(&[404]);
    }
}

#[tokio::test]
async fn copy_file_creates_an_independent_copy() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("source.txt"), "source").await;

    dav.copy(&ctx.path("source.txt"), &ctx.path("copy.txt"), None)
        .await
        .expect(&[201]);
    assert_eq!(dav.read(&ctx.path("copy.txt")).await, b"source");

    dav.write(&ctx.path("copy.txt"), "changed copy").await;
    assert_eq!(dav.read(&ctx.path("source.txt")).await, b"source");
}

#[tokio::test]
async fn copy_onto_existing_overwrites_by_default() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("source.txt"), "source").await;
    dav.write(&ctx.path("target.txt"), "target").await;

    dav.copy(&ctx.path("source.txt"), &ctx.path("target.txt"), None)
        .await
        .expect(&[204]);
    assert_eq!(dav.read(&ctx.path("target.txt")).await, b"source");
}

#[tokio::test]
async fn copy_with_overwrite_false_onto_existing_is_412() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("source.txt"), "source").await;
    dav.write(&ctx.path("target.txt"), "target").await;

    dav.copy(
        &ctx.path("source.txt"),
        &ctx.path("target.txt"),
        Some(false),
    )
    .await
    .expect(&[412]);
    assert_eq!(dav.read(&ctx.path("target.txt")).await, b"target");
}

#[tokio::test]
async fn copy_collection_is_recursive() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir_all(&ctx.path("src/nested")).await;
    dav.write(&ctx.path("src/nested/leaf.txt"), "leaf").await;
    dav.write(&ctx.path("src/top.txt"), "top").await;

    dav.copy(&ctx.path("src"), &ctx.path("dst"), None)
        .await
        .expect(&[201]);
    assert_eq!(dav.read(&ctx.path("dst/nested/leaf.txt")).await, b"leaf");
    assert_eq!(dav.read(&ctx.path("dst/top.txt")).await, b"top");
    assert_eq!(dav.read(&ctx.path("src/top.txt")).await, b"top");
}

#[tokio::test]
async fn move_file_renames_it() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("before.txt"), "content").await;

    dav.mv(&ctx.path("before.txt"), &ctx.path("after.txt"), None)
        .await
        .expect(&[201]);
    dav.get(&ctx.path("before.txt")).await.expect(&[404]);
    assert_eq!(dav.read(&ctx.path("after.txt")).await, b"content");
}

#[tokio::test]
async fn move_onto_existing_overwrites_by_default() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("source.txt"), "source").await;
    dav.write(&ctx.path("target.txt"), "target").await;

    dav.mv(&ctx.path("source.txt"), &ctx.path("target.txt"), None)
        .await
        .expect(&[204]);
    dav.get(&ctx.path("source.txt")).await.expect(&[404]);
    assert_eq!(dav.read(&ctx.path("target.txt")).await, b"source");
}

#[tokio::test]
async fn move_with_overwrite_false_onto_existing_is_412() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("source.txt"), "source").await;
    dav.write(&ctx.path("target.txt"), "target").await;

    dav.mv(
        &ctx.path("source.txt"),
        &ctx.path("target.txt"),
        Some(false),
    )
    .await
    .expect(&[412]);
    assert_eq!(dav.read(&ctx.path("source.txt")).await, b"source");
    assert_eq!(dav.read(&ctx.path("target.txt")).await, b"target");
}

#[tokio::test]
async fn move_collection_moves_descendants() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir_all(&ctx.path("old/nested")).await;
    dav.write(&ctx.path("old/nested/leaf.txt"), "leaf").await;

    dav.mv(&ctx.path("old"), &ctx.path("new"), None)
        .await
        .expect(&[201]);
    dav.propfind(&ctx.path("old"), "0", PROPFIND_STANDARD)
        .await
        .expect(&[404]);
    assert_eq!(dav.read(&ctx.path("new/nested/leaf.txt")).await, b"leaf");
}

#[tokio::test]
async fn copy_and_move_into_missing_parent_are_409() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("source.txt"), "source").await;

    dav.copy(&ctx.path("source.txt"), &ctx.path("missing/copy.txt"), None)
        .await
        .expect(&[409]);
    dav.mv(
        &ctx.path("source.txt"),
        &ctx.path("missing/moved.txt"),
        None,
    )
    .await
    .expect(&[409]);
    assert_eq!(dav.read(&ctx.path("source.txt")).await, b"source");
}

#[tokio::test]
async fn proppatch_sets_and_removes_dead_props() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("props.txt");
    dav.write(&rel, "props").await;

    let set = dav
        .proppatch(
            &rel,
            &proppatch_set_dead(&[("color", "blue <&> \"quoted\""), ("size", "large")]),
        )
        .await;
    let multistatus = set.multistatus();
    let entry = multistatus.get(&dav.href_path(&rel)).unwrap();
    assert_eq!(entry.prop_status(DEAD_NS, "color"), Some(200));
    assert_eq!(entry.prop_status(DEAD_NS, "size"), Some(200));

    let found = dav
        .propfind(&rel, "0", &propfind_dead(&["color", "size"]))
        .await
        .multistatus();
    let entry = found.get(&dav.href_path(&rel)).unwrap();
    assert_eq!(
        entry.text(DEAD_NS, "color").as_deref(),
        Some("blue <&> \"quoted\"")
    );
    assert_eq!(entry.text(DEAD_NS, "size").as_deref(), Some("large"));

    let remove = dav
        .proppatch(&rel, &proppatch_remove_dead(&["color"]))
        .await;
    remove.multistatus();

    let found = dav
        .propfind(&rel, "0", &propfind_dead(&["color", "size"]))
        .await
        .multistatus();
    let entry = found.get(&dav.href_path(&rel)).unwrap();
    assert_eq!(entry.prop_status(DEAD_NS, "color"), Some(404), "{entry:?}");
    assert_eq!(entry.text(DEAD_NS, "size").as_deref(), Some("large"));
}

#[tokio::test]
async fn dead_props_on_collections_roundtrip() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("dir");
    dav.create_dir(&rel).await;
    dav.proppatch(&rel, &proppatch_set_dead(&[("label", "folder")]))
        .await
        .multistatus();
    let found = dav
        .propfind(&rel, "0", &propfind_dead(&["label"]))
        .await
        .multistatus();
    assert_eq!(
        found
            .get(&dav.href_path(&rel))
            .unwrap()
            .text(DEAD_NS, "label")
            .as_deref(),
        Some("folder")
    );
}

#[tokio::test]
async fn dead_props_follow_copy_and_move() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("dir")).await;
    dav.write(&ctx.path("dir/file.txt"), "x").await;
    dav.proppatch(
        &ctx.path("dir/file.txt"),
        &proppatch_set_dead(&[("tag", "kept")]),
    )
    .await
    .multistatus();

    dav.copy(&ctx.path("dir"), &ctx.path("copied"), None)
        .await
        .expect(&[201]);
    dav.mv(&ctx.path("dir"), &ctx.path("moved"), None)
        .await
        .expect(&[201]);

    for rel in ["copied/file.txt", "moved/file.txt"] {
        let found = dav
            .propfind(&ctx.path(rel), "0", &propfind_dead(&["tag"]))
            .await
            .multistatus();
        let entry = found.get(&dav.href_path(&ctx.path(rel))).unwrap();
        assert_eq!(entry.text(DEAD_NS, "tag").as_deref(), Some("kept"), "{rel}");
    }
}

#[tokio::test]
async fn dead_props_do_not_survive_delete_and_recreate() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("reborn.txt");
    dav.write(&rel, "first life").await;
    dav.proppatch(&rel, &proppatch_set_dead(&[("ghost", "boo")]))
        .await
        .multistatus();
    dav.delete(&rel).await.expect(&[204]);
    dav.put(&rel, "second life").await.expect(&[201]);

    let found = dav
        .propfind(&rel, "0", &propfind_dead(&["ghost"]))
        .await
        .multistatus();
    let entry = found.get(&dav.href_path(&rel)).unwrap();
    assert_eq!(entry.prop_status(DEAD_NS, "ghost"), Some(404), "{entry:?}");
}

/// Extracts the lock token from a LOCK response.
fn lock_token(response: &gono_acceptance::Resp) -> String {
    response
        .header("lock-token")
        .unwrap_or_else(|| panic!("LOCK without Lock-Token\n{}", response.describe()))
        .trim()
        .to_owned()
}

#[tokio::test]
async fn lock_blocks_writes_without_the_token() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("locked.txt");
    dav.write(&rel, "before").await;

    let lock = dav
        .send(
            dav.request("LOCK", &dav.url(&rel))
                .header("Depth", "0")
                .header("Timeout", "Second-60")
                .header("Content-Type", "application/xml; charset=utf-8")
                .body(LOCKINFO_EXCLUSIVE),
        )
        .await;
    lock.expect(&[200]);
    let token = lock_token(&lock);
    assert!(
        token.starts_with('<') && token.ends_with('>'),
        "Lock-Token must be a coded URL: {token}"
    );
    let body = lock.text();
    assert!(
        body.contains("activelock") && body.contains(token.trim_matches(['<', '>'])),
        "LOCK body must contain the active lock\n{}",
        lock.describe()
    );

    let blocked_put = dav.put(&rel, "blocked").await;
    let blocked_delete = dav.delete(&rel).await;
    let blocked_move = dav.mv(&rel, &ctx.path("moved.txt"), None).await;
    let with_token = dav
        .send(
            dav.request("PUT", &dav.url(&rel))
                .header("If", format!("({token})"))
                .body("with token"),
        )
        .await;
    let unlock = dav
        .send(
            dav.request("UNLOCK", &dav.url(&rel))
                .header("Lock-Token", &token),
        )
        .await;

    blocked_put.expect(&[423]);
    blocked_delete.expect(&[423]);
    blocked_move.expect(&[423]);
    with_token.expect(&[204]);
    unlock.expect(&[204]);

    dav.put(&rel, "after unlock").await.expect(&[204]);
    assert_eq!(dav.read(&rel).await, b"after unlock");
}

#[tokio::test]
async fn second_exclusive_lock_is_423() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("contended.txt");
    dav.write(&rel, "x").await;

    let lock = || {
        dav.request("LOCK", &dav.url(&rel))
            .header("Depth", "0")
            .header("Timeout", "Second-60")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(LOCKINFO_EXCLUSIVE)
    };
    let first = dav.send(lock()).await;
    first.expect(&[200]);
    let token = lock_token(&first);
    let second = dav.send(lock()).await;
    let unlock = dav
        .send(
            dav.request("UNLOCK", &dav.url(&rel))
                .header("Lock-Token", &token),
        )
        .await;
    second.expect(&[423]);
    unlock.expect(&[204]);
}

#[tokio::test]
async fn unlock_with_unknown_token_fails() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("unlocked.txt");
    dav.write(&rel, "x").await;
    let response = dav
        .send(dav.request("UNLOCK", &dav.url(&rel)).header(
            "Lock-Token",
            "<urn:uuid:00000000-0000-4000-8000-000000000000>",
        ))
        .await;
    assert!(
        response.status.is_client_error(),
        "UNLOCK with an unknown token must fail\n{}",
        response.describe()
    );
}

#[tokio::test]
async fn names_with_special_characters_roundtrip() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let names = [
        "space name.txt",
        "ünïcødé 文件.txt",
        "hash#tag.txt",
        "percent%41.txt",
        "plus+and&amp.txt",
        "semi;colon=equals.txt",
        "quote'apostrophe.txt",
        "brackets[1](2){3}.txt",
        "question?.txt",
    ];
    for name in names {
        dav.put(&ctx.path(name), name.to_owned())
            .await
            .expect(&[201]);
    }
    let listing = dav
        .propfind(&ctx.dir, "1", PROPFIND_STANDARD)
        .await
        .multistatus();
    for name in names {
        assert!(
            listing.get(&dav.href_path(&ctx.path(name))).is_some(),
            "{name} missing from listing {:?}",
            listing.paths()
        );
        assert_eq!(dav.read(&ctx.path(name)).await, name.as_bytes(), "{name}");
    }
}

#[tokio::test]
async fn encoded_dot_segments_are_rejected() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("nested")).await;
    dav.write(&ctx.path("source.txt"), "source").await;

    // A URL parser would normalize `%2e%2e` away on the client, so send the target verbatim.
    let target = format!(
        "/remote.php/dav/files/{}/{}/nested/%2e%2e/escape.txt",
        encode_path(&ctx.cfg.full.user),
        encode_path(&ctx.dir)
    );
    match raw::status(
        ctx.base_url(),
        "PUT",
        &target,
        &ctx.cfg.full,
        &[],
        b"escape",
    )
    .await
    {
        Ok(status) => assert!(
            (400..500).contains(&status),
            "PUT {target} with an encoded `..` segment must be rejected, got {status}"
        ),
        Err(reason) => skip(&format!("raw PUT check skipped: {reason}")),
    }
    dav.get(&ctx.path("escape.txt")).await.expect(&[404]);

    let destination = format!("{}/nested/%2e%2e/escape.txt", dav.url(&ctx.dir));
    let copy = dav
        .transfer("COPY", &ctx.path("source.txt"), &destination, None)
        .await;
    assert!(
        copy.status.is_client_error(),
        "COPY to a Destination with an encoded `..` segment must be rejected\n{}",
        copy.describe()
    );
    dav.get(&ctx.path("escape.txt")).await.expect(&[404]);

    let nul_destination = format!("{}/bad%00name.txt", dav.url(&ctx.dir));
    let nul = dav
        .transfer("COPY", &ctx.path("source.txt"), &nul_destination, None)
        .await;
    assert!(
        nul.status.is_client_error(),
        "COPY to a Destination with NUL must be rejected\n{}",
        nul.describe()
    );
}

/// Sets a dead property on `rel` and returns its file id.
async fn tag(dav: &gono_acceptance::Dav, rel: &str) -> String {
    dav.proppatch(rel, &proppatch_set_dead(&[("marker", "keep-me")]))
        .await
        .multistatus();
    dav.fileid(rel).await
}

/// Asserts that `rel` still has the dead property set by [`tag`] and the same file id.
async fn assert_tag_intact(dav: &gono_acceptance::Dav, rel: &str, fileid: &str) {
    let response = dav.propfind(rel, "0", &propfind_dead(&["marker"])).await;
    let multistatus = response.multistatus();
    let entry = multistatus
        .get(&dav.href_path(rel))
        .unwrap_or_else(|| panic!("no entry for {rel}\n{}", response.describe()));
    assert_eq!(
        entry.text(DEAD_NS, "marker").as_deref(),
        Some("keep-me"),
        "dead property of {rel} was lost\n{}",
        response.describe()
    );
    assert_eq!(
        entry.text(OC, "fileid").as_deref(),
        Some(fileid),
        "file id of {rel} changed\n{}",
        response.describe()
    );
}

/// Regression (legacy): deleting `photos_1` also deleted the metadata of `photosX1/x.txt`
/// because the prefix query used an unescaped `LIKE 'photos_1/%'`.
#[tokio::test]
async fn regression_delete_keeps_metadata_of_wildcard_sibling() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("photos_1")).await;
    dav.write(&ctx.path("photos_1/inner.txt"), "inner").await;
    dav.create_dir(&ctx.path("photosX1")).await;
    dav.write(&ctx.path("photosX1/x.txt"), "sibling").await;
    let fileid = tag(&dav, &ctx.path("photosX1/x.txt")).await;

    dav.delete(&ctx.path("photos_1")).await.expect(&[204]);
    assert_tag_intact(&dav, &ctx.path("photosX1/x.txt"), &fileid).await;
}

/// Regression (legacy): moving `photos_1` rewrote the metadata paths of `photosX1/x.txt`
/// through the same unescaped `LIKE` prefix query.
#[tokio::test]
async fn regression_move_keeps_metadata_of_wildcard_sibling() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("photos_1")).await;
    dav.write(&ctx.path("photos_1/inner.txt"), "inner").await;
    dav.create_dir(&ctx.path("photosX1")).await;
    dav.write(&ctx.path("photosX1/x.txt"), "sibling").await;
    let fileid = tag(&dav, &ctx.path("photosX1/x.txt")).await;

    dav.mv(&ctx.path("photos_1"), &ctx.path("renamed"), None)
        .await
        .expect(&[201]);
    assert_tag_intact(&dav, &ctx.path("photosX1/x.txt"), &fileid).await;
}

/// Regression (legacy): SQLite `LIKE` is case-insensitive, so deleting `Docs` also deleted the
/// metadata of `docs/x.txt`. Only meaningful when the storage is case-sensitive.
#[tokio::test]
async fn regression_delete_keeps_metadata_of_case_variant_sibling() {
    let Some(ctx) = Ctx::new().await else { return };
    if !ctx.storage_is_case_sensitive().await {
        skip("server storage is case-insensitive; `Docs` and `docs` are the same directory");
        return;
    }
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("Docs")).await;
    dav.write(&ctx.path("Docs/inner.txt"), "inner").await;
    dav.create_dir(&ctx.path("docs")).await;
    dav.write(&ctx.path("docs/x.txt"), "sibling").await;
    let fileid = tag(&dav, &ctx.path("docs/x.txt")).await;

    dav.delete(&ctx.path("Docs")).await.expect(&[204]);
    assert_tag_intact(&dav, &ctx.path("docs/x.txt"), &fileid).await;
}
