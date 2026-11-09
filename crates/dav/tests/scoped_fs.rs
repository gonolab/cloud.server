//! ScopedFs behind dav-server: ETags, live properties, permissions, mounts, path safety and
//! single-transaction subtree operations.

mod common;

use common::{Harness, dav, mount, nc, oc};

#[tokio::test]
async fn one_quoted_etag_on_every_interface() {
    let h = Harness::new().await;
    let full = h.full();
    let put = h.put(&full, "etag.txt", "first").await;
    put.expect(201);
    let put_etag = put.header("etag").unwrap();
    assert!(
        put_etag.starts_with('"') && put_etag.ends_with('"'),
        "{put_etag}"
    );

    let get = h.send(&full, "GET", "etag.txt", &[], "").await;
    get.expect(200);
    assert_eq!(get.header("etag").unwrap(), put_etag);
    let head = h.send(&full, "HEAD", "etag.txt", &[], "").await;
    assert_eq!(head.header("etag").unwrap(), put_etag);
    assert_eq!(
        h.prop(&full, "etag.txt", &dav("getetag")).await.unwrap(),
        put_etag,
        "PROPFIND getetag is the same quoted value"
    );
    assert_eq!(
        put.outcome.as_ref().unwrap().etag,
        put_etag.trim_matches('"')
    );

    let conditional = h
        .send(
            &full,
            "PUT",
            "etag.txt",
            &[("If-Match", put_etag.as_str())],
            "second",
        )
        .await;
    conditional.expect(204);
    let stale = h
        .send(
            &full,
            "PUT",
            "etag.txt",
            &[("If-Match", put_etag.as_str())],
            "third",
        )
        .await;
    stale.expect(412);
    let none_match = h
        .send(&full, "PUT", "etag.txt", &[("If-None-Match", "*")], "x")
        .await;
    none_match.expect(412);
}

#[tokio::test]
async fn nextcloud_live_props_are_reported() {
    let h = Harness::new().await;
    let full = h.full();
    h.mkcol(&full, "dir").await.expect(201);
    h.mkcol(&full, "dir/sub").await.expect(201);
    h.put(&full, "dir/a.txt", "12345").await.expect(201);
    h.put(&full, "dir/sub/b.txt", "1234567").await.expect(201);

    let file = h.props(&full, "dir/a.txt").await;
    let fileid = &file[&oc("fileid")].1;
    assert!(fileid.parse::<u64>().is_ok(), "{fileid}");
    assert_eq!(
        file[&oc("id")].1,
        format!("{:08}{}", fileid.parse::<u64>().unwrap(), h.instance_id)
    );
    assert_eq!(file[&oc("permissions")].1, "GDNVW");
    assert_eq!(file[&oc("favorite")].1, "0");
    assert_eq!(file[&oc("size")].1, "5");
    assert_eq!(file[&nc("has-preview")].1, "false");
    assert_eq!(file[&dav("getcontentlength")].1, "5");

    let dir = h.props(&full, "dir").await;
    assert_eq!(dir[&oc("permissions")].1, "GDNVCK");
    assert_eq!(dir[&oc("size")].1, "12", "recursive folder size");
    assert_ne!(dir[&oc("fileid")].1, *fileid);

    let root = h.props(&full, "").await;
    assert_eq!(
        root[&oc("permissions")].1,
        "GMCK",
        "the mount root cannot be deleted"
    );
}

#[tokio::test]
async fn favorites_are_set_with_proppatch_without_changing_the_etag() {
    let h = Harness::new().await;
    let full = h.full();
    h.put(&full, "fav.txt", "x").await.expect(201);
    let etag = h.prop(&full, "fav.txt", &dav("getetag")).await;
    let patch = |value: &str| {
        format!(
            r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>{value}</oc:favorite></d:prop></d:set></d:propertyupdate>"#
        )
    };
    let set = h.send(&full, "PROPPATCH", "fav.txt", &[], patch("1")).await;
    let statuses = set.multistatus();
    assert_eq!(statuses.values().next().unwrap()[&oc("favorite")].0, 200);
    assert_eq!(
        h.prop(&full, "fav.txt", &oc("favorite")).await.unwrap(),
        "1"
    );
    assert_eq!(h.prop(&full, "fav.txt", &dav("getetag")).await, etag);

    let read_only = r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:fileid>1</oc:fileid></d:prop></d:set></d:propertyupdate>"#.to_owned();
    let refused = h.send(&full, "PROPPATCH", "fav.txt", &[], read_only).await;
    assert_eq!(
        refused.multistatus().values().next().unwrap()[&oc("fileid")].0,
        403
    );
}

#[tokio::test]
async fn dead_props_are_listed_only_when_asked_for() {
    let h = Harness::new().await;
    let full = h.full();
    h.put(&full, "props.txt", "x").await.expect(201);
    let set = r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:x="urn:test"><d:set><d:prop><x:color>blue</x:color><x:size>large</x:size></d:prop></d:set></d:propertyupdate>"#;
    h.send(&full, "PROPPATCH", "props.txt", &[], set)
        .await
        .expect(207);

    let one = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:x="urn:test"><d:prop><x:color/></d:prop></d:propfind>"#;
    let response = h
        .send(&full, "PROPFIND", "props.txt", &[("Depth", "0")], one)
        .await;
    let text = response.text();
    assert_eq!(
        text.matches("color").count(),
        2,
        "one element, no duplicate: {text}"
    );
    assert!(
        !text.contains("large"),
        "unrequested dead props are not listed: {text}"
    );

    let all = h
        .send(&full, "PROPFIND", "props.txt", &[("Depth", "0")], "")
        .await;
    let text = all.text();
    assert!(text.contains("blue") && text.contains("large"), "{text}");
}

#[tokio::test]
async fn missing_props_are_reported_as_404() {
    let h = Harness::new().await;
    let full = h.full();
    h.put(&full, "props.txt", "x").await.expect(201);
    let ask = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:x="urn:test" xmlns:oc="http://owncloud.org/ns"><d:prop><x:never-set/><oc:fileid/></d:prop></d:propfind>"#;
    let response = h
        .send(&full, "PROPFIND", "props.txt", &[("Depth", "0")], ask)
        .await;
    let entries = response.multistatus();
    let props = entries.values().next().unwrap();
    assert_eq!(props["{urn:test}never-set"].0, 404);
    assert_eq!(props[&oc("fileid")].0, 200);

    let all = h
        .send(&full, "PROPFIND", "props.txt", &[("Depth", "0")], "")
        .await;
    assert!(
        !all.text().contains("404"),
        "allprop lists only what exists"
    );
}

#[tokio::test]
async fn read_only_scopes_refuse_every_write() {
    let h = Harness::new().await;
    let full = h.full();
    h.put(&full, "file.txt", "original").await.expect(201);
    h.mkcol(&full, "sub").await.expect(201);
    let view = h.view();

    for (method, rel, headers, body) in [
        ("PUT", "new.txt", vec![], "x"),
        ("PUT", "file.txt", vec![], "x"),
        (
            "PATCH",
            "file.txt",
            vec![
                ("Content-Type", "application/x-sabredav-partialupdate"),
                ("X-Update-Range", "append"),
            ],
            " appended",
        ),
        ("MKCOL", "new-dir", vec![], ""),
        ("DELETE", "file.txt", vec![], ""),
        ("DELETE", "sub", vec![], ""),
        (
            "MOVE",
            "file.txt",
            vec![("Destination", "/remote.php/dav/files/alice/moved.txt")],
            "",
        ),
        (
            "COPY",
            "file.txt",
            vec![("Destination", "/remote.php/dav/files/alice/copied.txt")],
            "",
        ),
        (
            "PROPPATCH",
            "file.txt",
            vec![],
            r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:x="urn:x"><d:set><d:prop><x:a>1</x:a></d:prop></d:set></d:propertyupdate>"#,
        ),
    ] {
        let response = h.send(&view, method, rel, &headers, body).await;
        assert_eq!(
            response.status.as_u16(),
            403,
            "{method} {rel}: {}",
            response.text()
        );
    }
    assert_eq!(
        std::fs::read_to_string(h.disk("file.txt")).unwrap(),
        "original"
    );
    assert!(h.disk("sub").is_dir());
    for gone in ["new.txt", "new-dir", "moved.txt", "copied.txt"] {
        assert!(!h.disk(gone).exists(), "{gone}");
    }

    let listing = h.propfind(&view, "", "1").await.multistatus();
    for (href, props) in &listing {
        let permissions = &props[&oc("permissions")].1;
        assert!(
            !permissions.contains(['W', 'C', 'K', 'D', 'N', 'V']),
            "{href}: {permissions}"
        );
    }
}

#[tokio::test]
async fn scoped_mounts_map_paths_and_show_a_virtual_root() {
    let h = Harness::new().await;
    let full = h.full();
    for dir in ["acc-scope", "acc-scope/view", "acc-scope/full", "private"] {
        h.mkcol(&full, dir).await.expect(201);
    }
    h.put(&full, "acc-scope/view/readme.txt", "read me")
        .await
        .expect(201);
    h.put(&full, "private/secret.txt", "secret")
        .await
        .expect(201);
    let scoped = h.identity(vec![
        mount("/acc-full", "/acc-scope/full", true),
        mount("/acc-view", "/acc-scope/view", false),
        mount("/missing", "/does-not-exist", true),
    ]);

    let listing = h.propfind(&scoped, "", "1").await.multistatus();
    let mut hrefs: Vec<&String> = listing.keys().collect();
    hrefs.sort();
    assert_eq!(
        hrefs,
        [
            "/remote.php/dav/files/alice",
            "/remote.php/dav/files/alice/acc-full",
            "/remote.php/dav/files/alice/acc-view",
        ]
    );
    let root = &listing["/remote.php/dav/files/alice"];
    assert_eq!(root[&oc("permissions")].1, "G");
    assert!(
        root.get(&oc("fileid"))
            .is_none_or(|(status, _)| *status == 404),
        "virtual collections have no file id"
    );

    let read = h.send(&scoped, "GET", "acc-view/readme.txt", &[], "").await;
    read.expect(200);
    assert_eq!(read.body, "read me");
    h.put(&scoped, "acc-full/upload.txt", "uploaded")
        .await
        .expect(201);
    assert_eq!(
        std::fs::read_to_string(h.disk("acc-scope/full/upload.txt")).unwrap(),
        "uploaded"
    );

    h.put(&scoped, "virtual.txt", "x").await.expect(403);
    h.mkcol(&scoped, "virtual-dir").await.expect(403);
    h.put(&scoped, "acc-view/new.txt", "x").await.expect(403);
    h.send(&scoped, "GET", "private/secret.txt", &[], "")
        .await
        .expect(404);
    h.send(&scoped, "GET", "acc-scope/view/readme.txt", &[], "")
        .await
        .expect(404);
    h.send(&scoped, "DELETE", "acc-full", &[], "")
        .await
        .expect(403);

    let before = h.prop(&scoped, "", &dav("getetag")).await.unwrap();
    h.put(&scoped, "acc-full/another.txt", "x")
        .await
        .expect(201);
    let after = h.prop(&scoped, "", &dav("getetag")).await.unwrap();
    assert_ne!(before, after, "virtual ETags follow the mounts below them");
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_never_lead_out_of_the_tree() {
    use std::os::unix::fs::symlink;

    let h = Harness::new().await;
    let full = h.full();
    let outside = h.dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), "secret").unwrap();
    symlink(&outside, h.disk("escape")).unwrap();
    symlink(outside.join("secret.txt"), h.disk("link.txt")).unwrap();
    h.put(&full, "real.txt", "real").await.expect(201);

    let listing = h.propfind(&full, "", "1").await.multistatus();
    assert_eq!(listing.len(), 2, "{:?}", listing.keys());
    for rel in ["escape/secret.txt", "link.txt", "escape"] {
        h.send(&full, "GET", rel, &[], "").await.expect(404);
    }
    h.put(&full, "escape/planted.txt", "x").await.expect(409);
    assert!(!outside.join("planted.txt").exists());
    h.send(&full, "DELETE", "escape", &[], "").await.expect(404);
    assert!(outside.join("secret.txt").exists());
}

#[tokio::test]
async fn names_are_stored_in_nfc() {
    let h = Harness::new().await;
    let full = h.full();
    let nfd = "cafe%CC%81.txt";
    h.put(&full, nfd, "accent").await.expect(201);
    assert!(
        h.disk("caf\u{e9}.txt").exists(),
        "stored under the NFC name"
    );
    let get = h.send(&full, "GET", "caf%C3%A9.txt", &[], "").await;
    get.expect(200);
    assert_eq!(get.body, "accent");
    h.put(&full, nfd, "again").await.expect(204);

    // A decomposed name created behind the server's back is hidden.
    std::fs::write(h.disk("").join("na\u{0303}o.txt"), "nfd").unwrap();
    let listing = h.propfind(&full, "", "1").await.multistatus();
    assert!(
        listing.keys().all(|href| !href.contains('\u{0303}')),
        "{:?}",
        listing.keys()
    );
}

#[tokio::test]
async fn dot_segments_and_nul_never_reach_the_disk() {
    let h = Harness::new().await;
    let full = h.full();
    h.mkcol(&full, "nested").await.expect(201);
    let nul = h.put(&full, "bad%00name.txt", "x").await;
    assert!(nul.status.is_client_error(), "{}", nul.status);
    let other_user = h
        .send(
            &full,
            "COPY",
            "nested",
            &[("Destination", "/remote.php/dav/files/bob/stolen")],
            "",
        )
        .await;
    assert!(other_user.status.is_client_error(), "{}", other_user.status);
}

#[tokio::test]
async fn collection_operations_are_single_metadata_transactions() {
    let h = Harness::new().await;
    let full = h.full();
    for dir in ["tree", "tree/a", "tree/a/b"] {
        h.mkcol(&full, dir).await.expect(201);
    }
    h.put(&full, "tree/a/b/leaf.txt", "leaf").await.expect(201);
    h.put(&full, "tree/top.txt", "top").await.expect(201);
    let tag = r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:x="urn:test"><d:set><d:prop><x:tag>kept</x:tag></d:prop></d:set></d:propertyupdate>"#;
    h.send(&full, "PROPPATCH", "tree/a/b/leaf.txt", &[], tag)
        .await
        .expect(207);

    let before = h.change_count().await;
    let copy = h
        .send(
            &full,
            "COPY",
            "tree",
            &[("Destination", "/remote.php/dav/files/alice/copy")],
            "",
        )
        .await;
    copy.expect(201);
    assert_eq!(h.change_count().await, before + 1, "one COPY, one change");
    assert_eq!(
        std::fs::read_to_string(h.disk("copy/a/b/leaf.txt")).unwrap(),
        "leaf"
    );
    let tagged = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:x="urn:test"><d:prop><x:tag/></d:prop></d:propfind>"#;
    let copied = h
        .send(
            &full,
            "PROPFIND",
            "copy/a/b/leaf.txt",
            &[("Depth", "0")],
            tagged,
        )
        .await;
    assert!(copied.text().contains("kept"), "{}", copied.text());
    assert_eq!(h.prop(&full, "copy", &oc("size")).await.unwrap(), "7");

    let shallow = h
        .send(
            &full,
            "COPY",
            "tree",
            &[
                ("Destination", "/remote.php/dav/files/alice/shallow"),
                ("Depth", "0"),
            ],
            "",
        )
        .await;
    shallow.expect(201);
    assert!(h.disk("shallow").is_dir());
    assert!(!h.disk("shallow/top.txt").exists());

    let before = h.change_count().await;
    h.send(&full, "DELETE", "tree", &[], "").await.expect(204);
    assert_eq!(h.change_count().await, before + 1, "one DELETE, one change");
    assert!(!h.disk("tree").exists());
    h.propfind(&full, "tree/a/b/leaf.txt", "0")
        .await
        .expect(404);

    let before = h.change_count().await;
    h.send(
        &full,
        "MOVE",
        "copy",
        &[("Destination", "/remote.php/dav/files/alice/moved")],
        "",
    )
    .await
    .expect(201);
    assert_eq!(h.change_count().await, before + 1);
    let moved = h
        .send(
            &full,
            "PROPFIND",
            "moved/a/b/leaf.txt",
            &[("Depth", "0")],
            tagged,
        )
        .await;
    assert!(moved.text().contains("kept"));
}

#[tokio::test]
async fn directory_etags_propagate_and_ids_are_stable() {
    let h = Harness::new().await;
    let full = h.full();
    h.mkcol(&full, "d1").await.expect(201);
    h.mkcol(&full, "d1/d2").await.expect(201);
    h.put(&full, "d1/d2/f.txt", "original").await.expect(201);
    let id = h.prop(&full, "d1/d2/f.txt", &oc("fileid")).await;

    async fn etags(h: &Harness, full: &std::sync::Arc<gono_dav::Identity>) -> Vec<String> {
        let mut etags = Vec::new();
        for rel in ["", "d1", "d1/d2"] {
            etags.push(h.prop(full, rel, &dav("getetag")).await.unwrap());
        }
        etags
    }
    let before = etags(&h, &full).await;
    h.put(&full, "d1/d2/f.txt", "modified").await.expect(204);
    let after = etags(&h, &full).await;
    assert!(
        before.iter().zip(&after).all(|(a, b)| a != b),
        "{before:?} {after:?}"
    );
    assert_eq!(h.prop(&full, "d1/d2/f.txt", &oc("fileid")).await, id);

    h.send(
        &full,
        "MOVE",
        "d1/d2/f.txt",
        &[("Destination", "/remote.php/dav/files/alice/d1/g.txt")],
        "",
    )
    .await
    .expect(201);
    assert_eq!(h.prop(&full, "d1/g.txt", &oc("fileid")).await, id);
}

#[tokio::test]
async fn x_oc_mtime_sets_the_modification_time() {
    let h = Harness::new().await;
    let full = h.full();
    h.send(
        &full,
        "PUT",
        "mtime.txt",
        &[("X-OC-MTime", "1700000000")],
        "mtime",
    )
    .await
    .expect(201);
    assert_eq!(
        h.prop(&full, "mtime.txt", &dav("getlastmodified"))
            .await
            .unwrap(),
        "Tue, 14 Nov 2023 22:13:20 GMT"
    );
}

#[tokio::test]
async fn webdav_alias_reaches_the_same_files() {
    let h = Harness::new().await;
    let full = h.full();
    h.put(&full, "alias.txt", "same").await.expect(201);
    let request = http::Request::builder()
        .method("GET")
        .uri("/remote.php/webdav/alias.txt")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    let (parts, body) = request.into_parts();
    let ctx = gono_dav::Ctx::new(full.clone(), gono_dav::RequestInfo::from_parts(&parts));
    let response = h
        .handler
        .handle_guarded(http::Request::from_parts(parts, body), "alice".into(), ctx)
        .await;
    assert_eq!(response.status(), 200);
}
