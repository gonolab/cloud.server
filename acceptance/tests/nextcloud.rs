//! Nextcloud protocol surface: status.php, capabilities, OCS user endpoints, live properties and
//! `OC-*` headers, ETags (including directory ETag propagation), favorites with the
//! `filter-files` REPORT, and chunked upload v2.

use gono_acceptance::{
    Ctx, DAV, Dav, OC, Resp,
    dav::{FILTER_FILES_FAVORITES, normalize_etag, proppatch_favorite},
    random_id,
};

// ---------------------------------------------------------------------------------------------
// status.php, capabilities, OCS
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn status_php_is_public_and_reports_installed() {
    let Some(ctx) = Ctx::bare() else { return };
    let response =
        gono_acceptance::dav::send(&ctx.http, ctx.http.get(ctx.url("/status.php"))).await;
    response.expect(&[200]);
    let status = response.json();
    assert_eq!(status["installed"], true, "{status}");
    assert_eq!(status["maintenance"], false, "{status}");
    assert_eq!(status["needsDbUpgrade"], false, "{status}");
    for field in ["version", "versionstring", "productname"] {
        assert!(
            status[field]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "status.php field {field} must be a non-empty string: {status}"
        );
    }
}

#[tokio::test]
async fn connectivity_probe_returns_204() {
    let Some(ctx) = Ctx::bare() else { return };
    for path in ["/index.php/204", "/204"] {
        let response = gono_acceptance::dav::send(&ctx.http, ctx.http.get(ctx.url(path))).await;
        response.expect(&[204]);
        assert!(response.body.is_empty(), "{}", response.describe());
    }
}

#[tokio::test]
async fn capabilities_are_public_on_all_aliases() {
    let Some(ctx) = Ctx::bare() else { return };
    for path in [
        "/ocs/v1.php/cloud/capabilities",
        "/ocs/v2.php/cloud/capabilities",
        "/index.php/ocs/v1.php/cloud/capabilities",
        "/index.php/ocs/v2.php/cloud/capabilities",
    ] {
        let response = ctx.ocs("GET", path, None).await;
        response.expect(&[200]);
        let body = response.json();
        assert_eq!(body["ocs"]["meta"]["status"], "ok", "{path}: {body}");
        let data = &body["ocs"]["data"];
        assert!(
            data["version"]["string"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "{path}: capabilities must report version.string: {body}"
        );
        assert_eq!(
            data["capabilities"]["dav"]["chunking"], "1.0",
            "{path}: chunking v2 must be advertised: {body}"
        );
    }
}

const OCS_USER_PATHS: [&str; 4] = [
    "/ocs/v1.php/cloud/user",
    "/ocs/v2.php/cloud/user",
    "/index.php/ocs/v1.php/cloud/user",
    "/index.php/ocs/v2.php/cloud/user",
];

#[tokio::test]
async fn ocs_user_requires_authentication() {
    let Some(ctx) = Ctx::bare() else { return };
    for path in OCS_USER_PATHS {
        ctx.ocs("GET", path, None).await.expect(&[401]);
    }
}

#[tokio::test]
async fn ocs_user_returns_the_current_user_on_all_aliases() {
    let Some(ctx) = Ctx::bare() else { return };
    let user = &ctx.cfg.full.user;
    for path in OCS_USER_PATHS
        .into_iter()
        .map(str::to_owned)
        .chain([format!("/ocs/v2.php/cloud/users/{user}")])
    {
        let response = ctx.ocs("GET", &path, Some(&ctx.cfg.full)).await;
        response.expect(&[200]);
        let body = response.json();
        assert_eq!(body["ocs"]["meta"]["status"], "ok", "{path}: {body}");
        let data = &body["ocs"]["data"];
        assert_eq!(data["id"], user.as_str(), "{path}: {body}");
        assert!(
            data["displayname"].is_string() || data["display-name"].is_string(),
            "{path}: profile must include a display name: {body}"
        );
        assert!(
            data["quota"].is_object(),
            "{path}: profile must include quota: {body}"
        );
    }
}

#[tokio::test]
async fn ocs_user_lookup_of_another_user_is_refused() {
    let Some(ctx) = Ctx::bare() else { return };
    let user2 = gono_acceptance::require!(ctx.user2(), "GONO_ACCEPT_USER2/PASSWORD2 not set");
    let path = format!("/ocs/v2.php/cloud/users/{}", ctx.cfg.full.user);
    let response = ctx.ocs("GET", &path, Some(&user2)).await;
    response.expect(&[403, 404]);
}

// ---------------------------------------------------------------------------------------------
// Live properties and OC-* headers
// ---------------------------------------------------------------------------------------------

fn assert_permissions(permissions: &str, required: &str, context: &str) {
    for letter in required.chars() {
        assert!(
            permissions.contains(letter),
            "{context}: permissions {permissions:?} lack {letter:?}"
        );
    }
}

#[tokio::test]
async fn propfind_reports_nextcloud_live_props() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("dir")).await;
    dav.write(&ctx.path("dir/file.txt"), "12345").await;

    let file = dav.stat(&ctx.path("dir/file.txt")).await;
    for (ns, name) in [
        (OC, "fileid"),
        (OC, "id"),
        (OC, "permissions"),
        (OC, "favorite"),
        (DAV, "getetag"),
        (DAV, "getlastmodified"),
    ] {
        assert!(
            file.text(ns, name).is_some_and(|value| !value.is_empty()),
            "file lacks {{{ns}}}{name}: {file:?}"
        );
    }
    assert_eq!(file.text(OC, "favorite").as_deref(), Some("0"));
    assert_permissions(&file.text(OC, "permissions").unwrap(), "DNVW", "file");

    let dir = dav.stat(&ctx.path("dir")).await;
    for (ns, name) in [
        (OC, "fileid"),
        (OC, "id"),
        (OC, "permissions"),
        (OC, "favorite"),
        (DAV, "getetag"),
    ] {
        assert!(
            dir.text(ns, name).is_some_and(|value| !value.is_empty()),
            "dir lacks {{{ns}}}{name}: {dir:?}"
        );
    }
    assert_permissions(&dir.text(OC, "permissions").unwrap(), "DNVCK", "dir");
    assert_ne!(file.text(OC, "fileid"), dir.text(OC, "fileid"));
}

#[tokio::test]
async fn oc_size_reports_file_and_recursive_folder_sizes() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir_all(&ctx.path("dir/sub")).await;
    dav.write(&ctx.path("dir/a.txt"), "12345").await;
    dav.write(&ctx.path("dir/sub/b.txt"), "1234567").await;

    let file = dav.stat(&ctx.path("dir/a.txt")).await;
    assert_eq!(file.text(OC, "size").as_deref(), Some("5"), "{file:?}");
    let dir = dav.stat(&ctx.path("dir")).await;
    assert_eq!(
        dir.text(OC, "size").as_deref(),
        Some("12"),
        "a folder's oc:size is the total size of its contents: {dir:?}"
    );
}

/// Nextcloud clients treat `oc:fileid` as a number (the Android app parses it as a long, and
/// notify_push `notify_file_id` messages carry numeric ids). `oc:id` starts with the same number.
#[tokio::test]
async fn fileid_is_numeric_and_matches_oc_id() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("numeric.txt"), "x").await;
    let entry = dav.stat(&ctx.path("numeric.txt")).await;
    let fileid = entry.text(OC, "fileid").unwrap_or_default();
    let oc_id = entry.text(OC, "id").unwrap_or_default();
    assert!(
        !fileid.is_empty() && fileid.chars().all(|c| c.is_ascii_digit()),
        "oc:fileid must be numeric, got {fileid:?} (oc:id {oc_id:?})"
    );
    let leading: String = oc_id.chars().take_while(char::is_ascii_digit).collect();
    assert_eq!(
        leading.parse::<u64>().ok(),
        fileid.parse::<u64>().ok(),
        "oc:id {oc_id:?} must start with the numeric file id {fileid:?}"
    );
}

fn fileid_header_matches(header: &str, entry: &gono_acceptance::xml::DavResponse) -> bool {
    Some(header) == entry.text(OC, "fileid").as_deref()
        || Some(header) == entry.text(OC, "id").as_deref()
}

#[tokio::test]
async fn put_and_head_return_oc_headers() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("headers.txt");
    let put = dav.put(&rel, "headers").await;
    put.expect(&[201]);

    let oc_etag = put
        .header("oc-etag")
        .unwrap_or_else(|| panic!("PUT without OC-ETag\n{}", put.describe()));
    let etag = put
        .header("etag")
        .unwrap_or_else(|| panic!("PUT without ETag\n{}", put.describe()));
    assert_eq!(
        normalize_etag(&etag),
        normalize_etag(&oc_etag),
        "{}",
        put.describe()
    );
    let fileid = put
        .header("oc-fileid")
        .unwrap_or_else(|| panic!("PUT without OC-FileId\n{}", put.describe()));
    let put_permissions = put
        .header("x-nc-permissions")
        .unwrap_or_else(|| panic!("PUT without X-NC-Permissions\n{}", put.describe()));

    let entry = dav.stat(&rel).await;
    assert!(
        fileid_header_matches(&fileid, &entry),
        "OC-FileId {fileid:?} must equal oc:fileid or oc:id: {entry:?}"
    );
    assert_eq!(Some(put_permissions), entry.text(OC, "permissions"));

    let head = dav.head(&rel).await;
    head.expect(&[200]);
    for name in ["oc-etag", "oc-fileid", "x-nc-permissions", "etag"] {
        assert!(
            head.header(name).is_some(),
            "HEAD lacks {name}\n{}",
            head.describe()
        );
    }
    assert_eq!(head.header("oc-fileid"), Some(fileid));
    assert_eq!(
        head.header("x-nc-permissions"),
        entry.text(OC, "permissions")
    );

    let head_dir = dav.head(&ctx.dir).await;
    head_dir.expect(&[200]);
    let dir_entry = dav.stat(&ctx.dir).await;
    assert!(
        head_dir
            .header("oc-fileid")
            .is_some_and(|value| fileid_header_matches(&value, &dir_entry)),
        "HEAD on a collection must carry its OC-FileId\n{}",
        head_dir.describe()
    );
    assert_eq!(
        head_dir.header("x-nc-permissions"),
        dir_entry.text(OC, "permissions"),
        "{}",
        head_dir.describe()
    );
}

#[tokio::test]
async fn put_with_x_oc_mtime_sets_last_modified() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("mtime.txt");
    let put = dav
        .send(
            dav.request("PUT", &dav.url(&rel))
                .header("X-OC-MTime", "1700000000")
                .body("mtime"),
        )
        .await;
    put.expect(&[201]);
    assert_eq!(
        put.header("x-oc-mtime").as_deref(),
        Some("accepted"),
        "{}",
        put.describe()
    );
    let entry = dav.stat(&rel).await;
    assert_eq!(
        entry.text(DAV, "getlastmodified").as_deref(),
        Some("Tue, 14 Nov 2023 22:13:20 GMT")
    );
}

#[tokio::test]
async fn fileid_is_kept_on_move_and_overwrite_and_new_on_copy() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("a.txt"), "a").await;
    let original = dav.fileid(&ctx.path("a.txt")).await;

    dav.write(&ctx.path("a.txt"), "overwritten").await;
    assert_eq!(dav.fileid(&ctx.path("a.txt")).await, original, "overwrite");

    dav.mv(&ctx.path("a.txt"), &ctx.path("b.txt"), None)
        .await
        .expect(&[201]);
    assert_eq!(dav.fileid(&ctx.path("b.txt")).await, original, "move");

    dav.copy(&ctx.path("b.txt"), &ctx.path("c.txt"), None)
        .await
        .expect(&[201]);
    let copied = dav.fileid(&ctx.path("c.txt")).await;
    assert_ne!(copied, original, "copy must allocate a new file id");
}

// ---------------------------------------------------------------------------------------------
// ETags
// ---------------------------------------------------------------------------------------------

/// Regression (legacy): PUT/HEAD reported one ETag and GET/PROPFIND another for the same file.
#[tokio::test]
async fn regression_etag_is_identical_across_methods() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("etag.txt");
    dav.write(&rel, "first").await;
    dav.proppatch(&rel, &proppatch_favorite(1))
        .await
        .expect(&[207]);
    let put = dav.write(&rel, "second version").await;

    let mut seen: Vec<(&str, String)> = Vec::new();
    seen.push(("PUT ETag", put.header("etag").unwrap_or_default()));
    seen.push(("PUT OC-ETag", put.header("oc-etag").unwrap_or_default()));
    let head = dav.head(&rel).await;
    seen.push(("HEAD ETag", head.header("etag").unwrap_or_default()));
    let get = dav.get(&rel).await;
    seen.push(("GET ETag", get.header("etag").unwrap_or_default()));
    let entry = dav.stat(&rel).await;
    seen.push((
        "PROPFIND getetag",
        entry.text(DAV, "getetag").unwrap_or_default(),
    ));
    let report = dav
        .report(&ctx.dir, FILTER_FILES_FAVORITES)
        .await
        .multistatus();
    let reported = report
        .get(&dav.href_path(&rel))
        .and_then(|entry| entry.text(DAV, "getetag"))
        .unwrap_or_default();
    seen.push(("REPORT filter-files getetag", reported));

    let normalized: Vec<(&str, String)> = seen
        .iter()
        .map(|(source, etag)| (*source, normalize_etag(etag)))
        .collect();
    let reference = normalized[0].1.clone();
    assert!(!reference.is_empty(), "PUT must return an ETag: {seen:?}");
    assert!(
        normalized.iter().all(|(_, etag)| *etag == reference),
        "every method must report the same ETag for one file version: {seen:#?}"
    );
}

/// Regression (legacy): using the ETag returned by PUT in `If-Match` failed with 412.
#[tokio::test]
async fn regression_if_match_with_put_etag_succeeds() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("conditional.txt");
    let put = dav.write(&rel, "v1").await;
    let etag = put
        .header("etag")
        .unwrap_or_else(|| panic!("PUT without ETag\n{}", put.describe()));

    let conditional = dav
        .send(
            dav.request("PUT", &dav.url(&rel))
                .header("If-Match", &etag)
                .body("v2"),
        )
        .await;
    conditional.expect(&[204]);
    assert_eq!(dav.read(&rel).await, b"v2");
}

#[tokio::test]
async fn if_match_with_propfind_etag_succeeds() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("conditional.txt");
    dav.write(&rel, "v1").await;
    let etag = dav.etag(&rel).await;

    dav.send(
        dav.request("PUT", &dav.url(&rel))
            .header("If-Match", format!("\"{etag}\""))
            .body("v2"),
    )
    .await
    .expect(&[204]);
}

#[tokio::test]
async fn if_match_with_stale_etag_is_412() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("stale.txt");
    dav.write(&rel, "v1").await;
    let stale = dav.etag(&rel).await;
    dav.write(&rel, "v2 is longer").await;

    dav.send(
        dav.request("PUT", &dav.url(&rel))
            .header("If-Match", format!("\"{stale}\""))
            .body("v3"),
    )
    .await
    .expect(&[412]);
    assert_eq!(dav.read(&rel).await, b"v2 is longer");
}

#[tokio::test]
async fn if_none_match_star_prevents_overwrite() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("exists.txt");
    dav.write(&rel, "original").await;
    dav.send(
        dav.request("PUT", &dav.url(&rel))
            .header("If-None-Match", "*")
            .body("clobber"),
    )
    .await
    .expect(&[412]);
    assert_eq!(dav.read(&rel).await, b"original");
}

#[tokio::test]
async fn file_etag_changes_when_content_changes() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("changing.txt");
    dav.write(&rel, "aaaa").await;
    let before = dav.etag(&rel).await;
    // Same size on purpose: the ETag must not depend on size and coarse mtime only.
    dav.write(&rel, "bbbb").await;
    let after = dav.etag(&rel).await;
    assert_ne!(before, after);
}

/// ETags of `<dir>`, `<dir>/d1`, `<dir>/d1/d2` and the user root.
async fn ancestor_etags(ctx: &Ctx, dav: &Dav, dirs: &[&str]) -> Vec<(String, String)> {
    let mut etags = vec![(String::from("<root>"), dav.etag("").await)];
    etags.push((ctx.dir.clone(), dav.etag(&ctx.dir).await));
    for dir in dirs {
        etags.push((ctx.path(dir), dav.etag(&ctx.path(dir)).await));
    }
    etags
}

fn assert_all_changed(before: &[(String, String)], after: &[(String, String)], operation: &str) {
    let unchanged: Vec<&String> = before
        .iter()
        .zip(after)
        .filter(|((_, old), (_, new))| old == new)
        .map(|((path, _), _)| path)
        .collect();
    assert!(
        unchanged.is_empty(),
        "{operation}: ETag of these ancestor collections did not change: {unchanged:?}\nbefore: {before:?}\nafter: {after:?}"
    );
}

async fn nested_tree(ctx: &Ctx, dav: &Dav) {
    dav.create_dir_all(&ctx.path("d1/d2")).await;
    dav.write(&ctx.path("d1/d2/f.txt"), "original").await;
}

/// Regression (legacy): modifying `d1/d2/f.txt` left the ETags of `d2`, `d1`, and the root
/// unchanged.
#[tokio::test]
async fn regression_dir_etag_propagates_on_modify() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    nested_tree(&ctx, &dav).await;
    let before = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    dav.write(&ctx.path("d1/d2/f.txt"), "modified").await;
    let after = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    assert_all_changed(&before, &after, "modify d1/d2/f.txt");
}

#[tokio::test]
async fn dir_etag_propagates_on_create() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    nested_tree(&ctx, &dav).await;
    let before = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    dav.write(&ctx.path("d1/d2/new.txt"), "new").await;
    let after = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    assert_all_changed(&before, &after, "create d1/d2/new.txt");
}

#[tokio::test]
async fn dir_etag_propagates_on_mkcol() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    nested_tree(&ctx, &dav).await;
    let before = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    dav.create_dir(&ctx.path("d1/d2/sub")).await;
    let after = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    assert_all_changed(&before, &after, "MKCOL d1/d2/sub");
}

#[tokio::test]
async fn dir_etag_propagates_on_delete() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    nested_tree(&ctx, &dav).await;
    let before = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    dav.delete(&ctx.path("d1/d2/f.txt")).await.expect(&[204]);
    let after = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    assert_all_changed(&before, &after, "DELETE d1/d2/f.txt");
}

#[tokio::test]
async fn dir_etag_propagates_on_move_between_directories() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir_all(&ctx.path("a/deep")).await;
    dav.create_dir_all(&ctx.path("b/deep")).await;
    dav.write(&ctx.path("a/deep/x.txt"), "x").await;
    let dirs = ["a", "a/deep", "b", "b/deep"];
    let before = ancestor_etags(&ctx, &dav, &dirs).await;
    dav.mv(&ctx.path("a/deep/x.txt"), &ctx.path("b/deep/y.txt"), None)
        .await
        .expect(&[201]);
    let after = ancestor_etags(&ctx, &dav, &dirs).await;
    assert_all_changed(&before, &after, "MOVE a/deep/x.txt -> b/deep/y.txt");
}

#[tokio::test]
async fn dir_etag_propagates_on_copy() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    nested_tree(&ctx, &dav).await;
    let before = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    dav.copy(&ctx.path("d1/d2/f.txt"), &ctx.path("d1/d2/g.txt"), None)
        .await
        .expect(&[201]);
    let after = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    assert_all_changed(&before, &after, "COPY d1/d2/f.txt -> d1/d2/g.txt");
}

#[tokio::test]
async fn dir_etag_propagates_on_chunked_upload() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    nested_tree(&ctx, &dav).await;
    let before = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    chunked_upload(&dav, &ctx.path("d1/d2/chunked.bin"), &[b"hello ", b"world"])
        .await
        .expect(&[201]);
    let after = ancestor_etags(&ctx, &dav, &["d1", "d1/d2"]).await;
    assert_all_changed(&before, &after, "chunked upload into d1/d2");
}

// ---------------------------------------------------------------------------------------------
// Favorites
// ---------------------------------------------------------------------------------------------

async fn favorite_of(dav: &Dav, rel: &str) -> Option<String> {
    dav.stat(rel).await.text(OC, "favorite")
}

#[tokio::test]
async fn favorite_proppatch_roundtrips_for_files_and_folders() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("file.txt"), "x").await;
    dav.create_dir(&ctx.path("folder")).await;

    for rel in [ctx.path("file.txt"), ctx.path("folder")] {
        assert_eq!(favorite_of(&dav, &rel).await.as_deref(), Some("0"), "{rel}");
        let set = dav.proppatch(&rel, &proppatch_favorite(1)).await;
        let multistatus = set.multistatus();
        assert_eq!(
            multistatus
                .get(&dav.href_path(&rel))
                .and_then(|entry| entry.prop_status(OC, "favorite")),
            Some(200),
            "{}",
            set.describe()
        );
        assert_eq!(favorite_of(&dav, &rel).await.as_deref(), Some("1"), "{rel}");
        dav.proppatch(&rel, &proppatch_favorite(0))
            .await
            .expect(&[207]);
        assert_eq!(favorite_of(&dav, &rel).await.as_deref(), Some("0"), "{rel}");
    }
}

#[tokio::test]
async fn copy_does_not_carry_the_favorite_flag() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("favorite.txt"), "x").await;
    dav.proppatch(&ctx.path("favorite.txt"), &proppatch_favorite(1))
        .await
        .expect(&[207]);
    dav.copy(&ctx.path("favorite.txt"), &ctx.path("copy.txt"), None)
        .await
        .expect(&[201]);
    assert_eq!(
        favorite_of(&dav, &ctx.path("copy.txt")).await.as_deref(),
        Some("0")
    );
    assert_eq!(
        favorite_of(&dav, &ctx.path("favorite.txt"))
            .await
            .as_deref(),
        Some("1")
    );
}

#[tokio::test]
async fn favorite_survives_move() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir(&ctx.path("dir")).await;
    dav.write(&ctx.path("dir/favorite.txt"), "x").await;
    dav.proppatch(&ctx.path("dir/favorite.txt"), &proppatch_favorite(1))
        .await
        .expect(&[207]);
    dav.mv(&ctx.path("dir"), &ctx.path("renamed"), None)
        .await
        .expect(&[201]);
    assert_eq!(
        favorite_of(&dav, &ctx.path("renamed/favorite.txt"))
            .await
            .as_deref(),
        Some("1")
    );
}

/// Paths under the test directory reported by a `filter-files` REPORT.
async fn favorites_under(dav: &Dav, report_rel: &str, dir_rel: &str) -> Vec<String> {
    let response = dav.report(report_rel, FILTER_FILES_FAVORITES).await;
    let multistatus = response.multistatus();
    let prefix = format!("{}/", dav.href_path(dir_rel));
    for entry in &multistatus.responses {
        if entry.path.starts_with(&prefix) {
            assert_eq!(
                entry.text(OC, "favorite").as_deref(),
                Some("1"),
                "filter-files entries must report oc:favorite 1\n{}",
                response.describe()
            );
        }
    }
    let mut paths: Vec<String> = multistatus
        .paths()
        .into_iter()
        .filter_map(|path| path.strip_prefix(&prefix).map(str::to_owned))
        .collect();
    paths.sort();
    paths
}

#[tokio::test]
async fn filter_files_report_lists_favorites_recursively() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.create_dir_all(&ctx.path("projects/nested")).await;
    dav.create_dir(&ctx.path("projects/starred-dir")).await;
    for (rel, body) in [
        ("outside-favorite.txt", "outside"),
        ("projects/plain.txt", "plain"),
        ("projects/favorite.txt", "favorite"),
        ("projects/nested/starred.md", "nested"),
    ] {
        dav.write(&ctx.path(rel), body).await;
    }
    for rel in [
        "outside-favorite.txt",
        "projects/favorite.txt",
        "projects/nested/starred.md",
        "projects/starred-dir",
    ] {
        dav.proppatch(&ctx.path(rel), &proppatch_favorite(1))
            .await
            .expect(&[207]);
    }

    let in_projects = favorites_under(&dav, &ctx.path("projects"), &ctx.dir).await;
    assert_eq!(
        in_projects,
        vec![
            "projects/favorite.txt".to_owned(),
            "projects/nested/starred.md".to_owned(),
            "projects/starred-dir".to_owned(),
        ]
    );

    let from_root = favorites_under(&dav, "", &ctx.dir).await;
    assert_eq!(
        from_root,
        vec![
            "outside-favorite.txt".to_owned(),
            "projects/favorite.txt".to_owned(),
            "projects/nested/starred.md".to_owned(),
            "projects/starred-dir".to_owned(),
        ]
    );
}

#[tokio::test]
async fn filter_files_report_follows_delete_and_move() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    for rel in ["deleted.txt", "moved.txt", "kept.txt"] {
        dav.write(&ctx.path(rel), rel.to_owned()).await;
        dav.proppatch(&ctx.path(rel), &proppatch_favorite(1))
            .await
            .expect(&[207]);
    }
    dav.delete(&ctx.path("deleted.txt")).await.expect(&[204]);
    dav.mv(&ctx.path("moved.txt"), &ctx.path("renamed.txt"), None)
        .await
        .expect(&[201]);

    let favorites = favorites_under(&dav, &ctx.dir, &ctx.dir).await;
    assert_eq!(
        favorites,
        vec!["kept.txt".to_owned(), "renamed.txt".to_owned()]
    );
}

// ---------------------------------------------------------------------------------------------
// Chunked upload v2
// ---------------------------------------------------------------------------------------------

async fn mkcol_upload(dav: &Dav, upload: &str, destination: &str, total: usize) -> Resp {
    dav.send(
        dav.request("MKCOL", &dav.upload_url(upload))
            .header("Destination", destination)
            .header("OC-Total-Length", total.to_string()),
    )
    .await
}

async fn put_chunk(
    dav: &Dav,
    upload: &str,
    name: &str,
    destination: &str,
    total: usize,
    body: &[u8],
) -> Resp {
    dav.send(
        dav.request("PUT", &dav.upload_url(&format!("{upload}/{name}")))
            .header("Destination", destination)
            .header("OC-Total-Length", total.to_string())
            .body(body.to_vec()),
    )
    .await
}

async fn move_upload(dav: &Dav, upload: &str, destination: &str, total: usize) -> Resp {
    dav.send(
        dav.request("MOVE", &dav.upload_url(&format!("{upload}/.file")))
            .header("Destination", destination)
            .header("OC-Total-Length", total.to_string()),
    )
    .await
}

/// Uploads `chunks` (named 1, 2, ...) to `rel` through chunking v2 and returns the final MOVE.
async fn chunked_upload(dav: &Dav, rel: &str, chunks: &[&[u8]]) -> Resp {
    let upload = format!("acc-{}", random_id());
    let destination = dav.url(rel);
    let total: usize = chunks.iter().map(|chunk| chunk.len()).sum();
    mkcol_upload(dav, &upload, &destination, total)
        .await
        .expect(&[201]);
    for (index, chunk) in chunks.iter().enumerate() {
        put_chunk(
            dav,
            &upload,
            &format!("{:05}", index + 1),
            &destination,
            total,
            chunk,
        )
        .await
        .expect(&[201, 204]);
    }
    move_upload(dav, &upload, &destination, total).await
}

#[tokio::test]
async fn chunked_upload_assembles_the_file() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let upload = format!("acc-{}", random_id());
    let rel = ctx.path("chunked.txt");
    let destination = dav.url(&rel);

    mkcol_upload(&dav, &upload, &destination, 11)
        .await
        .expect(&[201]);
    // Chunks arrive out of order on purpose.
    put_chunk(&dav, &upload, "00002", &destination, 11, b"world")
        .await
        .expect(&[201, 204]);
    put_chunk(&dav, &upload, "00001", &destination, 11, b"hello ")
        .await
        .expect(&[201, 204]);
    let moved = dav
        .send(
            dav.request("MOVE", &dav.upload_url(&format!("{upload}/.file")))
                .header("Destination", &destination)
                .header("OC-Total-Length", "11")
                .header("X-OC-MTime", "1700000000"),
        )
        .await;
    moved.expect(&[201]);
    assert!(moved.header("oc-fileid").is_some(), "{}", moved.describe());
    assert!(moved.header("oc-etag").is_some(), "{}", moved.describe());
    assert_eq!(
        moved.header("x-oc-mtime").as_deref(),
        Some("accepted"),
        "{}",
        moved.describe()
    );

    assert_eq!(dav.read(&rel).await, b"hello world");
    let entry = dav.stat(&rel).await;
    assert_eq!(
        entry.text(DAV, "getlastmodified").as_deref(),
        Some("Tue, 14 Nov 2023 22:13:20 GMT")
    );

    // The upload session is consumed by the MOVE.
    move_upload(&dav, &upload, &destination, 11)
        .await
        .expect(&[404]);
}

#[tokio::test]
async fn chunked_upload_reports_the_final_etag() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("chunked-etag.txt");
    let moved = chunked_upload(&dav, &rel, &[b"abc", b"def"]).await;
    moved.expect(&[201]);
    let oc_etag = moved
        .header("oc-etag")
        .unwrap_or_else(|| panic!("chunk MOVE without OC-ETag\n{}", moved.describe()));
    assert_eq!(
        normalize_etag(&oc_etag),
        dav.etag(&rel).await,
        "{}",
        moved.describe()
    );
    if let Some(etag) = moved.header("etag") {
        assert_eq!(normalize_etag(&etag), normalize_etag(&oc_etag));
    }
}

#[tokio::test]
async fn chunked_upload_overwrites_an_existing_file() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let rel = ctx.path("replace.txt");
    dav.write(&rel, "old content").await;
    let fileid = dav.fileid(&rel).await;

    chunked_upload(&dav, &rel, &[b"new ", b"content"])
        .await
        .expect(&[204]);
    assert_eq!(dav.read(&rel).await, b"new content");
    assert_eq!(
        dav.fileid(&rel).await,
        fileid,
        "overwrite must keep the file id"
    );
}

#[tokio::test]
async fn chunked_upload_rejects_invalid_chunk_names() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let upload = format!("acc-{}", random_id());
    let destination = dav.url(&ctx.path("invalid.txt"));
    mkcol_upload(&dav, &upload, &destination, 3)
        .await
        .expect(&[201]);
    put_chunk(&dav, &upload, "not-a-number", &destination, 3, b"bad")
        .await
        .expect(&[400]);
    dav.delete_upload(&upload).await;
}

#[tokio::test]
async fn chunked_upload_rejects_a_mismatched_destination() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let upload = format!("acc-{}", random_id());
    let destination = dav.url(&ctx.path("original.txt"));
    let other = dav.url(&ctx.path("other.txt"));
    mkcol_upload(&dav, &upload, &destination, 3)
        .await
        .expect(&[201]);
    let response = put_chunk(&dav, &upload, "00001", &other, 3, b"bad").await;
    assert!(
        response.status.is_client_error(),
        "a chunk for a different Destination must be rejected\n{}",
        response.describe()
    );
    dav.delete_upload(&upload).await;
    dav.get(&ctx.path("other.txt")).await.expect(&[404]);
}

#[tokio::test]
async fn chunked_upload_rejects_an_impossible_total_length() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let upload = format!("acc-{}", random_id());
    let destination = dav.url(&ctx.path("huge.bin"));
    let response = dav
        .send(
            dav.request("MKCOL", &dav.upload_url(&upload))
                .header("Destination", &destination)
                .header("OC-Total-Length", i64::MAX.to_string()),
        )
        .await;
    response.expect(&[507]);
}

/// Regression (legacy): the merged file was not checked against `OC-Total-Length`.
#[tokio::test]
async fn regression_chunked_upload_verifies_total_length() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let upload = format!("acc-{}", random_id());
    let rel = ctx.path("short.txt");
    let destination = dav.url(&rel);
    mkcol_upload(&dav, &upload, &destination, 11)
        .await
        .expect(&[201]);
    put_chunk(&dav, &upload, "00001", &destination, 11, b"hello")
        .await
        .expect(&[201, 204]);
    put_chunk(&dav, &upload, "00002", &destination, 11, b"worl")
        .await
        .expect(&[201, 204]);
    let moved = move_upload(&dav, &upload, &destination, 11).await;
    dav.delete_upload(&upload).await;
    assert!(
        moved.status.is_client_error(),
        "assembling 9 bytes for OC-Total-Length 11 must fail\n{}",
        moved.describe()
    );
    dav.get(&rel).await.expect(&[404]);
}

#[tokio::test]
async fn chunked_upload_can_be_cancelled() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let upload = format!("acc-{}", random_id());
    let rel = ctx.path("cancelled.txt");
    let destination = dav.url(&rel);
    mkcol_upload(&dav, &upload, &destination, 5)
        .await
        .expect(&[201]);
    put_chunk(&dav, &upload, "00001", &destination, 5, b"hello")
        .await
        .expect(&[201, 204]);
    dav.send(dav.request("DELETE", &dav.upload_url(&upload)))
        .await
        .expect(&[204]);
    move_upload(&dav, &upload, &destination, 5)
        .await
        .expect(&[404]);
    dav.get(&rel).await.expect(&[404]);
}
