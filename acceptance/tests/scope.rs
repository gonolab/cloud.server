//! Multiple users and app password scopes: read-only (`view`) scopes reject every write method,
//! scoped app passwords only see their mounts, and users cannot reach each other's files.

use gono_acceptance::{
    Cred, Ctx, Dav, OC, SCOPED_FULL_MOUNT, SCOPED_FULL_STORAGE, SCOPED_VIEW_MOUNT,
    SCOPED_VIEW_STORAGE,
    dav::{LOCKINFO_EXCLUSIVE, PROPFIND_STANDARD, encode_path, proppatch_set_dead},
    random_id, raw, require, skip,
};

const WRITE_LETTERS: &[char] = &['W', 'C', 'K', 'D', 'N', 'V'];

fn assert_read_only_permissions(permissions: &str, context: &str) {
    let granted: Vec<char> = WRITE_LETTERS
        .iter()
        .copied()
        .filter(|letter| permissions.contains(*letter))
        .collect();
    assert!(
        granted.is_empty(),
        "{context}: read-only scope must not report write permissions {granted:?} (got {permissions:?})"
    );
}

/// Seeds `<dir>/file.txt` and `<dir>/sub/` with the full credential.
async fn seed(ctx: &Ctx) -> Dav {
    let dav = ctx.dav();
    dav.write(&ctx.path("file.txt"), "original").await;
    dav.create_dir(&ctx.path("sub")).await;
    dav
}

#[tokio::test]
async fn read_only_scope_can_read() {
    let Some(ctx) = Ctx::new().await else { return };
    let view = require!(ctx.view(), "GONO_ACCEPT_VIEW_PASSWORD not set");
    seed(&ctx).await;
    let dav = ctx.dav_as(&view);

    let listing = dav
        .propfind(&ctx.dir, "1", PROPFIND_STANDARD)
        .await
        .multistatus();
    let file = listing
        .get(&dav.href_path(&ctx.path("file.txt")))
        .expect("file in listing");
    let sub = listing
        .get(&dav.href_path(&ctx.path("sub")))
        .expect("sub in listing");
    assert_read_only_permissions(&file.text(OC, "permissions").unwrap_or_default(), "file");
    assert_read_only_permissions(&sub.text(OC, "permissions").unwrap_or_default(), "folder");

    assert_eq!(dav.read(&ctx.path("file.txt")).await, b"original");
    let head = dav.head(&ctx.path("file.txt")).await;
    head.expect(&[200]);
    if let Some(permissions) = head.header("x-nc-permissions") {
        assert_read_only_permissions(&permissions, "HEAD X-NC-Permissions");
    }
}

#[tokio::test]
async fn read_only_scope_rejects_write_methods() {
    let Some(ctx) = Ctx::new().await else { return };
    let view = require!(ctx.view(), "GONO_ACCEPT_VIEW_PASSWORD not set");
    let full = seed(&ctx).await;
    let dav = ctx.dav_as(&view);
    let file = ctx.path("file.txt");

    let attempts: Vec<(&str, gono_acceptance::Resp)> = vec![
        (
            "PUT new file",
            dav.put(&ctx.path("new.txt"), "blocked").await,
        ),
        ("PUT overwrite", dav.put(&file, "blocked").await),
        ("MKCOL", dav.mkcol(&ctx.path("new-dir")).await),
        ("DELETE file", dav.delete(&file).await),
        ("DELETE folder", dav.delete(&ctx.path("sub")).await),
        ("MOVE", dav.mv(&file, &ctx.path("moved.txt"), None).await),
        ("COPY", dav.copy(&file, &ctx.path("copied.txt"), None).await),
        (
            "PROPPATCH dead property",
            dav.proppatch(&file, &proppatch_set_dead(&[("blocked", "1")]))
                .await,
        ),
        (
            "LOCK",
            dav.send(
                dav.request("LOCK", &dav.url(&file))
                    .header("Depth", "0")
                    .header("Timeout", "Second-30")
                    .header("Content-Type", "application/xml; charset=utf-8")
                    .body(LOCKINFO_EXCLUSIVE),
            )
            .await,
        ),
    ];
    let accepted: Vec<String> = attempts
        .iter()
        .filter(|(_, response)| response.code() != 403)
        .map(|(name, response)| format!("{name}: {}", response.describe()))
        .collect();

    assert_eq!(full.read(&file).await, b"original");
    for rel in ["new.txt", "new-dir", "moved.txt", "copied.txt"] {
        full.propfind(&ctx.path(rel), "0", PROPFIND_STANDARD)
            .await
            .expect(&[404]);
    }
    assert!(full.stat(&ctx.path("sub")).await.is_collection());
    assert!(
        accepted.is_empty(),
        "read-only scope must answer 403 to every write method:\n{}",
        accepted.join("\n")
    );
}

/// Regression (legacy): a read-only app password could rewrite files with
/// `PATCH` + `X-Update-Range: append` (PUT was 403, PATCH returned 204).
#[tokio::test]
async fn regression_read_only_scope_rejects_patch() {
    let Some(ctx) = Ctx::new().await else { return };
    let view = require!(ctx.view(), "GONO_ACCEPT_VIEW_PASSWORD not set");
    let full = seed(&ctx).await;
    let dav = ctx.dav_as(&view);
    let file = ctx.path("file.txt");

    let patch = dav
        .send(
            dav.request("PATCH", &dav.url(&file))
                .header("Content-Type", "application/x-sabredav-partialupdate")
                .header("X-Update-Range", "append")
                .body(" appended"),
        )
        .await;
    let content = String::from_utf8_lossy(&full.read(&file).await).into_owned();
    assert_eq!(
        content,
        "original",
        "read-only PATCH changed the file\n{}",
        patch.describe()
    );
    patch.expect(&[403]);
}

#[tokio::test]
async fn read_only_scope_rejects_chunked_upload() {
    let Some(ctx) = Ctx::new().await else { return };
    let view = require!(ctx.view(), "GONO_ACCEPT_VIEW_PASSWORD not set");
    let full = seed(&ctx).await;
    let dav = ctx.dav_as(&view);
    let upload = format!("acc-{}", random_id());
    let rel = ctx.path("chunked.txt");
    let destination = dav.url(&rel);

    let mkcol = dav
        .send(
            dav.request("MKCOL", &dav.upload_url(&upload))
                .header("Destination", &destination)
                .header("OC-Total-Length", "5"),
        )
        .await;
    let outcome = if mkcol.code() == 403 {
        mkcol
    } else {
        let chunk = dav
            .send(
                dav.request("PUT", &dav.upload_url(&format!("{upload}/00001")))
                    .header("Destination", &destination)
                    .header("OC-Total-Length", "5")
                    .body("hello"),
            )
            .await;
        if chunk.code() == 403 {
            chunk
        } else {
            dav.send(
                dav.request("MOVE", &dav.upload_url(&format!("{upload}/.file")))
                    .header("Destination", &destination)
                    .header("OC-Total-Length", "5"),
            )
            .await
        }
    };
    dav.delete_upload(&upload).await;
    full.get(&rel).await.expect(&[404]);
    outcome.expect(&[403]);
}

/// Prepares the scoped password's storage directories and a per-test subdirectory in both.
async fn scoped_setup(ctx: &Ctx) -> Option<(Cred, Dav, Dav)> {
    let scoped = match ctx.scoped() {
        Some(scoped) => scoped,
        None => {
            skip("GONO_ACCEPT_SCOPED_PASSWORD not set");
            return None;
        }
    };
    let full = ctx.dav();
    for storage in [SCOPED_VIEW_STORAGE, SCOPED_FULL_STORAGE] {
        full.create_dir_all(storage).await;
        let rel = format!("{storage}/{}", ctx.dir);
        full.create_dir(&rel).await;
        ctx.cleanup_later(&ctx.cfg.full, &rel);
    }
    let dav = ctx.dav_as(&scoped);
    Some((scoped, full, dav))
}

#[tokio::test]
async fn scoped_password_lists_only_its_mounts() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((_, _, dav)) = scoped_setup(&ctx).await else {
        return;
    };
    let mut paths = dav
        .propfind("", "1", PROPFIND_STANDARD)
        .await
        .multistatus()
        .paths();
    paths.sort();
    let mut expected = vec![
        dav.href_path(""),
        dav.href_path(SCOPED_FULL_MOUNT),
        dav.href_path(SCOPED_VIEW_MOUNT),
    ];
    expected.sort();
    assert_eq!(paths, expected);
}

#[tokio::test]
async fn scoped_password_maps_mounts_to_storage_paths() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((_, full, dav)) = scoped_setup(&ctx).await else {
        return;
    };
    full.write(
        &format!("{SCOPED_VIEW_STORAGE}/{}/readme.txt", ctx.dir),
        "read me",
    )
    .await;
    assert_eq!(
        dav.read(&format!("{SCOPED_VIEW_MOUNT}/{}/readme.txt", ctx.dir))
            .await,
        b"read me"
    );

    let mounted = format!("{SCOPED_FULL_MOUNT}/{}/upload.txt", ctx.dir);
    dav.put(&mounted, "uploaded").await.expect(&[201]);
    assert_eq!(
        full.read(&format!("{SCOPED_FULL_STORAGE}/{}/upload.txt", ctx.dir))
            .await,
        b"uploaded"
    );
    full.get(&mounted).await.expect(&[404]);

    let listing = dav
        .propfind(
            &format!("{SCOPED_FULL_MOUNT}/{}", ctx.dir),
            "1",
            PROPFIND_STANDARD,
        )
        .await
        .multistatus();
    assert!(
        listing.get(&dav.href_path(&mounted)).is_some(),
        "hrefs must use the mount path: {:?}",
        listing.paths()
    );

    let moved = format!("{SCOPED_FULL_MOUNT}/{}/moved.txt", ctx.dir);
    dav.mv(&mounted, &moved, None).await.expect(&[201]);
    assert_eq!(
        full.read(&format!("{SCOPED_FULL_STORAGE}/{}/moved.txt", ctx.dir))
            .await,
        b"uploaded"
    );
}

#[tokio::test]
async fn scoped_password_rejects_paths_outside_its_mounts() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((_, full, dav)) = scoped_setup(&ctx).await else {
        return;
    };
    full.write(&ctx.path("secret.txt"), "secret").await;
    full.write(&format!("{SCOPED_VIEW_STORAGE}/{}/r.txt", ctx.dir), "r")
        .await;

    for (name, response) in [
        ("GET outside file", dav.get(&ctx.path("secret.txt")).await),
        (
            "PROPFIND outside folder",
            dav.propfind(&ctx.dir, "0", PROPFIND_STANDARD).await,
        ),
        (
            "GET storage path instead of mount path",
            dav.get(&format!("{SCOPED_VIEW_STORAGE}/{}/r.txt", ctx.dir))
                .await,
        ),
    ] {
        assert!(
            matches!(response.code(), 403 | 404),
            "{name} must be 403 or 404\n{}",
            response.describe()
        );
        assert_ne!(response.body, b"secret");
    }

    for (name, response) in [
        (
            "PUT into the virtual root",
            dav.put(&format!("{}-x.txt", ctx.dir), "x").await,
        ),
        (
            "MKCOL in the virtual root",
            dav.mkcol(&format!("{}-dir", ctx.dir)).await,
        ),
        (
            "PUT outside folder",
            dav.put(&ctx.path("intruder.txt"), "x").await,
        ),
    ] {
        assert!(
            response.status.is_client_error(),
            "{name} must be rejected\n{}",
            response.describe()
        );
    }
    full.get(&ctx.path("intruder.txt")).await.expect(&[404]);
    full.get(&format!("{}-x.txt", ctx.dir)).await.expect(&[404]);
}

#[tokio::test]
async fn scoped_view_mount_rejects_writes() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((_, full, dav)) = scoped_setup(&ctx).await else {
        return;
    };
    let view_dir = format!("{SCOPED_VIEW_MOUNT}/{}", ctx.dir);
    let full_dir = format!("{SCOPED_FULL_MOUNT}/{}", ctx.dir);
    dav.write(&format!("{full_dir}/source.txt"), "source").await;
    full.write(&format!("{SCOPED_VIEW_STORAGE}/{}/r.txt", ctx.dir), "r")
        .await;

    for (name, response) in [
        ("PUT", dav.put(&format!("{view_dir}/new.txt"), "x").await),
        ("DELETE", dav.delete(&format!("{view_dir}/r.txt")).await),
        (
            "COPY into view mount",
            dav.copy(
                &format!("{full_dir}/source.txt"),
                &format!("{view_dir}/copied.txt"),
                None,
            )
            .await,
        ),
        (
            "MOVE into view mount",
            dav.mv(
                &format!("{full_dir}/source.txt"),
                &format!("{view_dir}/moved.txt"),
                None,
            )
            .await,
        ),
        (
            "MOVE out of view mount",
            dav.mv(
                &format!("{view_dir}/r.txt"),
                &format!("{full_dir}/stolen.txt"),
                None,
            )
            .await,
        ),
    ] {
        assert_eq!(response.code(), 403, "{name}\n{}", response.describe());
    }
    assert_eq!(dav.read(&format!("{full_dir}/source.txt")).await, b"source");
    assert_eq!(dav.read(&format!("{view_dir}/r.txt")).await, b"r");
}

/// Creates the per-test directory in the second user's tree too.
async fn user2_setup(ctx: &Ctx) -> Option<(Cred, Dav)> {
    let user2 = match ctx.user2() {
        Some(user2) => user2,
        None => {
            skip("GONO_ACCEPT_USER2/PASSWORD2 not set");
            return None;
        }
    };
    let dav2 = ctx.dav_as(&user2);
    dav2.create_dir(&ctx.dir).await;
    ctx.cleanup_later(&user2, &ctx.dir);
    dav2.write(&ctx.path("private.txt"), "user2 private").await;
    Some((user2, dav2))
}

#[tokio::test]
async fn users_cannot_reach_each_others_files() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((user2, dav2)) = user2_setup(&ctx).await else {
        return;
    };
    let dav1 = ctx.dav();
    dav1.write(&ctx.path("mine.txt"), "user1 private").await;

    let foreign_url = dav1.url_for_user(&user2.user, &ctx.path("private.txt"));
    let foreign_root = dav1.url_for_user(&user2.user, "");
    let attempts = [
        (
            "PROPFIND other user's root",
            dav1.propfind_url(&foreign_root, "0", PROPFIND_STANDARD)
                .await,
        ),
        (
            "GET other user's file",
            dav1.send(dav1.request("GET", &foreign_url)).await,
        ),
        (
            "PUT into other user's tree",
            dav1.send(
                dav1.request(
                    "PUT",
                    &dav1.url_for_user(&user2.user, &ctx.path("planted.txt")),
                )
                .body("planted"),
            )
            .await,
        ),
        (
            "DELETE other user's file",
            dav1.send(dav1.request("DELETE", &foreign_url)).await,
        ),
    ];
    for (name, response) in &attempts {
        assert!(
            matches!(response.code(), 403 | 404),
            "{name} must be 403 or 404\n{}",
            response.describe()
        );
        assert_ne!(response.body, b"user2 private");
    }

    assert_eq!(dav2.read(&ctx.path("private.txt")).await, b"user2 private");
    dav2.get(&ctx.path("planted.txt")).await.expect(&[404]);
    dav2.get(&ctx.path("mine.txt")).await.expect(&[404]);
    assert_eq!(dav1.read(&ctx.path("mine.txt")).await, b"user1 private");
}

#[tokio::test]
async fn destination_in_another_users_tree_is_rejected() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((user2, dav2)) = user2_setup(&ctx).await else {
        return;
    };
    let dav1 = ctx.dav();
    dav1.write(&ctx.path("mine.txt"), "mine").await;

    for method in ["COPY", "MOVE"] {
        let destination = dav1.url_for_user(&user2.user, &ctx.path(&format!("{method}.txt")));
        let response = dav1
            .transfer(method, &ctx.path("mine.txt"), &destination, None)
            .await;
        assert!(
            response.status.is_client_error(),
            "{method} into another user's tree must be rejected\n{}",
            response.describe()
        );
        dav2.get(&ctx.path(&format!("{method}.txt")))
            .await
            .expect(&[404]);
    }
    assert_eq!(dav1.read(&ctx.path("mine.txt")).await, b"mine");
}

#[tokio::test]
async fn dot_dot_cannot_escape_the_user_root() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((user2, _dav2)) = user2_setup(&ctx).await else {
        return;
    };
    let user1 = encode_path(&ctx.cfg.full.user);
    let target_tail = format!(
        "{}/{}/private.txt",
        encode_path(&user2.user),
        encode_path(&ctx.dir)
    );

    for target in [
        format!("/remote.php/dav/files/{user1}/%2e%2e/{target_tail}"),
        format!("/remote.php/dav/files/{user1}/..%2F{target_tail}"),
        format!("/remote.php/dav/files/{user1}/%2e%2e%2f{target_tail}"),
    ] {
        match raw::status(ctx.base_url(), "GET", &target, &ctx.cfg.full, &[], b"").await {
            Ok(status) => assert!(
                (400..500).contains(&status),
                "GET {target} must be rejected, got {status}"
            ),
            Err(reason) => {
                skip(&format!("raw request checks skipped: {reason}"));
                return;
            }
        }
    }
}

#[tokio::test]
async fn chunked_upload_cannot_target_another_user() {
    let Some(ctx) = Ctx::new().await else { return };
    let Some((user2, dav2)) = user2_setup(&ctx).await else {
        return;
    };
    let dav1 = ctx.dav();
    let upload = format!("acc-{}", random_id());

    let foreign_session = format!(
        "{}/remote.php/dav/uploads/{}/{upload}",
        ctx.base_url(),
        encode_path(&user2.user)
    );
    let response = dav1
        .send(
            dav1.request("MKCOL", &foreign_session)
                .header("Destination", dav1.url(&ctx.path("x.txt")))
                .header("OC-Total-Length", "1"),
        )
        .await;
    assert!(
        matches!(response.code(), 403 | 404),
        "MKCOL in another user's upload namespace must be 403 or 404\n{}",
        response.describe()
    );

    let foreign_destination = dav1.url_for_user(&user2.user, &ctx.path("chunked.txt"));
    let mkcol = dav1
        .send(
            dav1.request("MKCOL", &dav1.upload_url(&upload))
                .header("Destination", &foreign_destination)
                .header("OC-Total-Length", "5"),
        )
        .await;
    if mkcol.is_success() {
        dav1.send(
            dav1.request("PUT", &dav1.upload_url(&format!("{upload}/00001")))
                .header("Destination", &foreign_destination)
                .header("OC-Total-Length", "5")
                .body("hello"),
        )
        .await;
        let moved = dav1
            .send(
                dav1.request("MOVE", &dav1.upload_url(&format!("{upload}/.file")))
                    .header("Destination", &foreign_destination)
                    .header("OC-Total-Length", "5"),
            )
            .await;
        dav1.delete_upload(&upload).await;
        assert!(
            moved.status.is_client_error(),
            "assembling into another user's tree must be rejected\n{}",
            moved.describe()
        );
    }
    dav2.get(&ctx.path("chunked.txt")).await.expect(&[404]);
}
