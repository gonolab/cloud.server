//! The SQLite lock system behind dav-server.

mod common;

use std::time::Duration;

use common::{Harness, mount};
use gono_core::locks::LockStore;
use gono_dav::locks::SqliteLs;

const LOCKINFO: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:lockinfo xmlns:d="DAV:">
  <d:lockscope><d:exclusive/></d:lockscope>
  <d:locktype><d:write/></d:locktype>
  <d:owner><d:href>tester</d:href></d:owner>
</d:lockinfo>"#;

/// A handler with a fresh lock system over the harness's database and file system.
fn handler(h: &Harness, max_timeout: u64) -> dav_server::DavHandler<gono_dav::Ctx> {
    dav_server::DavHandler::builder()
        .filesystem(Box::new(h.fs.clone()))
        .locksystem(SqliteLs::new(
            LockStore::new(h.pool.clone()),
            Duration::from_secs(max_timeout),
        ))
        .build_handler()
}

async fn harness(max_timeout: u64) -> Harness {
    let h = Harness::new().await;
    let handler = handler(&h, max_timeout);
    Harness { handler, ..h }
}

fn token(response: &common::Response) -> String {
    response.header("lock-token").expect("Lock-Token header")
}

#[tokio::test]
async fn exclusive_locks_block_writes_without_the_token() {
    let h = harness(3600).await;
    let full = h.full();
    h.put(&full, "locked.txt", "before").await.expect(201);
    let lock = h
        .send(
            &full,
            "LOCK",
            "locked.txt",
            &[("Depth", "0"), ("Timeout", "Second-60")],
            LOCKINFO,
        )
        .await;
    lock.expect(200);
    let token = token(&lock);
    assert!(token.starts_with("<opaquelocktoken:"), "{token}");
    assert!(lock.text().contains("activelock"), "{}", lock.text());

    h.put(&full, "locked.txt", "blocked").await.expect(423);
    h.send(&full, "DELETE", "locked.txt", &[], "")
        .await
        .expect(423);
    h.send(
        &full,
        "MOVE",
        "locked.txt",
        &[("Destination", "/remote.php/dav/files/alice/moved.txt")],
        "",
    )
    .await
    .expect(423);
    h.send(&full, "LOCK", "locked.txt", &[("Depth", "0")], LOCKINFO)
        .await
        .expect(423);

    let if_header = format!("({token})");
    h.send(
        &full,
        "PUT",
        "locked.txt",
        &[("If", if_header.as_str())],
        "with token",
    )
    .await
    .expect(204);
    h.send(
        &full,
        "UNLOCK",
        "locked.txt",
        &[(
            "Lock-Token",
            "<opaquelocktoken:00000000-0000-4000-8000-000000000000>",
        )],
        "",
    )
    .await
    .expect(409);
    h.send(
        &full,
        "UNLOCK",
        "locked.txt",
        &[("Lock-Token", token.as_str())],
        "",
    )
    .await
    .expect(204);
    h.put(&full, "locked.txt", "after").await.expect(204);
}

#[tokio::test]
async fn timeouts_are_clamped_and_expired_locks_are_ignored() {
    let h = harness(120).await;
    let full = h.full();
    h.put(&full, "f.txt", "x").await.expect(201);
    let lock = h
        .send(&full, "LOCK", "f.txt", &[("Timeout", "Infinite")], LOCKINFO)
        .await;
    lock.expect(200);
    assert!(lock.text().contains("Second-120"), "{}", lock.text());
    let timeout_at: i64 = sqlx::query_scalar("SELECT timeout_at - created_at FROM locks")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(timeout_at, 120);

    sqlx::query("UPDATE locks SET timeout_at = 1")
        .execute(&h.pool)
        .await
        .unwrap();
    h.put(&full, "f.txt", "free again").await.expect(204);
}

#[tokio::test]
async fn deep_locks_cover_descendants_and_show_in_propfind() {
    let h = harness(3600).await;
    let full = h.full();
    h.mkcol(&full, "dir").await.expect(201);
    h.put(&full, "dir/inner.txt", "x").await.expect(201);
    let lock = h
        .send(&full, "LOCK", "dir", &[("Depth", "infinity")], LOCKINFO)
        .await;
    lock.expect(200);
    h.put(&full, "dir/inner.txt", "blocked").await.expect(423);
    h.put(&full, "dir/new.txt", "blocked").await.expect(423);

    let discovery = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:lockdiscovery/></d:prop></d:propfind>"#;
    let response = h
        .send(
            &full,
            "PROPFIND",
            "dir/inner.txt",
            &[("Depth", "0")],
            discovery,
        )
        .await;
    let text = response.text();
    assert!(
        text.contains(&token(&lock).trim_matches(['<', '>']).to_owned()),
        "{text}"
    );
    assert!(
        text.contains("/remote.php/dav/files/alice/dir/"),
        "lock root: {text}"
    );
}

/// litmus sends the lock owner as text in a default namespace (`<lockinfo xmlns="DAV:">`).
#[tokio::test]
async fn owners_in_a_default_namespace_survive_storage() {
    let h = harness(3600).await;
    let full = h.full();
    h.put(&full, "owned.txt", "x").await.expect(201);
    let lockinfo = r#"<?xml version="1.0" encoding="utf-8"?><lockinfo xmlns="DAV:"><lockscope><exclusive/></lockscope><locktype><write/></locktype><owner>litmus test suite</owner></lockinfo>"#;
    let lock = h
        .send(&full, "LOCK", "owned.txt", &[("Depth", "0")], lockinfo)
        .await;
    lock.expect(200);
    assert!(lock.text().contains("litmus test suite"), "{}", lock.text());
    let discovery = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:lockdiscovery/></d:prop></d:propfind>"#;
    let found = h
        .send(&full, "PROPFIND", "owned.txt", &[("Depth", "0")], discovery)
        .await;
    assert!(
        found.text().contains("litmus test suite"),
        "{}",
        found.text()
    );
}

#[tokio::test]
async fn locks_follow_storage_paths_across_mounts_and_restarts() {
    let h = harness(3600).await;
    let full = h.full();
    h.mkcol(&full, "shared").await.expect(201);
    h.put(&full, "shared/doc.txt", "x").await.expect(201);
    let scoped = h.identity(vec![mount("/work", "/shared", true)]);
    h.send(&scoped, "LOCK", "work/doc.txt", &[("Depth", "0")], LOCKINFO)
        .await
        .expect(200);
    h.put(&full, "shared/doc.txt", "other mount")
        .await
        .expect(423);

    // A new lock system over the same database still knows the lock.
    let restarted = handler(&h, 3600);
    h.send_via(
        &restarted,
        &full,
        "PUT",
        "shared/doc.txt",
        &[],
        "after restart",
    )
    .await
    .expect(423);
}
