//! Short-lived protocol state against a real SQLite database: chunked upload sessions.

use gono_core::{
    RelPath, Username,
    config::DbConfig,
    db::{self, OpenMode, Pool},
    uploads::{self, SESSION_TTL_SECS},
    users::{self, NewUser},
};

async fn fixture() -> (tempfile::TempDir, Pool, i64) {
    let dir = tempfile::tempdir().unwrap();
    let config = DbConfig {
        path: dir.path().join("gono-cloud.db"),
        max_connections: 4,
        busy_timeout_secs: 5,
    };
    let pool = db::connect(&config, OpenMode::CreateIfMissing)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let username = Username::new("alice").unwrap();
    let owner = users::create(
        &pool,
        &NewUser {
            username: &username,
            display_name: "Alice",
            password_hash: "x",
            is_admin: false,
        },
        |_| Ok(()),
    )
    .await
    .unwrap();
    (dir, pool, owner)
}

#[tokio::test]
async fn upload_sessions_live_until_they_expire() {
    let (_dir, pool, owner) = fixture().await;
    let target = RelPath::parse("docs/big.bin").unwrap();
    let now = 1_000;
    assert!(
        uploads::create(&pool, owner, "s1", Some(&target), Some(11), now)
            .await
            .unwrap()
    );
    assert!(
        !uploads::create(&pool, owner, "s1", None, None, now)
            .await
            .unwrap(),
        "ids are unique per user"
    );
    assert!(
        uploads::create(&pool, owner, "S1", None, None, now)
            .await
            .unwrap(),
        "ids compare byte for byte"
    );

    let session = uploads::get(&pool, owner, "s1", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.target, Some(target));
    assert_eq!(session.total_size, Some(11));
    assert_eq!(session.expires_at, now + SESSION_TTL_SECS);
    let unbound = uploads::get(&pool, owner, "S1", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unbound.target, None, "the MOVE names the destination");

    // Activity extends the lifetime.
    let later = now + SESSION_TTL_SECS - 1;
    assert!(uploads::touch(&pool, owner, "s1", later).await.unwrap());
    let expired_at = now + SESSION_TTL_SECS;
    assert!(
        uploads::get(&pool, owner, "S1", expired_at)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        uploads::get(&pool, owner, "s1", expired_at)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        !uploads::touch(&pool, owner, "S1", expired_at)
            .await
            .unwrap()
    );
    assert_eq!(
        uploads::list(&pool, owner, expired_at)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.upload_id)
            .collect::<Vec<_>>(),
        ["s1"]
    );

    // An expired session can be created again under its id.
    assert!(
        uploads::create(&pool, owner, "S1", None, None, expired_at)
            .await
            .unwrap()
    );
    let purged = uploads::purge_expired(&pool, later + SESSION_TTL_SECS)
        .await
        .unwrap();
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0], (owner, "s1".to_owned()));
    assert_eq!(uploads::all_ids(&pool).await.unwrap().len(), 1);
    assert!(uploads::delete(&pool, owner, "S1").await.unwrap());
    assert!(!uploads::delete(&pool, owner, "S1").await.unwrap());
}
