//! Short-lived protocol state against a real SQLite database: chunked upload sessions, Login
//! Flow v2 sign-ins and browser sessions.

use gono_core::{
    RelPath, Username, app_passwords,
    config::DbConfig,
    db::{self, OpenMode, Pool},
    login_flows::{self, FLOW_TTL_SECS},
    uploads::{self, SESSION_TTL_SECS},
    users::{self, NewUser},
    web_sessions::{self, IDLE_TIMEOUT_SECS, MAX_LIFETIME_SECS},
};
use secrecy::ExposeSecret as _;

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

#[tokio::test]
async fn login_flows_mint_one_app_password_after_consent() {
    let (_dir, pool, owner) = fixture().await;
    let now = 5_000;
    let flow = login_flows::create(&pool, "Nextcloud desktop 3.13.0 (macOS)", now)
        .await
        .unwrap()
        .unwrap();
    let poll = flow.poll_token.expose_secret();
    let login = flow.login_token.expose_secret();
    assert_ne!(poll, login);
    assert_eq!(flow.expires_at, now + FLOW_TTL_SECS);

    // Pending until granted; the poll token does not open the browser pages.
    assert!(
        login_flows::complete(&pool, poll, now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(login_flows::find(&pool, poll, now).await.unwrap().is_none());
    let found = login_flows::find(&pool, login, now).await.unwrap().unwrap();
    assert_eq!(found.client_name, "Nextcloud desktop 3.13.0 (macOS)");
    assert_eq!(found.granted_user_id, None);
    assert!(
        login_flows::grant(&pool, found.id, owner, now)
            .await
            .unwrap()
    );
    assert!(
        !login_flows::grant(&pool, found.id, owner, now)
            .await
            .unwrap(),
        "granted once"
    );

    let credentials = login_flows::complete(&pool, poll, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credentials.username.as_str(), "alice");
    assert_eq!(credentials.label, "Nextcloud desktop 3.13.0 (macOS)");
    let password = credentials.app_password.expose_secret();
    assert!(password.len() >= 40, "{password}");
    let device = app_passwords::authenticate(&pool, "alice", &credentials.app_password, now)
        .await
        .unwrap()
        .expect("the minted app password works");
    assert_eq!(device.scopes, [app_passwords::Scope::full_access()]);
    assert!(
        login_flows::complete(&pool, poll, now)
            .await
            .unwrap()
            .is_none(),
        "single use"
    );
    assert!(
        login_flows::find(&pool, login, now)
            .await
            .unwrap()
            .is_none()
    );

    // Denied and expired flows never complete.
    let denied = login_flows::create(&pool, "x", now).await.unwrap().unwrap();
    let id = login_flows::find(&pool, denied.login_token.expose_secret(), now)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert!(login_flows::deny(&pool, id).await.unwrap());
    assert!(
        !login_flows::grant(&pool, id, owner, now).await.unwrap(),
        "nothing left to grant"
    );
    let late = login_flows::create(&pool, "y", now).await.unwrap().unwrap();
    let id = login_flows::find(&pool, late.login_token.expose_secret(), now)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert!(login_flows::grant(&pool, id, owner, now).await.unwrap());
    let expired = now + FLOW_TTL_SECS;
    assert!(
        login_flows::complete(&pool, late.poll_token.expose_secret(), expired)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(login_flows::purge_expired(&pool, expired).await.unwrap(), 1);
    assert_eq!(app_passwords::list(&pool, owner).await.unwrap().len(), 1);
}

#[tokio::test]
async fn login_flows_are_bounded_and_skip_disabled_accounts() {
    let (_dir, pool, owner) = fixture().await;
    let now = 1;
    for _ in 0..login_flows::MAX_PENDING_FLOWS {
        assert!(
            login_flows::create(&pool, "c", now)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(
        login_flows::create(&pool, "c", now)
            .await
            .unwrap()
            .is_none()
    );
    let later = now + FLOW_TTL_SECS;
    let flow = login_flows::create(&pool, "c", later)
        .await
        .unwrap()
        .unwrap();
    let id = login_flows::find(&pool, flow.login_token.expose_secret(), later)
        .await
        .unwrap()
        .unwrap()
        .id;
    login_flows::grant(&pool, id, owner, later).await.unwrap();
    users::set_enabled(&pool, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    assert!(
        login_flows::complete(&pool, flow.poll_token.expose_secret(), later)
            .await
            .unwrap()
            .is_none()
    );
    assert!(app_passwords::list(&pool, owner).await.unwrap().is_empty());
}

#[tokio::test]
async fn web_sessions_slide_and_end() {
    let (_dir, pool, owner) = fixture().await;
    let now = 10_000;
    let token = web_sessions::create(&pool, owner, now).await.unwrap();
    let token = token.expose_secret();
    let user = web_sessions::lookup(&pool, token, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.username.as_str(), "alice");
    assert_eq!(user.user_id, owner);
    assert!(
        web_sessions::lookup(&pool, "other", now)
            .await
            .unwrap()
            .is_none()
    );

    // Use keeps it alive past the idle timeout, but not past the maximum lifetime.
    let mut at = now;
    while at + IDLE_TIMEOUT_SECS - 1 < now + MAX_LIFETIME_SECS {
        at += IDLE_TIMEOUT_SECS - 1;
        assert!(
            web_sessions::lookup(&pool, token, at)
                .await
                .unwrap()
                .is_some(),
            "{at}"
        );
    }
    assert!(
        web_sessions::lookup(&pool, token, now + MAX_LIFETIME_SECS)
            .await
            .unwrap()
            .is_none()
    );

    let idle = web_sessions::create(&pool, owner, now).await.unwrap();
    assert!(
        web_sessions::lookup(&pool, idle.expose_secret(), now + IDLE_TIMEOUT_SECS)
            .await
            .unwrap()
            .is_none()
    );
    let disabled = web_sessions::create(&pool, owner, now).await.unwrap();
    users::set_enabled(&pool, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    assert!(
        web_sessions::lookup(&pool, disabled.expose_secret(), now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        web_sessions::delete(&pool, disabled.expose_secret())
            .await
            .unwrap()
    );
    assert_eq!(
        web_sessions::purge_expired(&pool, now + MAX_LIFETIME_SECS)
            .await
            .unwrap(),
        2
    );
}
