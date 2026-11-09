//! Account and app password storage against a real SQLite database.

use gono_core::{
    Error, Permission, RelPath, Username,
    app_passwords::{self, Scope},
    config::DbConfig,
    db::{self, OpenMode, Pool},
    users::{self, NewUser},
};
use secrecy::{ExposeSecret, SecretString};

async fn database(dir: &std::path::Path) -> Pool {
    let config = DbConfig {
        path: dir.join("gono-cloud.db"),
        max_connections: 4,
        busy_timeout_secs: 5,
    };
    let pool = db::connect(&config, OpenMode::CreateIfMissing)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    pool
}

async fn add_user(pool: &Pool, name: &str) -> i64 {
    let username = Username::new(name).unwrap();
    users::create(
        pool,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: "not-a-real-hash",
            is_admin: false,
        },
        |_| Ok(()),
    )
    .await
    .unwrap()
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

#[tokio::test]
async fn failed_storage_setup_rolls_the_account_back() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;
    let username = Username::new("carol").unwrap();
    let result = users::create(
        &pool,
        &NewUser {
            username: &username,
            display_name: "Carol",
            password_hash: "x",
            is_admin: false,
        },
        |_| Err(Error::InvalidScopes("simulated".into())),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(users::find(&pool, &username).await.unwrap(), None);
}

#[tokio::test]
async fn app_passwords_authenticate_only_their_owner() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;
    let alice = add_user(&pool, "alice").await;
    add_user(&pool, "bob").await;

    let scopes = vec![Scope {
        mount_path: RelPath::parse("/Photos").unwrap(),
        storage_path: RelPath::parse("/Media/Photos").unwrap(),
        permission: Permission::View,
    }];
    let (id, token) = app_passwords::create(&pool, alice, "phone", scopes.clone(), None)
        .await
        .unwrap();

    let device = app_passwords::authenticate(&pool, "alice", &token, 100)
        .await
        .unwrap()
        .expect("valid credentials");
    assert_eq!(device.app_password_id, id);
    assert_eq!(device.user_id, alice);
    assert_eq!(device.scopes, scopes);

    for (user, password) in [
        ("bob", token.expose_secret().to_owned()),
        ("alice", "wrong-password".to_owned()),
        ("ALICE", token.expose_secret().to_owned()),
    ] {
        assert!(
            app_passwords::authenticate(&pool, user, &secret(&password), 100)
                .await
                .unwrap()
                .is_none(),
            "{user}"
        );
    }

    users::set_enabled(&pool, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    assert!(
        app_passwords::authenticate(&pool, "alice", &token, 100)
            .await
            .unwrap()
            .is_none(),
        "disabled accounts cannot sign in"
    );
}

#[tokio::test]
async fn expired_app_passwords_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;
    let alice = add_user(&pool, "alice").await;
    let (_, token) = app_passwords::create(&pool, alice, "temp", Vec::new(), Some(1000))
        .await
        .unwrap();
    assert!(
        app_passwords::authenticate(&pool, "alice", &token, 999)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        app_passwords::authenticate(&pool, "alice", &token, 1000)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn listing_deleting_and_recording_use() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;
    let alice = add_user(&pool, "alice").await;
    let bob = add_user(&pool, "bob").await;
    let (first, _) = app_passwords::create(&pool, alice, "laptop", Vec::new(), None)
        .await
        .unwrap();
    app_passwords::create(&pool, alice, "phone", Vec::new(), None)
        .await
        .unwrap();

    app_passwords::record_use(&pool, first, 500).await.unwrap();
    app_passwords::record_use(&pool, first, 400).await.unwrap();
    let listed = app_passwords::list(&pool, alice).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].last_used_at, Some(500), "never moves backwards");
    assert_eq!(listed[0].scopes, [Scope::full_access()]);

    assert!(
        !app_passwords::delete(&pool, bob, first).await.unwrap(),
        "only the owner can revoke"
    );
    assert!(app_passwords::delete(&pool, alice, first).await.unwrap());
    assert_eq!(app_passwords::list(&pool, alice).await.unwrap().len(), 1);
}
