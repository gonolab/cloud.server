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

async fn add_admin(pool: &Pool, name: &str) -> i64 {
    let username = Username::new(name).unwrap();
    users::create(
        pool,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: "x",
            is_admin: true,
        },
        |_| Ok(()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn the_last_enabled_admin_can_be_neither_disabled_nor_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;
    let root = Username::new("root").unwrap();
    let ops = Username::new("ops").unwrap();
    add_admin(&pool, "root").await;
    add_user(&pool, "alice").await;
    let alice = Username::new("alice").unwrap();

    assert!(matches!(
        users::set_enabled(&pool, &root, false).await,
        Err(Error::LastAdmin(_))
    ));
    assert!(matches!(
        users::delete(&pool, &root).await,
        Err(Error::LastAdmin(_))
    ));
    // Ordinary accounts are not affected.
    users::set_enabled(&pool, &alice, false).await.unwrap();
    users::delete(&pool, &alice).await.unwrap();

    // With a second enabled admin, either one may go, but not both.
    add_admin(&pool, "ops").await;
    users::set_enabled(&pool, &root, false).await.unwrap();
    assert!(matches!(
        users::delete(&pool, &ops).await,
        Err(Error::LastAdmin(_))
    ));
    // A disabled admin does not count, and may be deleted.
    users::delete(&pool, &root).await.unwrap();
    assert!(users::find(&pool, &ops).await.unwrap().unwrap().enabled);
}

#[tokio::test]
async fn concurrent_admin_removals_leave_one_admin() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;
    let names: Vec<Username> = ["a1", "a2", "a3", "a4"]
        .iter()
        .map(|name| Username::new(*name).unwrap())
        .collect();
    for name in &names {
        add_admin(&pool, name.as_str()).await;
    }
    // Every admin tries to disable or delete itself at the same moment.
    let tasks: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let pool = pool.clone();
            let name = name.clone();
            tokio::spawn(async move {
                if index % 2 == 0 {
                    users::set_enabled(&pool, &name, false).await
                } else {
                    users::delete(&pool, &name).await.map(|_| ())
                }
            })
        })
        .collect();
    let mut refused = 0;
    for task in tasks {
        if let Err(Error::LastAdmin(_)) = task.await.unwrap() {
            refused += 1;
        }
    }
    assert_eq!(refused, 1);
    let overview = gono_core::stats::overview(&pool, db::unix_now())
        .await
        .unwrap();
    assert_eq!(overview.admins, 1);
}

#[tokio::test]
async fn overview_counts() {
    let dir = tempfile::tempdir().unwrap();
    let pool = database(dir.path()).await;
    add_admin(&pool, "root").await;
    let alice = add_user(&pool, "alice").await;
    app_passwords::create(&pool, alice, "phone", Vec::new(), None)
        .await
        .unwrap();
    users::set_enabled(&pool, &Username::new("alice").unwrap(), false)
        .await
        .unwrap();
    let overview = gono_core::stats::overview(&pool, db::unix_now())
        .await
        .unwrap();
    assert_eq!(
        (overview.users, overview.admins, overview.disabled),
        (2, 1, 1)
    );
    assert_eq!(overview.app_passwords, 1);
    assert_eq!(overview.storage_used, 0);
    let per_user = gono_core::stats::per_user(&pool).await.unwrap();
    assert_eq!(per_user[&alice].app_passwords, 1);
}
