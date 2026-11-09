//! Schema migration tests: the migrations apply to an empty database, the resulting schema
//! enforces its constraints, and released migrations stay byte-for-byte unchanged.

use std::path::Path;

use gono_core::{
    Error, Username,
    config::DbConfig,
    db::{self, MIGRATOR, OpenMode, Pool},
    meta, password, users,
};
use secrecy::SecretString;

/// SHA-384 checksums (as computed by sqlx, equal to `shasum -a 384 <file>`) of every published
/// migration.
///
/// A migration counts as published once it is merged into `main`: from then on, development and
/// test databases have applied it, and sqlx refuses to open them if the file changes. If this
/// test fails because you edited one of these files, revert the edit and add a new migration
/// instead. Pin every new migration here in the change that adds it.
const RELEASED_MIGRATIONS: &[(i64, &str)] = &[(
    1,
    "b210dcedf8f0e378c06e55b33997812a9f78bdfdeef12d030f3ab88d6d0b65e75c85daace5264adbf6f2ccbba65b8124",
)];

fn db_config(dir: &Path) -> DbConfig {
    DbConfig {
        path: dir.join("nested").join("gono-cloud.db"),
        max_connections: 4,
        busy_timeout_secs: 5,
    }
}

async fn fresh_database(dir: &Path) -> Pool {
    let pool = db::connect(&db_config(dir), OpenMode::CreateIfMissing)
        .await
        .expect("connect");
    db::migrate(&pool).await.expect("migrate");
    pool
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn insert_user(pool: &Pool, username: &str) -> i64 {
    sqlx::query(
        "INSERT INTO users (username, display_name, password_hash, created_at, updated_at) \
         VALUES (?1, ?1, 'x', 0, 0)",
    )
    .bind(username)
    .execute(pool)
    .await
    .expect("insert user")
    .last_insert_rowid()
}

#[tokio::test]
async fn migrations_apply_to_an_empty_database() {
    let dir = tempfile::tempdir().unwrap();
    let pool = fresh_database(dir.path()).await;

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_schema WHERE type = 'table' \
         AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name <> '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        [
            "app_password_scopes",
            "app_passwords",
            "change_log",
            "dead_props",
            "files",
            "locks",
            "login_flows",
            "upload_sessions",
            "users",
            "web_sessions",
        ]
    );

    let applied: Vec<(i64, bool)> =
        sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    let expected: Vec<(i64, bool)> = MIGRATOR.iter().map(|m| (m.version, true)).collect();
    assert_eq!(applied, expected);
}

#[tokio::test]
async fn connections_use_wal_and_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let pool = fresh_database(dir.path()).await;

    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(journal_mode, "wal");

    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(foreign_keys, 1);
}

#[tokio::test]
async fn migrating_twice_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let pool = fresh_database(dir.path()).await;
    db::migrate(&pool).await.expect("second run");
    pool.close().await;

    let reopened = db::connect(&db_config(dir.path()), OpenMode::MustExist)
        .await
        .expect("reopen");
    db::migrate(&reopened).await.expect("run after reopen");
}

#[tokio::test]
async fn must_exist_never_creates_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let config = db_config(dir.path());
    let err = db::connect(&config, OpenMode::MustExist).await.unwrap_err();
    assert!(matches!(err, Error::DatabaseMissing { .. }), "{err:?}");
    assert!(!config.path.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let _pool = fresh_database(dir.path()).await;
    let config = db_config(dir.path());
    let mode = std::fs::metadata(&config.path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");
}

#[test]
fn released_migrations_are_unchanged() {
    for &(version, checksum) in RELEASED_MIGRATIONS {
        let migration = MIGRATOR
            .iter()
            .find(|m| m.version == version)
            .unwrap_or_else(|| panic!("released migration {version} was removed"));
        assert_eq!(
            hex(&migration.checksum),
            checksum,
            "released migration {version} was modified; add a new migration instead"
        );
    }
}

#[test]
fn migration_versions_are_contiguous() {
    let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    let expected: Vec<i64> = (1..=i64::try_from(versions.len()).unwrap()).collect();
    assert_eq!(versions, expected);
}

#[tokio::test]
async fn schema_enforces_constraints() {
    let dir = tempfile::tempdir().unwrap();
    let pool = fresh_database(dir.path()).await;
    let alice = insert_user(&pool, "alice").await;

    let rejects = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            let result = sqlx::query(sql).bind(alice).execute(&pool).await;
            assert!(result.is_err(), "should be rejected: {sql}");
        }
    };

    // Usernames are unique.
    rejects(
        "INSERT INTO users (username, display_name, password_hash, created_at, updated_at) \
         SELECT username, 'x', 'x', 0, 0 FROM users WHERE id = ?1",
    )
    .await;
    // Token hashes are 32-byte SHA-256 digests.
    rejects(
        "INSERT INTO app_passwords (user_id, token_hash, label, created_at) \
         VALUES (?1, x'00', 'short', 0)",
    )
    .await;
    // Foreign keys are enforced.
    rejects(
        "INSERT INTO app_passwords (user_id, token_hash, label, created_at) \
         VALUES (?1 + 100, zeroblob(32), 'orphan', 0)",
    )
    .await;
    // STRICT tables reject values of the wrong type.
    rejects(
        "INSERT INTO files (owner_id, rel_path, is_dir, etag, mtime_ns) \
         VALUES (?1, 'a', 0, 'e', 'yesterday')",
    )
    .await;
    // Locks always expire.
    rejects(
        "INSERT INTO locks (token, owner_id, rel_path, shared, deep, created_at, timeout_at) \
         VALUES ('t', ?1, 'a', 0, 0, 0, NULL)",
    )
    .await;

    let app_password: i64 = sqlx::query_scalar(
        "INSERT INTO app_passwords (user_id, token_hash, label, created_at) \
         VALUES (?1, zeroblob(32), 'laptop', 0) RETURNING id",
    )
    .bind(alice)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Scope permissions are limited to 'view' and 'full'.
    for (permission, ok) in [
        ("view", true),
        ("full", true),
        ("admin", false),
        ("VIEW", false),
    ] {
        let result = sqlx::query(
            "INSERT INTO app_password_scopes (app_password_id, mount_path, storage_path, permission) \
             VALUES (?1, ?2, '', ?2)",
        )
        .bind(app_password)
        .bind(permission)
        .execute(&pool)
        .await;
        assert_eq!(result.is_ok(), ok, "permission {permission:?}");
    }

    // Deleting a user removes everything that belongs to them.
    sqlx::query(
        "INSERT INTO files (owner_id, rel_path, is_dir, etag, mtime_ns) VALUES (?1, '', 1, 'e', 0)",
    )
    .bind(alice)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    for table in ["app_passwords", "app_password_scopes", "files"] {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let remaining: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining, 0,
            "{table} should be empty after deleting the user"
        );
    }
}

#[tokio::test]
async fn rel_path_ranges_select_exactly_the_subtree() {
    let dir = tempfile::tempdir().unwrap();
    let pool = fresh_database(dir.path()).await;
    let alice = insert_user(&pool, "alice").await;

    let paths = [
        "", "a", "a/b", "a/b/c", "a/_", "a/%", "A", "A/b", "a_b", "a%", "a.b", "ab", "a0", "b",
    ];
    for path in paths {
        sqlx::query(
            "INSERT INTO files (owner_id, rel_path, is_dir, etag, mtime_ns) \
             VALUES (?1, ?2, 0, 'e', 0)",
        )
        .bind(alice)
        .bind(path)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Paths that differ only in case are distinct rows (BINARY collation).
    let case_matches: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE owner_id = ?1 AND rel_path = 'A'")
            .bind(alice)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(case_matches, 1);

    let (lower, upper) = meta::descendant_bounds("a").unwrap();
    let subtree: Vec<String> = sqlx::query_scalar(
        "SELECT rel_path FROM files WHERE owner_id = ?1 AND rel_path >= ?2 AND rel_path < ?3 \
         ORDER BY rel_path",
    )
    .bind(alice)
    .bind(&lower)
    .bind(&upper)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(subtree, ["a/%", "a/_", "a/b", "a/b/c"]);

    // The range scan is served by the (owner_id, rel_path) index.
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN SELECT rel_path FROM files \
         WHERE owner_id = ?1 AND rel_path >= ?2 AND rel_path < ?3",
    )
    .bind(alice)
    .bind(&lower)
    .bind(&upper)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        plan.iter()
            .any(|(_, _, _, detail)| detail.contains("USING COVERING INDEX")
                || detail.contains("USING INDEX")),
        "{plan:?}"
    );
}

#[tokio::test]
async fn initial_admin_is_created_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let pool = fresh_database(dir.path()).await;

    let username = Username::new("admin").unwrap();
    let phc = password::hash(&SecretString::from("correct horse".to_owned())).unwrap();
    users::create_initial_admin(&pool, &username, "Admin", &phc)
        .await
        .expect("first admin");

    let (is_admin, enabled, stored_hash): (bool, bool, String) =
        sqlx::query_as("SELECT is_admin, enabled, password_hash FROM users WHERE username = ?1")
            .bind("admin")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_admin && enabled);
    assert_eq!(stored_hash, phc);

    let other = Username::new("mallory").unwrap();
    let err = users::create_initial_admin(&pool, &other, "Mallory", &phc)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AlreadyInitialized), "{err:?}");
    assert_eq!(users::count(&pool).await.unwrap(), 1);
}
