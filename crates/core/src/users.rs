//! User account storage.
//!
//! Every write is one `BEGIN IMMEDIATE` transaction. Creating an account also creates its
//! storage directories (see [`crate::storage`]); the directories are created before the
//! transaction commits, so a failure leaves neither a half-created account nor an orphaned
//! database row behind.

use sqlx::FromRow;

use crate::{
    db::{self, Pool},
    error::{Error, Result},
    types::Username,
};

/// Maximum length of a display name, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 255;

/// Validates a display name, defaulting to the username when none is given.
pub fn display_name_or_default(display_name: Option<&str>, username: &Username) -> Result<String> {
    let Some(display_name) = display_name else {
        return Ok(username.as_str().to_owned());
    };
    let display_name = display_name.trim();
    if display_name.is_empty() {
        return Err(Error::InvalidDisplayName("must not be empty"));
    }
    if display_name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(Error::InvalidDisplayName(
            "must be at most 255 characters long",
        ));
    }
    if display_name.chars().any(char::is_control) {
        return Err(Error::InvalidDisplayName(
            "must not contain control characters",
        ));
    }
    Ok(display_name.to_owned())
}

/// A user account as stored, without its password hash.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct User {
    /// Numeric id; also names the user's storage directories.
    pub id: i64,
    /// Login name.
    #[sqlx(try_from = "String")]
    pub username: Username,
    /// Name shown in clients.
    pub display_name: String,
    /// Whether the account may sign in.
    pub enabled: bool,
    /// Whether the account may use the web admin UI.
    pub is_admin: bool,
    /// Creation time, UNIX seconds.
    pub created_at: i64,
    /// Last change, UNIX seconds.
    pub updated_at: i64,
}

impl TryFrom<String> for Username {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

/// Input of [`create`].
#[derive(Debug, Clone)]
pub struct NewUser<'a> {
    /// Login name.
    pub username: &'a Username,
    /// Validated display name (see [`display_name_or_default`]).
    pub display_name: &'a str,
    /// Argon2id PHC string of the web login password.
    pub password_hash: &'a str,
    /// Grant access to the web admin UI.
    pub is_admin: bool,
}

const USER_COLUMNS: &str = "id, username, display_name, enabled, is_admin, created_at, updated_at";

/// Returns the number of user accounts.
pub async fn count(pool: &Pool) -> Result<i64> {
    let count = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Creates the first account of a fresh installation as an enabled admin.
///
/// `password_hash` is the PHC string from [`crate::password::hash`]. Fails with
/// [`Error::AlreadyInitialized`] if any account exists, so running `init` twice cannot create a
/// second admin behind the operator's back. The check and the insert share one
/// `BEGIN IMMEDIATE` transaction.
pub async fn create_initial_admin(
    pool: &Pool,
    username: &Username,
    display_name: &str,
    password_hash: &str,
) -> Result<i64> {
    let mut tx = db::begin_immediate(pool).await?;

    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;
    if existing > 0 {
        return Err(Error::AlreadyInitialized);
    }

    let id = insert(
        &mut tx,
        &NewUser {
            username,
            display_name,
            password_hash,
            is_admin: true,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Creates an enabled account and returns its id.
///
/// `prepare_storage` runs with the new id after the insert but before the commit; if it fails,
/// the account is not created. Use it to create the storage directories.
pub async fn create(
    pool: &Pool,
    user: &NewUser<'_>,
    prepare_storage: impl FnOnce(i64) -> Result<()>,
) -> Result<i64> {
    let mut tx = db::begin_immediate(pool).await?;
    let id = insert(&mut tx, user).await?;
    prepare_storage(id)?;
    tx.commit().await?;
    Ok(id)
}

async fn insert(tx: &mut db::Tx, user: &NewUser<'_>) -> Result<i64> {
    let now = db::unix_now();
    let result = sqlx::query(
        "INSERT INTO users (username, display_name, password_hash, enabled, is_admin, \
         created_at, updated_at) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?5)",
    )
    .bind(user.username.as_str())
    .bind(user.display_name)
    .bind(user.password_hash)
    .bind(user.is_admin)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|err| match err.as_database_error() {
        Some(db_err) if db_err.is_unique_violation() => Error::UserExists(user.username.clone()),
        _ => Error::Database(err),
    })?;
    Ok(result.last_insert_rowid())
}

/// Returns every account, ordered by username.
pub async fn list(pool: &Pool) -> Result<Vec<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users ORDER BY username");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await?)
}

/// Looks an account up by name.
pub async fn find(pool: &Pool, username: &Username) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1");
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(username.as_str())
        .fetch_optional(pool)
        .await?)
}

/// Like [`find`], but a missing account is [`Error::UserNotFound`].
pub async fn get(pool: &Pool, username: &Username) -> Result<User> {
    find(pool, username)
        .await?
        .ok_or_else(|| Error::UserNotFound(username.clone()))
}

/// Deletes an account. App passwords, sessions, file metadata and locks go with it through
/// `ON DELETE CASCADE`; the storage directories are left to the caller.
pub async fn delete(pool: &Pool, username: &Username) -> Result<User> {
    let mut tx = db::begin_immediate(pool).await?;
    let sql = format!("DELETE FROM users WHERE username = ?1 RETURNING {USER_COLUMNS}");
    let user: Option<User> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(username.as_str())
        .fetch_optional(&mut *tx)
        .await?;
    let user = user.ok_or_else(|| Error::UserNotFound(username.clone()))?;
    tx.commit().await?;
    Ok(user)
}

/// Replaces the web login password hash of an account.
pub async fn set_password_hash(
    pool: &Pool,
    username: &Username,
    password_hash: &str,
) -> Result<()> {
    update(
        pool,
        username,
        "password_hash = ?2",
        password_hash.to_owned().into(),
    )
    .await
}

/// Enables or disables an account. A disabled account cannot sign in with any credential.
pub async fn set_enabled(pool: &Pool, username: &Username, enabled: bool) -> Result<()> {
    update(pool, username, "enabled = ?2", enabled.into()).await
}

/// The values [`update`] can bind.
enum Value {
    Text(String),
    Bool(bool),
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

async fn update(pool: &Pool, username: &Username, assignment: &str, value: Value) -> Result<()> {
    let mut tx = db::begin_immediate(pool).await?;
    let sql = format!("UPDATE users SET {assignment}, updated_at = ?3 WHERE username = ?1");
    let query = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(username.as_str());
    let query = match value {
        Value::Text(text) => query.bind(text),
        Value::Bool(flag) => query.bind(flag),
    };
    let result = query.bind(db::unix_now()).execute(&mut *tx).await?;
    if result.rows_affected() == 0 {
        return Err(Error::UserNotFound(username.clone()));
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_defaults_to_username() {
        let username = Username::new("alice").unwrap();
        assert_eq!(display_name_or_default(None, &username).unwrap(), "alice");
        assert_eq!(
            display_name_or_default(Some("  Alice Example "), &username).unwrap(),
            "Alice Example"
        );
        assert!(display_name_or_default(Some("   "), &username).is_err());
        assert!(display_name_or_default(Some("a\u{7}b"), &username).is_err());
        assert!(display_name_or_default(Some(&"x".repeat(256)), &username).is_err());
    }
}
