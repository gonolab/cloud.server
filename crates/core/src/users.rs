//! User account storage.
//!
//! Only what `init` needs exists so far; the remaining account management (`user add`, `list`,
//! `delete`, `set-password`, `enable`, `disable`) is added together with its CLI commands.

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

    let now = db::unix_now();
    let result = sqlx::query(
        "INSERT INTO users (username, display_name, password_hash, enabled, is_admin, \
         created_at, updated_at) VALUES (?1, ?2, ?3, 1, 1, ?4, ?4)",
    )
    .bind(username.as_str())
    .bind(display_name)
    .bind(password_hash)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|err| match err.as_database_error() {
        Some(db_err) if db_err.is_unique_violation() => Error::UserExists(username.clone()),
        _ => Error::Database(err),
    })?;

    tx.commit().await?;
    Ok(result.last_insert_rowid())
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
