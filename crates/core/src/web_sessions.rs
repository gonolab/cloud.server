//! Browser sessions (`web_sessions` table).
//!
//! A session is created only by signing in with the web login password on one of the server's
//! HTML pages (Login Flow v2 now, the web admin UI later); app passwords never create one. The
//! browser holds a random token in a cookie and the table holds its SHA-256 digest.
//!
//! - A session ends [`IDLE_TIMEOUT_SECS`] after its last use and at the latest
//!   [`MAX_LIFETIME_SECS`] after it was created. Use extends it, at most once per
//!   [`SEEN_GRANULARITY_SECS`] so that page views do not all write to the database.
//! - A session of a disabled account is not accepted.
//! - Expired sessions are invisible to [`lookup`] and removed by a background task
//!   ([`purge_expired`]).

use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;

use crate::{
    db::{self, Pool},
    error::Result,
    secret,
    types::Username,
};

/// A session ends this long after its last use.
pub const IDLE_TIMEOUT_SECS: i64 = 30 * 60;

/// A session ends this long after it was created, however much it is used.
pub const MAX_LIFETIME_SECS: i64 = 12 * 60 * 60;

/// `last_seen_at` is written at most this often per session.
pub const SEEN_GRANULARITY_SECS: i64 = 60;

/// Length of the cookie token (about 256 bits).
const TOKEN_CHARS: usize = 43;

/// The account a live session belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    /// Row id of the session.
    pub session_id: i64,
    /// The signed-in account.
    pub user_id: i64,
    /// Its login name.
    pub username: Username,
    /// Its display name.
    pub display_name: String,
    /// Whether it may use the web admin UI.
    pub is_admin: bool,
}

/// Creates a session for `user_id` and returns the cookie token. The token is returned once;
/// only its digest is stored.
pub async fn create(pool: &Pool, user_id: i64, now: i64) -> Result<SecretString> {
    let token = secret::random_token(TOKEN_CHARS);
    let digest = secret::digest(token.expose_secret());
    let mut tx = db::begin_immediate(pool).await?;
    sqlx::query(
        "INSERT INTO web_sessions (token_hash, user_id, created_at, last_seen_at, expires_at) \
         VALUES (?1, ?2, ?3, ?3, ?4)",
    )
    .bind(&digest[..])
    .bind(user_id)
    .bind(now)
    .bind(now.saturating_add(IDLE_TIMEOUT_SECS.min(MAX_LIFETIME_SECS)))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(token)
}

#[derive(FromRow)]
struct Row {
    id: i64,
    created_at: i64,
    last_seen_at: i64,
    expires_at: i64,
    user_id: i64,
    username: String,
    display_name: String,
    is_admin: bool,
    enabled: bool,
}

/// The account of the live session with cookie token `token`, extending the session.
pub async fn lookup(pool: &Pool, token: &str, now: i64) -> Result<Option<SessionUser>> {
    let digest = secret::digest(token);
    let row: Option<Row> = sqlx::query_as(
        "SELECT s.id, s.created_at, s.last_seen_at, s.expires_at, u.id AS user_id, u.username, \
         u.display_name, u.is_admin, u.enabled FROM web_sessions s \
         JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1",
    )
    .bind(&digest[..])
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    if row.expires_at <= now || !row.enabled {
        return Ok(None);
    }
    if now - row.last_seen_at >= SEEN_GRANULARITY_SECS {
        let expires_at = now
            .saturating_add(IDLE_TIMEOUT_SECS)
            .min(row.created_at.saturating_add(MAX_LIFETIME_SECS));
        let mut tx = db::begin_immediate(pool).await?;
        sqlx::query("UPDATE web_sessions SET last_seen_at = ?2, expires_at = ?3 WHERE id = ?1")
            .bind(row.id)
            .bind(now)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(Some(SessionUser {
        session_id: row.id,
        user_id: row.user_id,
        username: Username::new(row.username)?,
        display_name: row.display_name,
        is_admin: row.is_admin,
    }))
}

/// Ends the session with cookie token `token`. Returns `false` if there was none.
pub async fn delete(pool: &Pool, token: &str) -> Result<bool> {
    let digest = secret::digest(token);
    let mut tx = db::begin_immediate(pool).await?;
    let deleted = sqlx::query("DELETE FROM web_sessions WHERE token_hash = ?1")
        .bind(&digest[..])
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(deleted)
}

/// Ends every session of `user_id` except `keep` (the session of the request that asked for
/// it, if any). Used when a password changes or an account is disabled. Returns how many
/// sessions ended.
pub async fn delete_for_user(pool: &Pool, user_id: i64, keep: Option<i64>) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let deleted = sqlx::query("DELETE FROM web_sessions WHERE user_id = ?1 AND id IS NOT ?2")
        .bind(user_id)
        .bind(keep)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(deleted)
}

/// Removes every session that expired at `now`. Returns how many there were.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query("DELETE FROM web_sessions WHERE expires_at <= ?1")
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(purged)
}
