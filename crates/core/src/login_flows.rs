//! Pending Login Flow v2 sign-ins (`login_flows` table).
//!
//! 1. [`create`]: a client starts a flow and receives two random tokens, one to poll with and
//!    one embedded in the login URL it opens in the browser. Only their digests are stored.
//! 2. [`find`] / [`grant`] / [`deny`]: the browser pages look the flow up by the login token;
//!    after the user signed in with the web login password and approved the device on the
//!    consent page, the flow is marked as granted to that user.
//! 3. [`complete`]: the client's next poll consumes the granted flow and mints a new app
//!    password (full access, labeled with the client's name) in the same transaction, and
//!    returns it exactly once. The plaintext is never stored.
//!
//! Flows expire [`FLOW_TTL_SECS`] after they were started, are single-use, and expired ones
//! are removed by a background task ([`purge_expired`]). At most [`MAX_PENDING_FLOWS`] live
//! flows exist at a time, so that anonymous clients cannot grow the table without bound.

use secrecy::{ExposeSecret as _, SecretString};
use sqlx::FromRow;

use crate::{
    app_passwords::{self, Scope},
    db::{self, Pool},
    error::Result,
    secret,
    types::Username,
};

/// Lifetime of a flow, in seconds (20 minutes, like Nextcloud).
pub const FLOW_TTL_SECS: i64 = 20 * 60;

/// Most live flows at a time.
pub const MAX_PENDING_FLOWS: i64 = 1000;

/// Length of the poll and login tokens (about 380 bits; Nextcloud uses 128 characters).
const TOKEN_CHARS: usize = 64;

/// Label of an app password whose client sent no usable name.
const FALLBACK_LABEL: &str = "Login Flow v2 device";

/// The tokens of a new flow, returned once.
#[derive(Debug)]
pub struct NewFlow {
    /// Token the client polls with.
    pub poll_token: SecretString,
    /// Token in the login URL.
    pub login_token: SecretString,
    /// Expiry, UNIX seconds.
    pub expires_at: i64,
}

/// A live flow, as the browser pages see it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Flow {
    /// Row id.
    pub id: i64,
    /// Name of the client that started the flow.
    pub client_name: String,
    /// The user who approved it, once approved.
    pub granted_user_id: Option<i64>,
    /// Expiry, UNIX seconds.
    pub expires_at: i64,
}

/// What a completed flow hands to the client.
#[derive(Debug)]
pub struct Credentials {
    /// Login name of the user who approved the device.
    pub username: Username,
    /// The newly minted app password.
    pub app_password: SecretString,
    /// Its id.
    pub app_password_id: i64,
    /// Its label.
    pub label: String,
}

/// Starts a flow for a client named `client_name`. Returns `None` when
/// [`MAX_PENDING_FLOWS`] live flows exist.
pub async fn create(pool: &Pool, client_name: &str, now: i64) -> Result<Option<NewFlow>> {
    let poll_token = secret::random_token(TOKEN_CHARS);
    let login_token = secret::random_token(TOKEN_CHARS);
    let expires_at = now.saturating_add(FLOW_TTL_SECS);
    let mut tx = db::begin_immediate(pool).await?;
    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM login_flows WHERE expires_at > ?1")
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
    if live >= MAX_PENDING_FLOWS {
        return Ok(None);
    }
    sqlx::query(
        "INSERT INTO login_flows (poll_token_hash, login_token_hash, client_name, created_at, \
         expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(&secret::digest(poll_token.expose_secret())[..])
    .bind(&secret::digest(login_token.expose_secret())[..])
    .bind(client_name)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(NewFlow {
        poll_token,
        login_token,
        expires_at,
    }))
}

/// The live flow whose login URL carries `login_token`.
pub async fn find(pool: &Pool, login_token: &str, now: i64) -> Result<Option<Flow>> {
    Ok(sqlx::query_as(
        "SELECT id, client_name, granted_user_id, expires_at FROM login_flows \
         WHERE login_token_hash = ?1 AND expires_at > ?2",
    )
    .bind(&secret::digest(login_token)[..])
    .bind(now)
    .fetch_optional(pool)
    .await?)
}

/// Records that `user_id` approved the live, not yet approved flow `id`. Returns `false` if
/// there is no such flow.
pub async fn grant(pool: &Pool, id: i64, user_id: i64, now: i64) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let granted = sqlx::query(
        "UPDATE login_flows SET granted_user_id = ?2 \
         WHERE id = ?1 AND granted_user_id IS NULL AND expires_at > ?3",
    )
    .bind(id)
    .bind(user_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(granted)
}

/// Ends the flow `id` without granting anything. Returns `false` if there was none.
pub async fn deny(pool: &Pool, id: i64) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let denied = sqlx::query("DELETE FROM login_flows WHERE id = ?1")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(denied)
}

/// Completes the approved flow polled with `poll_token`: deletes it and mints a new app
/// password for the approving user in the same transaction. Returns `None` while the flow is
/// pending, and for unknown, expired or already completed flows. A flow approved by an
/// account that was disabled since then is consumed without minting anything.
pub async fn complete(pool: &Pool, poll_token: &str, now: i64) -> Result<Option<Credentials>> {
    let mut tx = db::begin_immediate(pool).await?;
    let flow: Option<(String, i64)> = sqlx::query_as(
        "DELETE FROM login_flows WHERE poll_token_hash = ?1 AND granted_user_id IS NOT NULL \
         AND expires_at > ?2 RETURNING client_name, granted_user_id",
    )
    .bind(&secret::digest(poll_token)[..])
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((client_name, user_id)) = flow else {
        return Ok(None);
    };
    let user: Option<(String, bool)> =
        sqlx::query_as("SELECT username, enabled FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((username, true)) = user else {
        tx.commit().await?;
        return Ok(None);
    };
    let label =
        app_passwords::check_label(&client_name).unwrap_or_else(|_| FALLBACK_LABEL.to_owned());
    let app_password = app_passwords::generate_device_token();
    let app_password_id = app_passwords::insert(
        &mut tx,
        user_id,
        &label,
        &[Scope::full_access()],
        None,
        &app_password,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(Credentials {
        username: Username::new(username)?,
        app_password,
        app_password_id,
        label,
    }))
}

/// Removes every flow that expired at `now`. Returns how many there were.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query("DELETE FROM login_flows WHERE expires_at <= ?1")
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(purged)
}
