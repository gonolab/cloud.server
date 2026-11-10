//! Direct download links (`direct_downloads` table).
//!
//! The Nextcloud apps play video and audio that is not downloaded yet by handing a URL to the
//! system media player, which sends no credentials. They ask for that URL with
//! `POST /ocs/v2.php/apps/dav/api/v1/direct` and get `<base_url>/remote.php/direct/<token>`.
//!
//! - A link names one file by id, so it keeps working when the file is renamed or moved and
//!   serves the current content after an overwrite. Deleting the file removes it.
//! - A link acts with the app password that created it, with that password's mounts.
//!   Revoking the app password removes its links; a link of an expired app password or of a
//!   disabled account is not accepted ([`crate::app_passwords::device`]).
//! - Links expire after [`DEFAULT_LIFETIME_SECS`] (8 hours, as on Nextcloud) or the lifetime
//!   the client asked for, at most [`MAX_LIFETIME_SECS`]. Expired links are invisible to
//!   [`lookup`] and removed by a background task ([`purge_expired`]).
//! - The token is random (about 380 bits) and only its SHA-256 digest is stored.

use secrecy::{ExposeSecret as _, SecretString};

use crate::{
    db::{self, Pool},
    error::Result,
    secret,
};

/// Lifetime of a link when the client does not ask for one.
pub const DEFAULT_LIFETIME_SECS: i64 = 8 * 60 * 60;

/// Longest lifetime a client may ask for (Nextcloud's limit).
pub const MAX_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// Length of the token in the URL (Nextcloud uses 60 characters of the same alphabet).
const TOKEN_CHARS: usize = 64;

/// What a live link points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectDownload {
    /// The app password the link acts with.
    pub app_password_id: i64,
    /// The file it serves.
    pub file_id: i64,
}

/// Creates a link to `file_id` acting with `app_password_id`, valid for `lifetime_secs`, and
/// returns its token. The token is returned once; only its digest is stored.
pub async fn create(
    pool: &Pool,
    app_password_id: i64,
    file_id: i64,
    now: i64,
    lifetime_secs: i64,
) -> Result<SecretString> {
    let token = secret::random_token(TOKEN_CHARS);
    let digest = secret::digest(token.expose_secret());
    let mut tx = db::begin_immediate(pool).await?;
    sqlx::query(
        "INSERT INTO direct_downloads (token_hash, app_password_id, file_id, created_at, \
         expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(&digest[..])
    .bind(app_password_id)
    .bind(file_id)
    .bind(now)
    .bind(now.saturating_add(lifetime_secs))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(token)
}

/// The live link with token `token`, if there is one at `now`.
pub async fn lookup(pool: &Pool, token: &str, now: i64) -> Result<Option<DirectDownload>> {
    let digest = secret::digest(token);
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT app_password_id, file_id FROM direct_downloads \
         WHERE token_hash = ?1 AND expires_at > ?2",
    )
    .bind(&digest[..])
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(app_password_id, file_id)| DirectDownload {
        app_password_id,
        file_id,
    }))
}

/// Removes every link that expired at `now`. Returns how many there were.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<u64> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged = sqlx::query("DELETE FROM direct_downloads WHERE expires_at <= ?1")
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(purged)
}
