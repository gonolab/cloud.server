//! Chunked upload sessions (`upload_sessions` table).
//!
//! A session is created by `MKCOL /remote.php/dav/uploads/<user>/<upload id>` and lives until
//! the final `MOVE` assembles it, the client deletes it, or it expires [`SESSION_TTL_SECS`]
//! after the last chunk arrived. The chunks themselves are files in the data directory (see
//! [`crate::storage::DataLayout::upload_session_dir`]); this table only records what the
//! protocol needs to check: the destination and the announced total length.
//!
//! Expired sessions are invisible to every lookup here and removed by a background task
//! ([`purge_expired`]), never by the requests themselves.

use sqlx::FromRow;

use crate::{
    db::{self, Pool},
    error::Result,
    path::RelPath,
};

/// Lifetime of an upload session after its last activity, in seconds (24 hours, like
/// Nextcloud's cleanup of abandoned uploads).
pub const SESSION_TTL_SECS: i64 = 24 * 60 * 60;

/// One upload session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadSession {
    /// Owner of the session and of its destination.
    pub owner_id: i64,
    /// Name chosen by the client.
    pub upload_id: String,
    /// Destination (storage path), when the client named it at creation.
    pub target: Option<RelPath>,
    /// `OC-Total-Length` announced at creation.
    pub total_size: Option<u64>,
    /// Creation time, UNIX seconds.
    pub created_at: i64,
    /// Last activity, UNIX seconds.
    pub updated_at: i64,
    /// Expiry, UNIX seconds.
    pub expires_at: i64,
}

#[derive(FromRow)]
struct Row {
    owner_id: i64,
    upload_id: String,
    target_path: Option<String>,
    total_size: Option<i64>,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
}

impl From<Row> for UploadSession {
    fn from(row: Row) -> Self {
        Self {
            owner_id: row.owner_id,
            upload_id: row.upload_id,
            target: row.target_path.map(RelPath::from_db),
            total_size: row.total_size.and_then(|size| u64::try_from(size).ok()),
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
        }
    }
}

const COLUMNS: &str =
    "owner_id, upload_id, target_path, total_size, created_at, updated_at, expires_at";

/// Creates a session. Returns `false` if a live session with this id exists already; an expired
/// one is replaced.
pub async fn create(
    pool: &Pool,
    owner: i64,
    upload_id: &str,
    target: Option<&RelPath>,
    total_size: Option<u64>,
    now: i64,
) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    sqlx::query(
        "DELETE FROM upload_sessions WHERE owner_id = ?1 AND upload_id = ?2 AND expires_at <= ?3",
    )
    .bind(owner)
    .bind(upload_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO upload_sessions (owner_id, upload_id, target_path, total_size, created_at, \
         updated_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6) ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(upload_id)
    .bind(target.map(RelPath::as_str))
    .bind(total_size.map(|size| i64::try_from(size).unwrap_or(i64::MAX)))
    .bind(now)
    .bind(now.saturating_add(SESSION_TTL_SECS))
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(inserted)
}

/// The live session `upload_id` of `owner`.
pub async fn get(
    pool: &Pool,
    owner: i64,
    upload_id: &str,
    now: i64,
) -> Result<Option<UploadSession>> {
    let sql = format!(
        "SELECT {COLUMNS} FROM upload_sessions WHERE owner_id = ?1 AND upload_id = ?2 \
         AND expires_at > ?3"
    );
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(owner)
        .bind(upload_id)
        .bind(now)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(UploadSession::from))
}

/// The live sessions of `owner`, ordered by id.
pub async fn list(pool: &Pool, owner: i64, now: i64) -> Result<Vec<UploadSession>> {
    let sql = format!(
        "SELECT {COLUMNS} FROM upload_sessions WHERE owner_id = ?1 AND expires_at > ?2 \
         ORDER BY upload_id"
    );
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(owner)
        .bind(now)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(UploadSession::from).collect())
}

/// Records activity on a live session, which extends its lifetime. Returns `false` if there is
/// no such session (any more).
pub async fn touch(pool: &Pool, owner: i64, upload_id: &str, now: i64) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let touched = sqlx::query(
        "UPDATE upload_sessions SET updated_at = ?3, expires_at = ?4 \
         WHERE owner_id = ?1 AND upload_id = ?2 AND expires_at > ?3",
    )
    .bind(owner)
    .bind(upload_id)
    .bind(now)
    .bind(now.saturating_add(SESSION_TTL_SECS))
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(touched)
}

/// Deletes a session (live or expired). Returns `false` if there was none.
pub async fn delete(pool: &Pool, owner: i64, upload_id: &str) -> Result<bool> {
    let mut tx = db::begin_immediate(pool).await?;
    let deleted = sqlx::query("DELETE FROM upload_sessions WHERE owner_id = ?1 AND upload_id = ?2")
        .bind(owner)
        .bind(upload_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(deleted)
}

/// Deletes every session that expired at `now` and returns their `(owner, upload id)` pairs,
/// so that the caller can remove their chunks.
pub async fn purge_expired(pool: &Pool, now: i64) -> Result<Vec<(i64, String)>> {
    let mut tx = db::begin_immediate(pool).await?;
    let purged: Vec<(i64, String)> = sqlx::query_as(
        "DELETE FROM upload_sessions WHERE expires_at <= ?1 RETURNING owner_id, upload_id",
    )
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(purged)
}

/// Every session, live or not, as `(owner, upload id)` pairs (to find chunk directories that no
/// session owns).
pub async fn all_ids(pool: &Pool) -> Result<Vec<(i64, String)>> {
    Ok(
        sqlx::query_as("SELECT owner_id, upload_id FROM upload_sessions")
            .fetch_all(pool)
            .await?,
    )
}
