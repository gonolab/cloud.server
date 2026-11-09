//! Counts shown on the web admin UI.
//!
//! Read-only aggregate queries over the account and metadata tables. Every query uses an
//! index or touches one row per user; none scans the `files` table.

use std::collections::HashMap;

use crate::{db::Pool, error::Result};

/// Server-wide counts at a point in time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overview {
    /// User accounts.
    pub users: i64,
    /// Enabled admin accounts.
    pub admins: i64,
    /// Disabled accounts.
    pub disabled: i64,
    /// App passwords (including expired ones that were not revoked).
    pub app_passwords: i64,
    /// App passwords used in the last 24 hours.
    pub app_passwords_used_today: i64,
    /// Browser sessions that have not expired.
    pub web_sessions: i64,
    /// Login Flow v2 sign-ins waiting for the user or the device.
    pub pending_login_flows: i64,
    /// Chunked uploads that have not expired.
    pub uploads: i64,
    /// WebDAV locks that have not expired.
    pub locks: i64,
    /// Bytes stored in all users' files (the recursive size of every root).
    pub storage_used: u64,
}

/// Counts of one user.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserCounts {
    /// App passwords of the user.
    pub app_passwords: i64,
    /// Bytes stored in the user's files.
    pub storage_used: u64,
}

fn size(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// The server-wide counts at `now` (UNIX seconds).
pub async fn overview(pool: &Pool, now: i64) -> Result<Overview> {
    let (users, admins, disabled): (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(is_admin = 1 AND enabled = 1), 0), \
         COALESCE(SUM(enabled = 0), 0) FROM users",
    )
    .fetch_one(pool)
    .await?;
    let (app_passwords, app_passwords_used_today): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(last_used_at >= ?1), 0) FROM app_passwords")
            .bind(now - 24 * 3600)
            .fetch_one(pool)
            .await?;
    let count = |sql: &'static str| async move {
        sqlx::query_scalar::<_, i64>(sql)
            .bind(now)
            .fetch_one(pool)
            .await
    };
    let web_sessions = count("SELECT COUNT(*) FROM web_sessions WHERE expires_at > ?1").await?;
    let pending_login_flows =
        count("SELECT COUNT(*) FROM login_flows WHERE expires_at > ?1").await?;
    let uploads = count("SELECT COUNT(*) FROM upload_sessions WHERE expires_at > ?1").await?;
    let locks = count("SELECT COUNT(*) FROM locks WHERE timeout_at > ?1").await?;
    let storage_used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(f.size), 0) FROM users u \
         JOIN files f ON f.owner_id = u.id AND f.rel_path = ''",
    )
    .fetch_one(pool)
    .await?;
    Ok(Overview {
        users,
        admins,
        disabled,
        app_passwords,
        app_passwords_used_today,
        web_sessions,
        pending_login_flows,
        uploads,
        locks,
        storage_used: size(storage_used),
    })
}

/// The counts of every user, by user id.
pub async fn per_user(pool: &Pool) -> Result<HashMap<i64, UserCounts>> {
    let rows: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT u.id, \
         (SELECT COUNT(*) FROM app_passwords a WHERE a.user_id = u.id), \
         COALESCE((SELECT f.size FROM files f WHERE f.owner_id = u.id AND f.rel_path = ''), 0) \
         FROM users u",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, app_passwords, used)| {
            (
                id,
                UserCounts {
                    app_passwords,
                    storage_used: size(used),
                },
            )
        })
        .collect())
}
