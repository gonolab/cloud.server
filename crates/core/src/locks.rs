//! Persistent WebDAV locks (`locks` table).
//!
//! Locks are keyed by owner and storage path, so a file reached through two different mounts
//! is one lockable resource. Every lock has an absolute expiry; expired rows are ignored by
//! every query and purged whenever a lock is taken. The conflict rules follow RFC 4918 (and
//! dav-server's in-memory lock system): a lock covers its own path and, when `deep`, every
//! descendant; exclusive locks conflict with everything, shared locks only with exclusive ones.

use sqlx::FromRow;

use crate::{
    db::{self, Pool, Tx},
    error::Result,
    meta::descendant_bounds,
    path::RelPath,
};

/// One lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    /// `opaquelocktoken:` URI.
    pub token: String,
    /// Owner of the locked storage.
    pub owner_id: i64,
    /// Locked storage path.
    pub rel_path: RelPath,
    /// Principal (username) that took the lock.
    pub principal: Option<String>,
    /// The client's `<D:owner>` element, serialized.
    pub owner_xml: Option<Vec<u8>>,
    /// Shared or exclusive.
    pub shared: bool,
    /// Depth infinity.
    pub deep: bool,
    /// Creation time, UNIX seconds.
    pub created_at: i64,
    /// Expiry, UNIX seconds.
    pub timeout_at: i64,
}

#[derive(FromRow)]
struct Row {
    token: String,
    owner_id: i64,
    rel_path: String,
    principal: Option<String>,
    owner_xml: Option<Vec<u8>>,
    shared: bool,
    deep: bool,
    created_at: i64,
    timeout_at: i64,
}

impl From<Row> for Lock {
    fn from(row: Row) -> Self {
        Self {
            token: row.token,
            owner_id: row.owner_id,
            rel_path: RelPath::from_db(row.rel_path),
            principal: row.principal,
            owner_xml: row.owner_xml,
            shared: row.shared,
            deep: row.deep,
            created_at: row.created_at,
            timeout_at: row.timeout_at,
        }
    }
}

const COLUMNS: &str =
    "token, owner_id, rel_path, principal, owner_xml, shared, deep, created_at, timeout_at";

/// Lock storage. Cheap to clone.
#[derive(Debug, Clone)]
pub struct LockStore {
    pool: Pool,
}

impl LockStore {
    /// Wraps a connection pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Takes `lock` unless a conflicting lock exists; returns the conflicting lock otherwise.
    ///
    /// The check and the insert share one `BEGIN IMMEDIATE` transaction, which also purges
    /// expired locks.
    pub async fn try_lock(&self, lock: Lock, now: i64) -> Result<std::result::Result<Lock, Lock>> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        sqlx::query("DELETE FROM locks WHERE timeout_at <= ?1")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let mut existing = covering(&mut tx, lock.owner_id, &lock.rel_path, now).await?;
        if lock.deep {
            existing.extend(below(&mut tx, lock.owner_id, &lock.rel_path, now).await?);
        }
        if let Some(conflict) = existing
            .into_iter()
            .find(|other| !other.shared || !lock.shared)
        {
            return Ok(Err(conflict));
        }
        sqlx::query(
            "INSERT INTO locks (token, owner_id, rel_path, principal, owner_xml, shared, deep, \
             created_at, timeout_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&lock.token)
        .bind(lock.owner_id)
        .bind(lock.rel_path.as_str())
        .bind(&lock.principal)
        .bind(&lock.owner_xml)
        .bind(lock.shared)
        .bind(lock.deep)
        .bind(lock.created_at)
        .bind(lock.timeout_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Ok(lock))
    }

    /// Live locks that apply to `rel`: locks on `rel` itself and deep locks on its ancestors.
    pub async fn covering(&self, owner: i64, rel: &RelPath, now: i64) -> Result<Vec<Lock>> {
        let mut conn = self.pool.acquire().await?;
        covering_on(&mut conn, owner, rel, now).await
    }

    /// Live locks strictly below `rel`.
    pub async fn below(&self, owner: i64, rel: &RelPath, now: i64) -> Result<Vec<Lock>> {
        let mut conn = self.pool.acquire().await?;
        below_on(&mut conn, owner, rel, now).await
    }

    /// The live lock with `token` on `rel` or one of its ancestors (any depth).
    pub async fn find(
        &self,
        owner: i64,
        rel: &RelPath,
        token: &str,
        now: i64,
    ) -> Result<Option<Lock>> {
        let mut paths = rel.ancestors();
        paths.push(rel.clone());
        let placeholders = vec!["?"; paths.len()].join(", ");
        let sql = format!(
            "SELECT {COLUMNS} FROM locks WHERE token = ? AND owner_id = ? AND timeout_at > ? \
             AND rel_path IN ({placeholders})"
        );
        let mut query = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql))
            .bind(token)
            .bind(owner)
            .bind(now);
        for path in &paths {
            query = query.bind(path.as_str());
        }
        Ok(query.fetch_optional(&self.pool).await?.map(Lock::from))
    }

    /// Releases a lock.
    pub async fn remove(&self, token: &str) -> Result<bool> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        let result = sqlx::query("DELETE FROM locks WHERE token = ?1")
            .bind(token)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Moves the expiry of a lock.
    pub async fn refresh(&self, token: &str, timeout_at: i64) -> Result<()> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        sqlx::query("UPDATE locks SET timeout_at = ?2 WHERE token = ?1")
            .bind(token)
            .bind(timeout_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Removes every lock on `rel` and below (after DELETE or MOVE).
    pub async fn remove_subtree(&self, owner: i64, rel: &RelPath) -> Result<()> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        match descendant_bounds(rel.as_str()) {
            Some((lower, upper)) => {
                sqlx::query(
                    "DELETE FROM locks WHERE owner_id = ?1 \
                     AND (rel_path = ?2 OR (rel_path >= ?3 AND rel_path < ?4))",
                )
                .bind(owner)
                .bind(rel.as_str())
                .bind(lower)
                .bind(upper)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM locks WHERE owner_id = ?1")
                    .bind(owner)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Deletes expired locks. Returns how many were removed.
    pub async fn purge_expired(&self, now: i64) -> Result<u64> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        let result = sqlx::query("DELETE FROM locks WHERE timeout_at <= ?1")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }
}

async fn covering(tx: &mut Tx, owner: i64, rel: &RelPath, now: i64) -> Result<Vec<Lock>> {
    covering_on(tx, owner, rel, now).await
}

async fn below(tx: &mut Tx, owner: i64, rel: &RelPath, now: i64) -> Result<Vec<Lock>> {
    below_on(tx, owner, rel, now).await
}

async fn covering_on(
    conn: &mut sqlx::SqliteConnection,
    owner: i64,
    rel: &RelPath,
    now: i64,
) -> Result<Vec<Lock>> {
    let ancestors = rel.ancestors();
    let placeholders = vec!["?"; ancestors.len().max(1)].join(", ");
    let sql = format!(
        "SELECT {COLUMNS} FROM locks WHERE owner_id = ? AND timeout_at > ? \
         AND (rel_path = ? OR (deep = 1 AND rel_path IN ({placeholders}))) ORDER BY rel_path"
    );
    let mut query = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql))
        .bind(owner)
        .bind(now)
        .bind(rel.as_str());
    if ancestors.is_empty() {
        // `IN (?)` with a value that is never an ancestor of the root.
        query = query.bind(rel.as_str());
    }
    for ancestor in &ancestors {
        query = query.bind(ancestor.as_str());
    }
    Ok(query
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(Lock::from)
        .collect())
}

async fn below_on(
    conn: &mut sqlx::SqliteConnection,
    owner: i64,
    rel: &RelPath,
    now: i64,
) -> Result<Vec<Lock>> {
    let rows: Vec<Row> = match descendant_bounds(rel.as_str()) {
        Some((lower, upper)) => {
            let sql = format!(
                "SELECT {COLUMNS} FROM locks WHERE owner_id = ?1 AND timeout_at > ?2 \
                 AND rel_path >= ?3 AND rel_path < ?4"
            );
            sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .bind(now)
                .bind(lower)
                .bind(upper)
                .fetch_all(&mut *conn)
                .await?
        }
        None => {
            let sql = format!(
                "SELECT {COLUMNS} FROM locks WHERE owner_id = ?1 AND timeout_at > ?2 \
                 AND rel_path <> ''"
            );
            sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .bind(now)
                .fetch_all(&mut *conn)
                .await?
        }
    };
    Ok(rows.into_iter().map(Lock::from).collect())
}
