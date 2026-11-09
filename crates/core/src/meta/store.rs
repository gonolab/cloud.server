//! [`MetaStore`]: the single writer of file metadata.
//!
//! # Model
//!
//! The file system is authoritative for *what exists* and for file contents; the `files` table
//! holds what the file system cannot: stable numeric file ids (`oc:fileid`), ETags, recursive
//! folder sizes (`oc:size`), favorites and dead properties. The WebDAV layer performs a change
//! on disk first and then reports it here; each report is one `BEGIN IMMEDIATE` transaction
//! that updates the entry, its subtree, every ancestor collection and the change log together.
//!
//! # ETags
//!
//! - A **file** ETag is derived from the file id, the modification time and the size, plus a
//!   random nonce drawn at every write. The nonce matters: many file systems record mtimes
//!   with coarse granularity, so two writes of equal size in quick succession could otherwise
//!   produce the same ETag for different content.
//! - A **directory** ETag is a fresh random value whenever anything below it changes.
//! - Entries that appeared behind the server's back are adopted with
//!   [`derived_file_etag`] (no nonce), the same value the WebDAV layer reports for a file whose
//!   on-disk mtime or size no longer matches its row.
//!
//! # Paths
//!
//! All paths are [`RelPath`]s of one owner. Subtree operations select descendants with the
//! half-open range from [`super::descendant_bounds`], never with `LIKE`.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use rand::RngExt as _;
use sha2::{Digest, Sha256};
use sqlx::FromRow;

use super::{
    changes::{ChangeEvent, ChangeOperation, ChangeSink},
    descendant_bounds,
};
use crate::{
    db::{self, Pool, Tx},
    error::Result,
    path::RelPath,
};

/// Upper bound of bind parameters per statement in batched lookups.
const BATCH: usize = 400;

/// One row of the `files` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// File id, exposed as `oc:fileid`. Never reused.
    pub id: i64,
    /// Path inside the owner's tree.
    pub rel_path: RelPath,
    /// Directory or file.
    pub is_dir: bool,
    /// ETag without quotes.
    pub etag: String,
    /// Modification time recorded with the last write, UNIX nanoseconds.
    pub mtime_ns: i64,
    /// File size, or the total size of everything below a directory.
    pub size: u64,
    /// Favorite flag (`oc:favorite`).
    pub favorite: bool,
}

/// What the file system reports about an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskStat {
    /// Directory or regular file.
    pub is_dir: bool,
    /// Modification time, UNIX nanoseconds.
    pub mtime_ns: i64,
    /// Length in bytes (ignored for directories).
    pub size: u64,
}

impl DiskStat {
    /// What `lstat(2)` (or `stat(2)`) reported. Directories have size 0; modification times
    /// before the epoch count as 0.
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        let mtime_ns = meta.modified().map_or(0, |time| {
            time.duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| {
                    i64::try_from(since.as_nanos()).unwrap_or(i64::MAX)
                })
        });
        Self {
            is_dir: meta.is_dir(),
            mtime_ns,
            size: if meta.is_dir() { 0 } else { meta.len() },
        }
    }
}

/// What [`MetaStore::reconcile`] changed, or would change in a dry run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// New entries, top-most only (their contents are new as well).
    pub added: Vec<RelPath>,
    /// Number of rows created, including everything below `added`.
    pub added_rows: usize,
    /// Entries that no longer exist, top-most only.
    pub removed: Vec<RelPath>,
    /// Number of rows removed, including everything below `removed`.
    pub removed_rows: usize,
    /// Files whose size or modification time changed.
    pub modified: Vec<RelPath>,
    /// Existing directories whose recorded recursive size was wrong for other reasons than
    /// the changes above (drift).
    pub resized: usize,
}

impl Reconciled {
    /// Whether nothing had to change.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.modified.is_empty()
            && self.resized == 0
    }
}

/// One change of a PROPPATCH, applied in request order (a `remove` followed by a `set` of the
/// same property leaves it set, and the other way round).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropChange {
    /// Store (or replace) a property.
    Set(DeadProp),
    /// Delete a property by `(namespace, name)`.
    Remove(String, String),
}

/// A WebDAV dead property as stored by PROPPATCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadProp {
    /// Namespace URI; empty for properties without a namespace.
    pub namespace: String,
    /// Local name.
    pub name: String,
    /// The serialized property element.
    pub xml: Vec<u8>,
}

#[derive(FromRow)]
struct Row {
    id: i64,
    rel_path: String,
    is_dir: bool,
    etag: String,
    mtime_ns: i64,
    size: i64,
    favorite: bool,
}

impl From<Row> for FileRow {
    fn from(row: Row) -> Self {
        Self {
            id: row.id,
            rel_path: RelPath::from_db(row.rel_path),
            is_dir: row.is_dir,
            etag: row.etag,
            mtime_ns: row.mtime_ns,
            size: u64::try_from(row.size).unwrap_or(0),
            favorite: row.favorite,
        }
    }
}

const COLUMNS: &str = "id, rel_path, is_dir, etag, mtime_ns, size, favorite";

/// The ETag reported for a file whose metadata was not written by the server: a pure function
/// of the file id and what the file system reports.
pub fn derived_file_etag(id: i64, mtime_ns: i64, size: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gono-file-etag-v1\0");
    hasher.update(id.to_be_bytes());
    hasher.update(mtime_ns.to_be_bytes());
    hasher.update(size.to_be_bytes());
    hex20(&hasher.finalize())
}

/// The ETag of a file version written by the server (see the module documentation).
fn written_file_etag(id: i64, mtime_ns: i64, size: u64) -> String {
    let nonce: [u8; 16] = rand::rng().random();
    let mut hasher = Sha256::new();
    hasher.update(b"gono-file-etag-v1\x01");
    hasher.update(id.to_be_bytes());
    hasher.update(mtime_ns.to_be_bytes());
    hasher.update(size.to_be_bytes());
    hasher.update(nonce);
    hex20(&hasher.finalize())
}

/// A fresh directory ETag.
fn dir_etag() -> String {
    let random: [u8; 10] = rand::rng().random();
    hex20(&random)
}

/// The first 10 bytes as 20 lowercase hex digits.
fn hex20(bytes: &[u8]) -> String {
    bytes.iter().take(10).map(|b| format!("{b:02x}")).collect()
}

fn to_db_size(size: u64) -> i64 {
    i64::try_from(size).unwrap_or(i64::MAX)
}

/// File metadata store. Cheap to clone.
#[derive(Debug, Clone)]
pub struct MetaStore {
    pool: Pool,
    /// Receives the event of every committed change.
    sink: Option<Arc<dyn ChangeSink>>,
}

impl MetaStore {
    /// Wraps a connection pool. Changes are logged but not published anywhere.
    pub fn new(pool: Pool) -> Self {
        Self { pool, sink: None }
    }

    /// Publishes the event of every committed change to `sink` (see [`super::changes`]).
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn ChangeSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// The underlying pool.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Hands committed changes to the sink, in commit order.
    fn publish(&self, events: &[ChangeEvent]) {
        if let Some(sink) = &self.sink {
            for event in events {
                sink.publish(event);
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Change log
    // -----------------------------------------------------------------------------------------

    /// The id of the newest `change_log` row, or 0 when the log is empty.
    pub async fn latest_change_id(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM change_log")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Up to `limit` logged changes with an id greater than `after`, oldest first.
    pub async fn changes_since(&self, after: i64, limit: u32) -> Result<Vec<ChangeEvent>> {
        let rows: Vec<(i64, i64, i64, String, Option<String>, String)> = sqlx::query_as(
            "SELECT id, owner_id, file_id, rel_path, old_rel_path, operation FROM change_log \
             WHERE id > ?1 ORDER BY id LIMIT ?2",
        )
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut events = Vec::with_capacity(rows.len());
        for (id, owner_id, file_id, rel_path, old_rel_path, operation) in rows {
            let Ok(operation) = operation.parse() else {
                // The CHECK constraint makes this impossible; skip rather than fail the reader.
                continue;
            };
            events.push(ChangeEvent {
                id,
                owner_id,
                file_id,
                rel_path: RelPath::from_db(rel_path),
                old_rel_path: old_rel_path.map(RelPath::from_db),
                operation,
            });
        }
        Ok(events)
    }

    // -----------------------------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------------------------

    /// The row of one entry.
    pub async fn get(&self, owner: i64, rel: &RelPath) -> Result<Option<FileRow>> {
        let sql = format!("SELECT {COLUMNS} FROM files WHERE owner_id = ?1 AND rel_path = ?2");
        let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(owner)
            .bind(rel.as_str())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(FileRow::from))
    }

    /// The rows of several entries, keyed by path. Missing entries are simply absent.
    pub async fn get_many(
        &self,
        owner: i64,
        rels: &[RelPath],
    ) -> Result<HashMap<RelPath, FileRow>> {
        let mut found = HashMap::with_capacity(rels.len());
        for chunk in rels.chunks(BATCH) {
            let placeholders = vec!["?"; chunk.len()].join(", ");
            let sql = format!(
                "SELECT {COLUMNS} FROM files WHERE owner_id = ? AND rel_path IN ({placeholders})"
            );
            let mut query = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql)).bind(owner);
            for rel in chunk {
                query = query.bind(rel.as_str());
            }
            for row in query.fetch_all(&self.pool).await? {
                let row = FileRow::from(row);
                found.insert(row.rel_path.clone(), row);
            }
        }
        Ok(found)
    }

    /// Every row at `dir` or below it, ordered by path.
    pub async fn subtree(&self, owner: i64, dir: &RelPath) -> Result<Vec<FileRow>> {
        let rows: Vec<Row> = match descendant_bounds(dir.as_str()) {
            Some((lower, upper)) => {
                let sql = format!(
                    "SELECT {COLUMNS} FROM files WHERE owner_id = ?1 \
                     AND (rel_path = ?2 OR (rel_path >= ?3 AND rel_path < ?4)) ORDER BY rel_path"
                );
                sqlx::query_as(sqlx::AssertSqlSafe(sql))
                    .bind(owner)
                    .bind(dir.as_str())
                    .bind(lower)
                    .bind(upper)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                let sql =
                    format!("SELECT {COLUMNS} FROM files WHERE owner_id = ?1 ORDER BY rel_path");
                sqlx::query_as(sqlx::AssertSqlSafe(sql))
                    .bind(owner)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows.into_iter().map(FileRow::from).collect())
    }

    /// The favorites strictly below `dir` (and `dir` itself when `include_dir` is set), ordered
    /// by path. Served by the partial index `files_favorites`.
    pub async fn favorites(
        &self,
        owner: i64,
        dir: &RelPath,
        include_dir: bool,
    ) -> Result<Vec<FileRow>> {
        let rows: Vec<Row> = match descendant_bounds(dir.as_str()) {
            Some((lower, upper)) => {
                let sql = format!(
                    "SELECT {COLUMNS} FROM files WHERE owner_id = ?1 AND favorite = 1 \
                     AND ((rel_path >= ?2 AND rel_path < ?3) OR (?4 AND rel_path = ?5)) \
                     ORDER BY rel_path"
                );
                sqlx::query_as(sqlx::AssertSqlSafe(sql))
                    .bind(owner)
                    .bind(lower)
                    .bind(upper)
                    .bind(include_dir)
                    .bind(dir.as_str())
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                let sql = format!(
                    "SELECT {COLUMNS} FROM files WHERE owner_id = ?1 AND favorite = 1 \
                     AND (rel_path <> '' OR ?2) ORDER BY rel_path"
                );
                sqlx::query_as(sqlx::AssertSqlSafe(sql))
                    .bind(owner)
                    .bind(include_dir)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows.into_iter().map(FileRow::from).collect())
    }

    /// All dead properties of an entry.
    pub async fn dead_props(&self, file_id: i64) -> Result<Vec<DeadProp>> {
        let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
            "SELECT namespace, name, xml FROM dead_props WHERE file_id = ?1 \
             ORDER BY namespace, name",
        )
        .bind(file_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(namespace, name, xml)| DeadProp {
                namespace,
                name,
                xml,
            })
            .collect())
    }

    /// One dead property of an entry.
    pub async fn dead_prop(
        &self,
        file_id: i64,
        namespace: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        Ok(sqlx::query_scalar(
            "SELECT xml FROM dead_props WHERE file_id = ?1 AND namespace = ?2 AND name = ?3",
        )
        .bind(file_id)
        .bind(namespace)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?)
    }

    // -----------------------------------------------------------------------------------------
    // Adoption of entries the server did not create
    // -----------------------------------------------------------------------------------------

    /// Creates rows for entries that exist on disk but have no row yet, and returns the rows of
    /// all of them.
    ///
    /// This happens for the root of a new tree, after a crash between a file system change and
    /// its metadata update, and for changes made behind the server's back. Adoption is
    /// discovery, not a change: it neither bumps ancestor ETags nor writes the change log
    /// (that is `rescan`'s job). Existing rows are left untouched.
    pub async fn adopt(&self, owner: i64, entries: &[(RelPath, DiskStat)]) -> Result<Vec<FileRow>> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = db::begin_immediate(&self.pool).await?;
        let mut rows = Vec::with_capacity(entries.len());
        for (rel, stat) in entries {
            let row = match select(&mut tx, owner, rel).await? {
                Some(row) => row,
                None => insert(&mut tx, owner, rel, *stat, Etag::Derived).await?,
            };
            rows.push(row);
        }
        tx.commit().await?;
        Ok(rows)
    }

    // -----------------------------------------------------------------------------------------
    // Changes
    // -----------------------------------------------------------------------------------------

    /// Records that a file was written (created or overwritten) at `rel`.
    ///
    /// An existing file row keeps its id; otherwise a new id is allocated and stale rows at or
    /// below `rel` (for example a directory that was replaced out of band) are removed first,
    /// so that dead properties never survive a delete and re-create.
    pub async fn record_write(&self, owner: i64, rel: &RelPath, stat: DiskStat) -> Result<FileRow> {
        debug_assert!(!stat.is_dir);
        let mut tx = db::begin_immediate(&self.pool).await?;
        let existing = select(&mut tx, owner, rel).await?;
        let (row, delta, operation) = match existing {
            Some(old) if !old.is_dir => {
                let etag = written_file_etag(old.id, stat.mtime_ns, stat.size);
                sqlx::query("UPDATE files SET etag = ?2, mtime_ns = ?3, size = ?4 WHERE id = ?1")
                    .bind(old.id)
                    .bind(&etag)
                    .bind(stat.mtime_ns)
                    .bind(to_db_size(stat.size))
                    .execute(&mut *tx)
                    .await?;
                let delta = to_db_size(stat.size) - to_db_size(old.size);
                let row = FileRow {
                    etag,
                    mtime_ns: stat.mtime_ns,
                    size: stat.size,
                    ..old
                };
                (row, delta, ChangeOperation::Modify)
            }
            stale => {
                let removed = delete_subtree(&mut tx, owner, rel).await?;
                let stale_size = stale.map_or(removed, |row| to_db_size(row.size));
                let row = insert(&mut tx, owner, rel, stat, Etag::Written).await?;
                (
                    row,
                    to_db_size(stat.size) - stale_size,
                    ChangeOperation::Create,
                )
            }
        };
        propagate(&mut tx, owner, rel, delta).await?;
        let event = log_change(&mut tx, owner, row.id, rel, None, operation).await?;
        tx.commit().await?;
        self.publish(&[event]);
        Ok(row)
    }

    /// Records that a directory was created at `rel`.
    pub async fn record_mkdir(&self, owner: i64, rel: &RelPath, mtime_ns: i64) -> Result<FileRow> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        let stale = select(&mut tx, owner, rel).await?;
        let removed = delete_subtree(&mut tx, owner, rel).await?;
        let stale_size = stale.map_or(removed, |row| to_db_size(row.size));
        let stat = DiskStat {
            is_dir: true,
            mtime_ns,
            size: 0,
        };
        let row = insert(&mut tx, owner, rel, stat, Etag::Written).await?;
        propagate(&mut tx, owner, rel, -stale_size).await?;
        let event = log_change(&mut tx, owner, row.id, rel, None, ChangeOperation::Create).await?;
        tx.commit().await?;
        self.publish(&[event]);
        Ok(row)
    }

    /// Records that `rel` and everything below it were deleted. Returns the removed row of
    /// `rel` itself, if it had one.
    pub async fn record_delete(&self, owner: i64, rel: &RelPath) -> Result<Option<FileRow>> {
        assert!(!rel.is_root(), "the root cannot be deleted");
        let mut tx = db::begin_immediate(&self.pool).await?;
        let row = select(&mut tx, owner, rel).await?;
        let removed = delete_subtree(&mut tx, owner, rel).await?;
        let size = row.as_ref().map_or(removed, |row| to_db_size(row.size));
        propagate(&mut tx, owner, rel, -size).await?;
        let mut events = Vec::new();
        if let Some(row) = &row {
            events.push(
                log_change(&mut tx, owner, row.id, rel, None, ChangeOperation::Delete).await?,
            );
        }
        tx.commit().await?;
        self.publish(&events);
        Ok(row)
    }

    /// Records that `from` (with its subtree) was renamed to `to`, replacing whatever was at
    /// `to`. Ids, ETags of the moved entries, favorites and dead properties move along.
    ///
    /// `stat` describes the moved entry at its new location; it is used when `from` had no row
    /// (the entry is then adopted at `to` as if newly created).
    pub async fn record_move(
        &self,
        owner: i64,
        from: &RelPath,
        to: &RelPath,
        stat: DiskStat,
    ) -> Result<FileRow> {
        assert!(
            !from.is_root() && !to.is_root() && !to.starts_with(from) && !from.starts_with(to),
            "invalid move {from} -> {to}"
        );
        let mut tx = db::begin_immediate(&self.pool).await?;

        // Whatever was at the destination has been replaced.
        let replaced = select(&mut tx, owner, to).await?;
        let replaced_removed = delete_subtree(&mut tx, owner, to).await?;
        let replaced_size = replaced.map_or(replaced_removed, |row| to_db_size(row.size));
        propagate(&mut tx, owner, to, -replaced_size).await?;

        let (row, event) = match select(&mut tx, owner, from).await? {
            Some(source) => {
                sqlx::query("UPDATE files SET rel_path = ?3 WHERE owner_id = ?1 AND rel_path = ?2")
                    .bind(owner)
                    .bind(from.as_str())
                    .bind(to.as_str())
                    .execute(&mut *tx)
                    .await?;
                if let Some((lower, upper)) = descendant_bounds(from.as_str()) {
                    // `?4 || substr(rel_path, length(?2) + 1)` keeps the part below `from`,
                    // including its leading slash.
                    sqlx::query(
                        "UPDATE files SET rel_path = ?4 || substr(rel_path, length(?5) + 1) \
                         WHERE owner_id = ?1 AND rel_path >= ?2 AND rel_path < ?3",
                    )
                    .bind(owner)
                    .bind(lower)
                    .bind(upper)
                    .bind(to.as_str())
                    .bind(from.as_str())
                    .execute(&mut *tx)
                    .await?;
                }
                let size = to_db_size(source.size);
                propagate(&mut tx, owner, from, -size).await?;
                propagate(&mut tx, owner, to, size).await?;
                let event = log_change(
                    &mut tx,
                    owner,
                    source.id,
                    to,
                    Some(from),
                    ChangeOperation::Move,
                )
                .await?;
                let row = FileRow {
                    rel_path: to.clone(),
                    ..source
                };
                (row, event)
            }
            None => {
                let row = insert(&mut tx, owner, to, stat, Etag::Derived).await?;
                propagate(&mut tx, owner, from, 0).await?;
                propagate(&mut tx, owner, to, to_db_size(row.size)).await?;
                let event =
                    log_change(&mut tx, owner, row.id, to, None, ChangeOperation::Create).await?;
                (row, event)
            }
        };
        tx.commit().await?;
        self.publish(&[event]);
        Ok(row)
    }

    /// Records that the subtree at `from` was copied to `to`, replacing whatever was there.
    ///
    /// `entries` lists what the copy produced on disk, as paths relative to `to` (the root
    /// entry is [`RelPath::root`]), parents before children. Every copied entry gets a new
    /// id; dead properties are copied from the corresponding source entries, favorites are not.
    pub async fn record_copy(
        &self,
        owner: i64,
        from: &RelPath,
        to: &RelPath,
        entries: &[(RelPath, DiskStat)],
    ) -> Result<FileRow> {
        assert!(
            !to.is_root() && !to.starts_with(from),
            "invalid copy {from} -> {to}"
        );
        assert!(
            entries.first().is_some_and(|(rel, _)| rel.is_root()),
            "the copied entry itself must come first"
        );
        let mut tx = db::begin_immediate(&self.pool).await?;

        let replaced = select(&mut tx, owner, to).await?;
        let replaced_removed = delete_subtree(&mut tx, owner, to).await?;
        let replaced_size = replaced.map_or(replaced_removed, |row| to_db_size(row.size));

        // Source ids by path relative to `from` (a range query over the source subtree).
        let mut sources: HashMap<RelPath, i64> = HashMap::new();
        for source in select_subtree(&mut tx, owner, from).await? {
            if let Some(relative) = source.rel_path.strip_prefix(from) {
                sources.insert(relative, source.id);
            }
        }

        // Recursive directory sizes of the copy.
        let mut dir_sizes: HashMap<RelPath, u64> = HashMap::new();
        for (relative, stat) in entries.iter().filter(|(_, stat)| !stat.is_dir) {
            for ancestor in relative.ancestors() {
                *dir_sizes.entry(ancestor).or_default() += stat.size;
            }
        }

        let mut top = None;
        for (relative, stat) in entries {
            let mut stat = *stat;
            if stat.is_dir {
                stat.size = dir_sizes.get(relative).copied().unwrap_or(0);
            }
            let rel = to.join_path(relative);
            let row = insert(&mut tx, owner, &rel, stat, Etag::Written).await?;
            if let Some(source_id) = sources.get(relative) {
                sqlx::query(
                    "INSERT INTO dead_props (file_id, namespace, name, xml) \
                     SELECT ?1, namespace, name, xml FROM dead_props WHERE file_id = ?2",
                )
                .bind(row.id)
                .bind(source_id)
                .execute(&mut *tx)
                .await?;
            }
            top.get_or_insert(row);
        }
        let top = top.expect("entries is not empty");
        propagate(&mut tx, owner, to, to_db_size(top.size) - replaced_size).await?;
        let event = log_change(&mut tx, owner, top.id, to, None, ChangeOperation::Create).await?;
        tx.commit().await?;
        self.publish(&[event]);
        Ok(top)
    }

    /// Brings the rows of `scope` and everything below it in line with what is on disk (the
    /// core of `gono-cloud rescan`), in one transaction.
    ///
    /// - `ancestors` are the strict ancestors of `scope` as found on disk (from the root down);
    ///   missing rows are created for them silently, like [`MetaStore::adopt`].
    /// - `entries` are `scope` and everything below it on disk; empty when `scope` is gone.
    ///
    /// Rows without an entry (or of the wrong kind) are removed, entries without a row get
    /// one, and files whose size or modification time differ get the ETag the WebDAV layer
    /// already reports for them ([`derived_file_etag`]). Directory sizes inside `scope` are
    /// recomputed from the entries, the ancestors of `scope` are adjusted by the difference,
    /// and every directory above a change gets a new ETag. The change log records the top-most
    /// added and removed entries and every modified file, so clients and notify_push see the
    /// changes.
    ///
    /// With `dry_run`, the transaction is rolled back: the result says what would change.
    pub async fn reconcile(
        &self,
        owner: i64,
        scope: &RelPath,
        ancestors: &[(RelPath, DiskStat)],
        entries: &[(RelPath, DiskStat)],
        dry_run: bool,
    ) -> Result<Reconciled> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        let mut report = Reconciled::default();
        let mut events = Vec::new();

        // The root and the ancestors of the scope are adopted, never reported.
        let mut known: Vec<(RelPath, DiskStat)> = ancestors.to_vec();
        if scope.is_root()
            && let Some(root) = entries.iter().find(|(rel, _)| rel.is_root())
        {
            known.push(root.clone());
        }
        // Adopted rows start with size 0; correcting that is not drift.
        let mut adopted: HashSet<RelPath> = HashSet::new();
        for (rel, stat) in &known {
            if select(&mut tx, owner, rel).await?.is_none() {
                insert(&mut tx, owner, rel, *stat, Etag::Derived).await?;
                adopted.insert(rel.clone());
            }
        }

        let rows: HashMap<RelPath, FileRow> = select_subtree(&mut tx, owner, scope)
            .await?
            .into_iter()
            .map(|row| (row.rel_path.clone(), row))
            .collect();
        let disk: HashMap<&RelPath, DiskStat> =
            entries.iter().map(|(rel, stat)| (rel, *stat)).collect();
        let old_scope_size = rows.get(scope).map_or(0, |row| to_db_size(row.size));

        // Paths whose ancestors need a new ETag.
        let mut changed: Vec<RelPath> = Vec::new();

        // 1. Rows without a matching entry.
        let stale: BTreeSet<RelPath> = rows
            .values()
            .filter(|row| {
                disk.get(&row.rel_path)
                    .is_none_or(|stat| stat.is_dir != row.is_dir)
            })
            .map(|row| row.rel_path.clone())
            .collect();
        report.removed_rows = stale.len();
        for rel in &stale {
            let below_stale = rel.parent().is_some_and(|parent| stale.contains(&parent));
            if below_stale || rel.is_root() {
                continue;
            }
            delete_subtree(&mut tx, owner, rel).await?;
            let id = rows[rel].id;
            events.push(log_change(&mut tx, owner, id, rel, None, ChangeOperation::Delete).await?);
            report.removed.push(rel.clone());
            changed.push(rel.clone());
        }

        // 2. Entries without a row (including those whose row was of the wrong kind).
        let mut current: HashMap<RelPath, FileRow> = rows
            .into_iter()
            .filter(|(rel, _)| !stale.contains(rel))
            .collect();
        // `entries` lists parents before children, so a new entry's parent is new exactly when
        // it was inserted earlier in this loop.
        let mut new_paths: HashSet<RelPath> = HashSet::new();
        for (rel, stat) in entries {
            if current.contains_key(rel) || known.iter().any(|(known, _)| known == rel) {
                continue;
            }
            let row = insert(&mut tx, owner, rel, *stat, Etag::Derived).await?;
            report.added_rows += 1;
            let parent_is_new = rel
                .parent()
                .is_some_and(|parent| new_paths.contains(&parent));
            if !parent_is_new || rel == scope {
                events.push(
                    log_change(&mut tx, owner, row.id, rel, None, ChangeOperation::Create).await?,
                );
                report.added.push(rel.clone());
                changed.push(rel.clone());
            }
            new_paths.insert(rel.clone());
            current.insert(rel.clone(), row);
        }

        // 3. Files whose size or time changed.
        for (rel, stat) in entries.iter().filter(|(_, stat)| !stat.is_dir) {
            let Some(row) = current.get(rel) else {
                continue;
            };
            if row.mtime_ns == stat.mtime_ns && row.size == stat.size {
                continue;
            }
            let etag = derived_file_etag(row.id, stat.mtime_ns, stat.size);
            sqlx::query("UPDATE files SET etag = ?2, mtime_ns = ?3, size = ?4 WHERE id = ?1")
                .bind(row.id)
                .bind(&etag)
                .bind(stat.mtime_ns)
                .bind(to_db_size(stat.size))
                .execute(&mut *tx)
                .await?;
            if !new_paths.contains(rel) {
                events.push(
                    log_change(&mut tx, owner, row.id, rel, None, ChangeOperation::Modify).await?,
                );
                report.modified.push(rel.clone());
                changed.push(rel.clone());
            }
        }

        // 4. Recursive directory sizes inside the scope, from the entries.
        let mut sizes: HashMap<RelPath, u64> = entries
            .iter()
            .filter(|(_, stat)| stat.is_dir)
            .map(|(rel, _)| (rel.clone(), 0))
            .collect();
        for (rel, stat) in entries.iter().filter(|(_, stat)| !stat.is_dir) {
            for ancestor in rel.ancestors() {
                if let Some(size) = sizes.get_mut(&ancestor) {
                    *size += stat.size;
                }
            }
        }
        // Directories above a reported change get a new ETag (and their new size is explained
        // by that change); any other size difference is drift.
        let mut bump: BTreeSet<RelPath> = changed.iter().flat_map(RelPath::ancestors).collect();
        let explained = bump.clone();
        for (rel, size) in &sizes {
            let Some(row) = current.get(rel) else {
                continue;
            };
            if row.size == *size {
                continue;
            }
            sqlx::query("UPDATE files SET size = ?2 WHERE id = ?1")
                .bind(row.id)
                .bind(to_db_size(*size))
                .execute(&mut *tx)
                .await?;
            if !new_paths.contains(rel) && !adopted.contains(rel) && !explained.contains(rel) {
                report.resized += 1;
                bump.insert(rel.clone());
                bump.extend(rel.ancestors());
            }
        }

        // 5. The ancestors of the scope follow the scope's new total.
        let new_scope_size = match disk.get(scope) {
            Some(stat) if stat.is_dir => sizes.get(scope).copied().map_or(0, to_db_size),
            Some(stat) => to_db_size(stat.size),
            None => 0,
        };
        let delta = new_scope_size - old_scope_size;
        if delta != 0 {
            bump.extend(scope.ancestors());
        }
        for ancestor in scope.ancestors() {
            sqlx::query(
                "UPDATE files SET size = max(size + ?3, 0) WHERE owner_id = ?1 AND rel_path = ?2",
            )
            .bind(owner)
            .bind(ancestor.as_str())
            .bind(delta)
            .execute(&mut *tx)
            .await?;
        }

        // 6. New ETags for every directory above a change.
        for dir in &bump {
            sqlx::query(
                "UPDATE files SET etag = ?3 WHERE owner_id = ?1 AND rel_path = ?2 AND is_dir = 1",
            )
            .bind(owner)
            .bind(dir.as_str())
            .bind(dir_etag())
            .execute(&mut *tx)
            .await?;
        }

        if dry_run {
            tx.rollback().await?;
        } else {
            tx.commit().await?;
            self.publish(&events);
        }
        Ok(report)
    }

    /// Sets or clears the favorite flag. Favorites are not content, so ETags stay the same.
    pub async fn set_favorite(&self, file_id: i64, favorite: bool) -> Result<()> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        sqlx::query("UPDATE files SET favorite = ?2 WHERE id = ?1")
            .bind(file_id)
            .bind(favorite)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Applies the changes of a PROPPATCH to the dead properties of an entry, in order and in
    /// one transaction. Properties are not content, so ETags stay the same.
    pub async fn patch_dead_props(&self, file_id: i64, changes: &[PropChange]) -> Result<()> {
        let mut tx = db::begin_immediate(&self.pool).await?;
        for change in changes {
            match change {
                PropChange::Set(prop) => {
                    sqlx::query(
                        "INSERT INTO dead_props (file_id, namespace, name, xml) \
                         VALUES (?1, ?2, ?3, ?4) \
                         ON CONFLICT (file_id, namespace, name) DO UPDATE SET xml = excluded.xml",
                    )
                    .bind(file_id)
                    .bind(&prop.namespace)
                    .bind(&prop.name)
                    .bind(&prop.xml)
                    .execute(&mut *tx)
                    .await?;
                }
                PropChange::Remove(namespace, name) => {
                    sqlx::query(
                        "DELETE FROM dead_props WHERE file_id = ?1 AND namespace = ?2 AND name = ?3",
                    )
                    .bind(file_id)
                    .bind(namespace)
                    .bind(name)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        tx.commit().await?;
        Ok(())
    }
}

/// How the ETag of an inserted file row is chosen.
#[derive(Clone, Copy)]
enum Etag {
    /// A version written by the server ([`written_file_etag`]).
    Written,
    /// An adopted entry ([`derived_file_etag`]).
    Derived,
}

async fn select(tx: &mut Tx, owner: i64, rel: &RelPath) -> Result<Option<FileRow>> {
    let sql = format!("SELECT {COLUMNS} FROM files WHERE owner_id = ?1 AND rel_path = ?2");
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(owner)
        .bind(rel.as_str())
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.map(FileRow::from))
}

async fn select_subtree(tx: &mut Tx, owner: i64, dir: &RelPath) -> Result<Vec<FileRow>> {
    let (lower, upper) = descendant_bounds(dir.as_str()).unwrap_or_default();
    let sql = format!(
        "SELECT {COLUMNS} FROM files WHERE owner_id = ?1 \
         AND (rel_path = ?2 OR (rel_path >= ?3 AND rel_path < ?4) OR ?2 = '')"
    );
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(owner)
        .bind(dir.as_str())
        .bind(lower)
        .bind(upper)
        .fetch_all(&mut **tx)
        .await?;
    Ok(rows.into_iter().map(FileRow::from).collect())
}

/// Inserts a row and returns it. Directories start with size 0 unless `stat.size` says
/// otherwise (used by [`MetaStore::record_copy`]).
async fn insert(
    tx: &mut Tx,
    owner: i64,
    rel: &RelPath,
    stat: DiskStat,
    etag: Etag,
) -> Result<FileRow> {
    let size = to_db_size(stat.size);
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO files (owner_id, rel_path, is_dir, etag, mtime_ns, size) \
         VALUES (?1, ?2, ?3, '', ?4, ?5) RETURNING id",
    )
    .bind(owner)
    .bind(rel.as_str())
    .bind(stat.is_dir)
    .bind(stat.mtime_ns)
    .bind(size)
    .fetch_one(&mut **tx)
    .await?;
    let etag = match (stat.is_dir, etag) {
        (true, _) => dir_etag(),
        (false, Etag::Written) => written_file_etag(id, stat.mtime_ns, stat.size),
        (false, Etag::Derived) => derived_file_etag(id, stat.mtime_ns, stat.size),
    };
    sqlx::query("UPDATE files SET etag = ?2 WHERE id = ?1")
        .bind(id)
        .bind(&etag)
        .execute(&mut **tx)
        .await?;
    Ok(FileRow {
        id,
        rel_path: rel.clone(),
        is_dir: stat.is_dir,
        etag,
        mtime_ns: stat.mtime_ns,
        size: stat.size,
        favorite: false,
    })
}

/// Deletes the rows at and below `rel` (dead properties follow through `ON DELETE CASCADE`).
/// Returns the total size of the deleted file rows.
async fn delete_subtree(tx: &mut Tx, owner: i64, rel: &RelPath) -> Result<i64> {
    let (lower, upper) = descendant_bounds(rel.as_str()).expect("never the root");
    let removed: Vec<(bool, i64)> = sqlx::query_as(
        "DELETE FROM files WHERE owner_id = ?1 \
         AND (rel_path = ?2 OR (rel_path >= ?3 AND rel_path < ?4)) RETURNING is_dir, size",
    )
    .bind(owner)
    .bind(rel.as_str())
    .bind(lower)
    .bind(upper)
    .fetch_all(&mut **tx)
    .await?;
    Ok(removed
        .into_iter()
        .filter(|(is_dir, _)| !is_dir)
        .map(|(_, size)| size)
        .sum())
}

/// Gives every ancestor of `rel` a new ETag and adds `delta` to its recursive size.
///
/// Sizes are clamped at zero: they can only drift (after changes behind the server's back)
/// until the next `rescan`, and a drifted size must never make a write fail.
async fn propagate(tx: &mut Tx, owner: i64, rel: &RelPath, delta: i64) -> Result<()> {
    for ancestor in rel.ancestors() {
        sqlx::query(
            "UPDATE files SET etag = ?3, size = max(size + ?4, 0) \
             WHERE owner_id = ?1 AND rel_path = ?2",
        )
        .bind(owner)
        .bind(ancestor.as_str())
        .bind(dir_etag())
        .bind(delta)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Appends a `change_log` row and returns the event to publish once the transaction commits.
async fn log_change(
    tx: &mut Tx,
    owner: i64,
    file_id: i64,
    rel: &RelPath,
    old: Option<&RelPath>,
    operation: ChangeOperation,
) -> Result<ChangeEvent> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO change_log (owner_id, file_id, rel_path, old_rel_path, operation, \
         changed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id",
    )
    .bind(owner)
    .bind(file_id)
    .bind(rel.as_str())
    .bind(old.map(RelPath::as_str))
    .bind(operation.as_str())
    .bind(db::unix_now())
    .fetch_one(&mut **tx)
    .await?;
    Ok(ChangeEvent {
        id,
        owner_id: owner,
        file_id,
        rel_path: rel.clone(),
        old_rel_path: old.cloned(),
        operation,
    })
}
