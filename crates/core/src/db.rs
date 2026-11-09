//! SQLite connection setup and schema migrations.
//!
//! - Connections run in WAL mode with foreign keys enforced and `synchronous = FULL`.
//! - Writes go through [`begin_immediate`]: one `BEGIN IMMEDIATE` transaction per operation,
//!   so the write lock is taken up front and concurrent writers wait on `busy_timeout` instead
//!   of failing halfway through a transaction with `SQLITE_BUSY`.
//! - Migrations live in `crates/core/migrations/` and are embedded into the binary. They are
//!   append-only once released; see the header of `0001_initial.sql` and
//!   [`crate::meta`] for the path comparison rules every query must follow.

use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sqlx::{
    Sqlite, Transaction,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::{
    config::DbConfig,
    error::{Error, Result},
};

/// Connection pool type used throughout Gono Cloud.
pub type Pool = sqlx::SqlitePool;

/// The embedded schema migrations.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Whether [`connect`] may create a missing database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Create the file (and its parent directories) if needed. Used by `init`.
    CreateIfMissing,
    /// Fail with [`Error::DatabaseMissing`] if the file does not exist. Used by `serve` and the
    /// management commands, so that a typo in `db.path` cannot silently start from an empty
    /// database.
    MustExist,
}

/// Opens a connection pool to the configured database.
///
/// This does not run migrations; call [`migrate`] afterwards.
pub async fn connect(config: &DbConfig, mode: OpenMode) -> Result<Pool> {
    let path = &config.path;
    match mode {
        OpenMode::CreateIfMissing => create_database_file(path)?,
        OpenMode::MustExist => {
            if !path.exists() {
                return Err(Error::DatabaseMissing { path: path.clone() });
            }
        }
    }

    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        // Metadata must not lag behind file contents after a power loss.
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(config.busy_timeout_secs));

    let pool = SqlitePoolOptions::new()
        .max_connections(config.max_connections)
        .connect_with(options)
        .await?;
    Ok(pool)
}

/// Applies all pending migrations.
///
/// Fails if an already applied migration was modified (checksum mismatch) or if the database
/// was migrated by a newer version of Gono Cloud.
pub async fn migrate(pool: &Pool) -> Result<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}

/// Starts a write transaction with `BEGIN IMMEDIATE`.
///
/// Every operation that writes uses exactly one such transaction. Taking the write lock at
/// `BEGIN` means a transaction never has to be retried after it has already read data.
pub async fn begin_immediate(pool: &Pool) -> Result<Transaction<'static, Sqlite>> {
    Ok(pool.begin_with("BEGIN IMMEDIATE").await?)
}

/// Runs a trivial query to check that the database is reachable.
pub async fn ping(pool: &Pool) -> Result<()> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}

/// Current time as UNIX seconds, the unit of every `*_at` column.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Creates the database file and its parent directory if they do not exist yet.
///
/// On Unix the file is created with mode `0600` and new directories with `0700`: the database
/// holds password hashes. SQLite creates its `-wal` and `-shm` files with the permissions of
/// the main file.
fn create_database_file(path: &Path) -> Result<()> {
    let io_error = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(parent).map_err(|source| Error::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        // An empty file is a valid, empty SQLite database.
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(io_error(err)),
    }
}
