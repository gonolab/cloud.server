//! Domain error types.
//!
//! Library crates report failures with these typed errors. Only the binary crate wraps them in
//! `anyhow` to add context for the operator.

use std::{fmt, io, path::PathBuf};

use crate::types::Username;

/// Result alias for fallible domain operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors raised by domain operations (database, users, passwords).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A database query or connection failed.
    #[error("database error")]
    Database(#[from] sqlx::Error),

    /// Applying or verifying the schema migrations failed.
    #[error("database migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// The database file does not exist and the caller did not ask to create it.
    #[error(
        "database file {} does not exist; run `gono-cloud init` to create it",
        path.display()
    )]
    DatabaseMissing {
        /// Configured database path.
        path: PathBuf,
    },

    /// The configured data directory does not exist.
    #[error(
        "data directory {} does not exist; run `gono-cloud init` or fix storage.data_dir",
        path.display()
    )]
    DataDirMissing {
        /// Configured data directory.
        path: PathBuf,
    },

    /// Two directories that must share a file system (for atomic renames) do not.
    #[error(
        "{} and {} are on different file systems; uploads are moved into place with an \
         atomic rename, so the whole data directory must be on one file system",
        first.display(),
        second.display()
    )]
    CrossDevice {
        /// First directory.
        first: PathBuf,
        /// Directory on a different file system.
        second: PathBuf,
    },

    /// A new account's directory already holds files, probably of a deleted account with the
    /// same id.
    #[error(
        "{} already exists and is not empty; it may belong to a deleted account with the same \
         id. Move it away and try again",
        path.display()
    )]
    UserDirNotEmpty {
        /// The non-empty directory.
        path: PathBuf,
    },

    /// A file system operation failed.
    #[error("I/O error on {}", path.display())]
    Io {
        /// Path the operation was acting on.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },

    /// A username does not satisfy [`Username`]'s rules.
    #[error("invalid username {username:?}: {reason}")]
    InvalidUsername {
        /// The rejected input.
        username: String,
        /// Which rule was violated.
        reason: &'static str,
    },

    /// A display name is empty, too long or contains control characters.
    #[error("invalid display name: {0}")]
    InvalidDisplayName(&'static str),

    /// A permission string is neither `view` nor `full`.
    #[error("invalid permission {0:?}: expected `view` or `full`")]
    InvalidPermission(String),

    /// A new web login password does not satisfy the password policy.
    ///
    /// The message never contains the password itself.
    #[error("invalid password: {0}")]
    InvalidPassword(&'static str),

    /// Hashing a password failed. The password itself is never part of the error.
    #[error("password hashing failed")]
    PasswordHash(#[source] argon2::password_hash::Error),

    /// A user with this name already exists.
    #[error("user {0} already exists")]
    UserExists(Username),

    /// No account has this name.
    #[error("user {0} does not exist")]
    UserNotFound(Username),

    /// An app password label is empty, too long or contains control characters.
    #[error("invalid label: {0}")]
    InvalidLabel(&'static str),

    /// The mounts of an app password are inconsistent.
    #[error("invalid scopes: {0}")]
    InvalidScopes(String),

    /// A storage path is not acceptable.
    #[error("invalid path {path:?}: {source}")]
    InvalidPath {
        /// The rejected input.
        path: String,
        /// Which rule was violated.
        #[source]
        source: crate::path::PathError,
    },

    /// The change would leave no enabled admin account, so nobody could use the web admin UI.
    #[error("{0} is the last enabled admin; make another account an admin first, or keep this one")]
    LastAdmin(Username),

    /// `init` was run against a database that already has accounts.
    #[error("the database already contains users; manage accounts with `gono-cloud user`")]
    AlreadyInitialized,
}

/// Errors raised while loading or validating the configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("failed to read config file {}", path.display())]
    Read {
        /// Path of the config file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },

    /// The file is not valid TOML or does not match the schema (unknown keys, wrong types).
    #[error("failed to parse config file {}", path.display())]
    Parse {
        /// Path of the config file.
        path: PathBuf,
        /// Parser error, including the line and column of the problem.
        #[source]
        source: Box<toml::de::Error>,
    },

    /// The file parsed, but one or more values are not acceptable.
    #[error("invalid configuration:{}", DisplayIssues(.0))]
    Invalid(Vec<ValidationIssue>),
}

/// One rejected configuration value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Dotted key of the offending value, for example `server.bind`.
    pub key: &'static str,
    /// What is wrong and, where possible, how to fix it.
    pub message: String,
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.message)
    }
}

/// Renders every issue on its own line so operators can fix them all in one pass.
struct DisplayIssues<'a>(&'a [ValidationIssue]);

impl fmt::Display for DisplayIssues<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for issue in self.0 {
            write!(f, "\n  - {issue}")?;
        }
        Ok(())
    }
}
