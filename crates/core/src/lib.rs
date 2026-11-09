//! Core building blocks of Gono Cloud that do not depend on any HTTP framework.
//!
//! - [`config`]: the TOML configuration file, its defaults and its validation.
//! - [`db`]: SQLite connection setup and the embedded schema migrations.
//! - [`meta`]: rules shared by every query on path-keyed metadata.
//! - [`path`]: [`RelPath`], the validated and NFC-normalized form of storage paths.
//! - [`storage`]: layout of the data directory.
//! - [`types`]: validated domain types such as [`Username`] and [`Permission`].
//! - [`password`]: hashing of web login passwords.
//! - [`users`]: user account storage.
//! - [`error`]: the domain error types.

pub mod config;
pub mod db;
pub mod error;
pub mod meta;
pub mod password;
pub mod path;
pub mod storage;
pub mod types;
pub mod users;

pub use config::Config;
pub use error::{ConfigError, Error, Result};
pub use path::RelPath;
pub use types::{Permission, Username};

/// Product name reported to clients and used in user-facing output.
pub const PRODUCT_NAME: &str = "Gono Cloud";
