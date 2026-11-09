//! Core building blocks of Gono Cloud that do not depend on any HTTP framework.
//!
//! - [`config`]: the TOML configuration file, its defaults and its validation.
//! - [`db`]: SQLite connection setup and the embedded schema migrations.
//! - [`meta`]: rules shared by every query on path-keyed metadata.
//! - [`path`]: [`RelPath`], the validated and NFC-normalized form of storage paths.
//! - [`storage`]: layout of the data directory.
//! - [`settings`]: server-wide generated settings such as the instance id.
//! - [`types`]: validated domain types such as [`Username`] and [`Permission`].
//! - [`password`]: hashing of web login passwords.
//! - [`users`]: user account storage.
//! - [`app_passwords`]: device credentials and their mount scopes.
//! - [`locks`]: persistent WebDAV locks.
//! - [`uploads`]: chunked upload sessions.
//! - [`login_flows`]: pending Login Flow v2 sign-ins.
//! - [`web_sessions`]: browser sessions of the server's HTML pages.
//! - [`secret`]: random tokens and their digests.
//! - [`stats`]: counts shown on the web admin UI.
//! - [`error`]: the domain error types.

pub mod app_passwords;
pub mod config;
pub mod db;
pub mod error;
pub mod locks;
pub mod login_flows;
pub mod meta;
pub mod password;
pub mod path;
pub mod secret;
pub mod settings;
pub mod stats;
pub mod storage;
pub mod types;
pub mod uploads;
pub mod users;
pub mod web_sessions;

pub use config::Config;
pub use error::{ConfigError, Error, Result};
pub use path::RelPath;
pub use types::{Permission, Username};

/// Product name reported to clients and used in user-facing output.
pub const PRODUCT_NAME: &str = "Gono Cloud";
