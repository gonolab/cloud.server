//! Implementations of the subcommands.

pub mod app_password;
pub mod config_check;
pub mod init;
mod output;
pub mod serve;
pub mod user;

use std::path::Path;

use anyhow::{Context, bail};
use gono_core::{
    Config,
    config::LogLevel,
    db::{self, OpenMode, Pool},
};

use crate::logging::{self, Destination};

/// Loads and validates the config file, with a hint when it does not exist.
fn load_config(path: &Path) -> anyhow::Result<Config> {
    if !path.exists() {
        bail!(
            "config file {} not found; pass --config <PATH> or set GONO_CLOUD_CONFIG \
             (start from config.example.toml)",
            path.display()
        );
    }
    Ok(Config::load(path)?)
}

/// Loads the config, sets up warning-level logging to stderr, and opens the existing database
/// with all migrations applied. Used by the management commands.
async fn open_database(config_path: &Path) -> anyhow::Result<(Config, Pool)> {
    let config = load_config(config_path)?;
    // The guard only matters for file logging, which these commands never use.
    drop(logging::init(LogLevel::Warn, Destination::Stderr)?);
    let pool = db::connect(&config.db, OpenMode::MustExist)
        .await
        .context("open database")?;
    db::migrate(&pool)
        .await
        .context("apply database migrations")?;
    Ok((config, pool))
}

/// Placeholder result of subcommands whose arguments are defined but whose behavior is not
/// implemented yet.
pub fn not_implemented(command: &str) -> anyhow::Result<()> {
    bail!("`gono-cloud {command}` is not implemented yet")
}
