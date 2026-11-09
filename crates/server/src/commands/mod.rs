//! Implementations of the subcommands.

pub mod config_check;
pub mod init;
pub mod serve;

use std::path::Path;

use anyhow::bail;
use gono_core::Config;

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

/// Placeholder result of subcommands whose arguments are defined but whose behavior is not
/// implemented yet.
pub fn not_implemented(command: &str) -> anyhow::Result<()> {
    bail!("`gono-cloud {command}` is not implemented yet")
}
