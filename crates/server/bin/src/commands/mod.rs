//! Implementations of the subcommands.

pub mod app_password;
pub mod config_check;
pub mod init;
pub(crate) mod output;
pub mod rescan;
pub mod serve;
pub mod user;

use std::path::Path;

use anyhow::{Context, bail};
use gono_server_core::{
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

/// Refuses to work on an installation that belongs to another user when running as root.
///
/// The installer runs the server as a dedicated service user that owns the database and the
/// data directory. A command started as root (`sudo gono-cloud user add ...`) would create files
/// the server cannot write afterwards: the SQLite WAL and shared-memory files, the storage
/// directories of new users, partial uploads. Such commands have to run as the owner instead
/// (`sudo -u gono-cloud gono-cloud ...`). Installations owned by root are not affected.
fn refuse_root_on_foreign_install(config: &Config) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let euid = rustix::process::geteuid().as_raw();
        let paths = [config.db.path.as_path(), config.storage.data_dir.as_path()];
        if let Some((path, owner)) = foreign_owner(euid, &paths) {
            bail!(
                "this command runs as root, but {} belongs to user id {owner}; files it creates \
                 would be unusable for the server. Run it as the owner of the installation, for \
                 example `sudo -u {SERVICE_USER} gono-cloud ...`",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = config;
    Ok(())
}

/// The service user the installer creates (`packaging/server/install.sh`), for hints.
#[cfg(target_os = "macos")]
const SERVICE_USER: &str = "_gono-cloud";
#[cfg(all(unix, not(target_os = "macos")))]
const SERVICE_USER: &str = "gono-cloud";

/// With `euid` 0 (root), the first of `paths` (or its parent directory, while the path does not
/// exist yet) that is owned by another user, with that user's id.
#[cfg(unix)]
fn foreign_owner(euid: u32, paths: &[&Path]) -> Option<(std::path::PathBuf, u32)> {
    use std::os::unix::fs::MetadataExt as _;

    if euid != 0 {
        return None;
    }
    paths.iter().find_map(|path| {
        let candidate = if path.exists() {
            *path
        } else {
            // A relative path without a parent component lives in the current directory.
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
        };
        let owner = std::fs::metadata(candidate).ok()?.uid();
        (owner != 0).then(|| (candidate.to_path_buf(), owner))
    })
}

/// Loads the config, sets up warning-level logging to stderr, and opens the existing database
/// with all migrations applied. Used by the management commands.
async fn open_database(config_path: &Path) -> anyhow::Result<(Config, Pool)> {
    let config = load_config(config_path)?;
    refuse_root_on_foreign_install(&config)?;
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

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    #[test]
    fn root_is_refused_on_files_of_another_user() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("gono-cloud.db");
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let owner = std::fs::metadata(dir.path()).unwrap().uid();
        if owner == 0 {
            // Running the tests as root: every file belongs to root, nothing to refuse.
            assert_eq!(foreign_owner(0, &[&db, &data]), None);
            return;
        }

        // The database does not exist yet: its directory decides.
        assert_eq!(
            foreign_owner(0, &[&db, &data]),
            Some((dir.path().to_path_buf(), owner))
        );
        std::fs::write(&db, b"").unwrap();
        assert_eq!(foreign_owner(0, &[&db, &data]), Some((db.clone(), owner)));
        // Other users are never refused, whoever owns the files.
        assert_eq!(foreign_owner(owner, &[&db, &data]), None);
        assert_eq!(foreign_owner(owner + 1, &[&db, &data]), None);
    }
}
