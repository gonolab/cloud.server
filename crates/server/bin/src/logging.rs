//! Log output.
//!
//! `logging.level` applies to Gono Cloud's own crates; dependencies log at `warn` and above so
//! that, for example, sqlx does not log every statement. `GONO_CLOUD_LOG` replaces the whole
//! filter with a `tracing` directive string for debugging (`info,sqlx=debug`).
//!
//! Secrets never reach the log: plaintext passwords are carried in `SecretString`, whose
//! `Debug` output is redacted, and nothing logs request credentials or tokens.

use std::{
    fs::OpenOptions,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

use anyhow::Context;
use gono_core::config::LogLevel;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Environment variable that overrides the configured log filter.
pub const LOG_ENV: &str = "GONO_CLOUD_LOG";

/// Crates whose events `logging.level` applies to.
const OWN_CRATES: &[&str] = &["gono_cloud", "gono_core", "gono_dav", "gono_nextcloud"];

/// Where log lines go.
#[derive(Debug, Clone)]
pub enum Destination {
    /// Standard output: the default for `serve`.
    Stdout,
    /// Standard error: used by the one-shot commands, whose results go to stdout.
    Stderr,
    /// Append to a file (`logging.file`).
    File(PathBuf),
}

/// Keeps the background log writer alive. Drop it last so buffered lines are flushed on exit.
#[must_use = "dropping the guard stops log output"]
pub struct LogGuard(#[allow(dead_code)] Option<WorkerGuard>);

/// Installs the global `tracing` subscriber.
pub fn init(level: LogLevel, destination: Destination) -> anyhow::Result<LogGuard> {
    let filter = filter(level)?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    let guard = match destination {
        Destination::Stdout => {
            builder
                .with_ansi(io::stdout().is_terminal())
                .with_writer(io::stdout)
                .init();
            None
        }
        Destination::Stderr => {
            builder
                .with_ansi(io::stderr().is_terminal())
                .with_writer(io::stderr)
                .init();
            None
        }
        Destination::File(path) => {
            let file = open_log_file(&path)?;
            let (writer, guard) = tracing_appender::non_blocking(file);
            builder.with_ansi(false).with_writer(writer).init();
            Some(guard)
        }
    };
    Ok(LogGuard(guard))
}

fn filter(level: LogLevel) -> anyhow::Result<EnvFilter> {
    if let Some(directives) = std::env::var_os(LOG_ENV) {
        let directives = directives
            .into_string()
            .map_err(|_| anyhow::anyhow!("{LOG_ENV} is not valid UTF-8"))?;
        return EnvFilter::try_new(&directives)
            .with_context(|| format!("invalid {LOG_ENV} filter {directives:?}"));
    }

    let level = level.as_str();
    let mut directives = String::from("warn");
    for krate in OWN_CRATES {
        directives.push_str(&format!(",{krate}={level}"));
    }
    Ok(EnvFilter::try_new(directives)?)
}

fn open_log_file(path: &Path) -> anyhow::Result<std::fs::File> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create log directory {}", parent.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open log file {}", path.display()))
}
