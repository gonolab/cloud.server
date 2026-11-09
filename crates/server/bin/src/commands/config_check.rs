//! `gono-cloud config check`.

use std::path::Path;

use super::load_config;

/// Validates the config file and prints the effective settings, with relative paths resolved.
pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = load_config(config_path)?;

    let proxies = if config.server.trusted_proxies.is_empty() {
        "(none)".to_owned()
    } else {
        config
            .server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let log_file = config
        .logging
        .file
        .as_ref()
        .map_or_else(|| "(stdout)".to_owned(), |file| file.display().to_string());

    println!("Configuration OK: {}", config_path.display());
    println!();
    for (key, value) in [
        ("server.bind", config.server.bind.to_string()),
        ("server.base_url", config.server.base_url.to_string()),
        ("server.trusted_proxies", proxies),
        (
            "storage.data_dir",
            config.storage.data_dir.display().to_string(),
        ),
        ("db.path", config.db.path.display().to_string()),
        (
            "webdav.max_lock_timeout_secs",
            config.webdav.max_lock_timeout_secs.to_string(),
        ),
        ("logging.level", config.logging.level.as_str().to_owned()),
        ("logging.file", log_file),
        (
            "notify_push.enabled",
            config.notify_push.enabled.to_string(),
        ),
        ("admin.enabled", config.admin.enabled.to_string()),
        ("admin.path", config.admin.path.clone()),
    ] {
        println!("  {key:<29} {value}");
    }

    let warnings = config.warnings();
    if !warnings.is_empty() {
        println!();
        for warning in warnings {
            println!("warning: {warning}");
        }
    }
    Ok(())
}
