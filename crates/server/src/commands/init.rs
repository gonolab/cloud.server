//! `gono-cloud init`.

use std::{fs, path::Path};

use anyhow::Context;
use gono_core::{
    Error, PRODUCT_NAME,
    config::LogLevel,
    db::{self, OpenMode},
    password, users,
};

use super::load_config;
use crate::{
    cli::InitArgs,
    logging::{self, Destination},
    password_input,
};

/// Creates the data directory and the database, applies the migrations and creates the first
/// admin account.
///
/// Refuses to run against a database that already has accounts. The admin's web login password
/// is read from the terminal or stdin and is never printed or logged.
pub async fn run(config_path: &Path, args: InitArgs) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    let _log_guard = logging::init(LogLevel::Warn, Destination::Stderr)?;
    let display_name = users::display_name_or_default(args.display_name.as_deref(), &args.admin)?;

    create_private_dir(&config.storage.data_dir)?;
    let pool = db::connect(&config.db, OpenMode::CreateIfMissing)
        .await
        .context("create database")?;
    db::migrate(&pool)
        .await
        .context("apply database migrations")?;

    // Checked again inside the insert transaction; this early check only avoids prompting for a
    // password that would be thrown away.
    if users::count(&pool).await? > 0 {
        pool.close().await;
        return Err(Error::AlreadyInitialized.into());
    }

    let username = args.admin.clone();
    let source = args.password;
    let password =
        tokio::task::spawn_blocking(move || password_input::read_new_password(source, &username))
            .await??;
    let password_hash = tokio::task::spawn_blocking(move || password::hash(&password)).await??;

    users::create_initial_admin(&pool, &args.admin, &display_name, &password_hash).await?;
    pool.close().await;

    println!("Initialized {PRODUCT_NAME}.");
    println!();
    println!("  database        {}", config.db.path.display());
    println!("  data directory  {}", config.storage.data_dir.display());
    println!("  admin account   {}", args.admin);
    println!();
    println!("Start the server with `gono-cloud serve`.");
    Ok(())
}

/// Creates `path` and its parents. On Unix, newly created directories get mode `0700`.
fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(path)
        .with_context(|| format!("create data directory {}", path.display()))
}
