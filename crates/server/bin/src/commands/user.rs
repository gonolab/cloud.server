//! `gono-cloud user ...`: account management.

use std::path::Path;

use anyhow::Context;
use gono_server_core::{
    db, password,
    storage::DataLayout,
    users::{self, NewUser},
    web_sessions,
};

use super::{
    open_database,
    output::{format_time, print_table},
};
use crate::{cli::UserCommand, password_input};

/// Runs one `user` subcommand.
pub async fn run(config_path: &Path, command: UserCommand) -> anyhow::Result<()> {
    let (config, pool) = open_database(config_path).await?;
    let layout = DataLayout::new(&config.storage.data_dir);
    let result = match command {
        UserCommand::Add {
            username,
            display_name,
            admin,
            password,
        } => {
            let display_name = users::display_name_or_default(display_name.as_deref(), &username)?;
            if users::find(&pool, &username).await?.is_some() {
                // Checked again by the insert; this only avoids prompting for nothing.
                return Err(gono_server_core::Error::UserExists(username).into());
            }
            let hash = read_password_hash(password, &username).await?;
            let id = users::create(
                &pool,
                &NewUser {
                    username: &username,
                    display_name: &display_name,
                    password_hash: &hash,
                    is_admin: admin,
                },
                |id| layout.create_user(id),
            )
            .await?;
            println!("Created user {username} (id {id}).");
            println!(
                "Create an app password for a device with `gono-cloud app-password add {username} --label <NAME>`."
            );
            Ok(())
        }
        UserCommand::List => {
            let rows: Vec<Vec<String>> = users::list(&pool)
                .await?
                .into_iter()
                .map(|user| {
                    vec![
                        user.id.to_string(),
                        user.username.to_string(),
                        user.display_name,
                        yes_no(user.is_admin),
                        yes_no(user.enabled),
                        format_time(user.created_at),
                    ]
                })
                .collect();
            print_table(
                &[
                    "ID",
                    "USERNAME",
                    "DISPLAY NAME",
                    "ADMIN",
                    "ENABLED",
                    "CREATED",
                ],
                &rows,
            );
            Ok(())
        }
        UserCommand::Delete { username } => {
            let user = users::delete(&pool, &username).await?;
            println!("Deleted user {username} with its app passwords and metadata.");
            match layout.retire_user(user.id, username.as_str(), db::unix_now()) {
                Ok(Some(target)) => println!("Moved the user's files to {}.", target.display()),
                Ok(None) => {}
                Err(err) => {
                    // The account is gone either way. The leftover directory blocks the id from
                    // being reused for a new account until it is moved away.
                    eprintln!(
                        "warning: could not move the user's files to {}: {err:#}",
                        layout.deleted_root().display()
                    );
                }
            }
            Ok(())
        }
        UserCommand::SetPassword { username, password } => {
            let user = users::get(&pool, &username).await?;
            let hash = read_password_hash(password, &username).await?;
            users::set_password_hash(&pool, &username, &hash).await?;
            let ended = web_sessions::delete_for_user(&pool, user.id, None).await?;
            println!("Changed the web login password of {username}.");
            if ended > 0 {
                println!("Signed {username} out of {ended} browser session(s).");
            }
            Ok(())
        }
        UserCommand::Enable { username } => {
            users::set_enabled(&pool, &username, true).await?;
            println!("Enabled user {username}.");
            Ok(())
        }
        UserCommand::Disable { username } => {
            let user = users::get(&pool, &username).await?;
            users::set_enabled(&pool, &username, false).await?;
            web_sessions::delete_for_user(&pool, user.id, None).await?;
            println!(
                "Disabled user {username}; their app passwords and browser sessions stop working \
                 too."
            );
            Ok(())
        }
    };
    pool.close().await;
    result
}

/// Reads a new web login password (prompt or stdin) and hashes it off the async runtime.
async fn read_password_hash(
    source: crate::cli::PasswordSource,
    username: &gono_server_core::Username,
) -> anyhow::Result<String> {
    let username = username.clone();
    let password =
        tokio::task::spawn_blocking(move || password_input::read_new_password(source, &username))
            .await??;
    tokio::task::spawn_blocking(move || password::hash(&password))
        .await?
        .context("hash the password")
}

fn yes_no(value: bool) -> String {
    if value { "yes" } else { "no" }.to_owned()
}
