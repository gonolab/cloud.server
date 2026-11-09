//! `gono-cloud app-password ...`: device credentials.
//!
//! The value of a new app password is printed exactly once, to stdout, and never logged.

use std::path::Path;

use anyhow::bail;
use gono_core::{
    RelPath,
    app_passwords::{self, Scope},
    db, users,
};
use secrecy::ExposeSecret;

use super::{
    open_database,
    output::{format_optional_time, format_time, print_table},
};
use crate::cli::{AppPasswordCommand, ScopeArg};

/// Runs one `app-password` subcommand.
pub async fn run(config_path: &Path, command: AppPasswordCommand) -> anyhow::Result<()> {
    let (_, pool) = open_database(config_path).await?;
    let result = async {
        match command {
            AppPasswordCommand::Add {
                username,
                label,
                scopes,
                expires_in_days,
            } => {
                let user = users::get(&pool, &username).await?;
                let scopes = scopes
                    .iter()
                    .map(to_scope)
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let expires_at =
                    expires_in_days.map(|days| db::unix_now() + i64::from(days.get()) * 86_400);
                let (id, token) =
                    app_passwords::create(&pool, user.id, &label, scopes, expires_at).await?;
                let created = app_passwords::list(&pool, user.id)
                    .await?
                    .into_iter()
                    .find(|password| password.id == id);

                println!("Created app password {id} for {username}.");
                if let Some(created) = created {
                    println!("  label    {}", created.label);
                    println!("  scopes   {}", describe_scopes(&created.scopes));
                    println!(
                        "  expires  {}",
                        format_optional_time(created.expires_at, "never")
                    );
                }
                println!();
                println!("App password: {}", token.expose_secret());
                println!();
                println!(
                    "It is shown only once. Sign the device in with {username} and this password."
                );
                Ok(())
            }
            AppPasswordCommand::List { username } => {
                let user = users::get(&pool, &username).await?;
                let rows: Vec<Vec<String>> = app_passwords::list(&pool, user.id)
                    .await?
                    .into_iter()
                    .map(|password| {
                        vec![
                            password.id.to_string(),
                            password.label,
                            format_time(password.created_at),
                            format_optional_time(password.expires_at, "never"),
                            format_optional_time(password.last_used_at, "never"),
                            describe_scopes(&password.scopes),
                        ]
                    })
                    .collect();
                print_table(
                    &["ID", "LABEL", "CREATED", "EXPIRES", "LAST USED", "SCOPES"],
                    &rows,
                );
                Ok(())
            }
            AppPasswordCommand::Delete { username, id } => {
                let user = users::get(&pool, &username).await?;
                if !app_passwords::delete(&pool, user.id, id).await? {
                    bail!("user {username} has no app password with id {id}");
                }
                println!("Revoked app password {id} of {username}.");
                Ok(())
            }
        }
    }
    .await;
    pool.close().await;
    result
}

fn to_scope(arg: &ScopeArg) -> anyhow::Result<Scope> {
    let parse = |value: &str| {
        RelPath::parse(value).map_err(|source| gono_core::Error::InvalidPath {
            path: value.to_owned(),
            source,
        })
    };
    Ok(Scope {
        mount_path: parse(&arg.mount_path)?,
        storage_path: parse(&arg.storage_path)?,
        permission: arg.permission,
    })
}

/// `/=/:full`, `/Photos=/Media/Photos:view, ...`
fn describe_scopes(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(|scope| {
            format!(
                "{}={}:{}",
                scope.mount_path, scope.storage_path, scope.permission
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}
