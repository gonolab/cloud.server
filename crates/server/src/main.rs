//! `gono-cloud`: command line entry point of Gono Cloud.

mod app;
mod cli;
mod commands;
mod logging;
mod password_input;
mod shutdown;

use std::process::ExitCode;

use clap::Parser;

use crate::{
    cli::{AppPasswordCommand, Cli, Command, ConfigCommand, UserCommand},
    commands::not_implemented,
};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = cli.config.as_path();
    match cli.command {
        Command::Serve => commands::serve::run(config).await,
        Command::Init(args) => commands::init::run(config, args).await,
        Command::Config(ConfigCommand::Check) => commands::config_check::run(config),
        Command::User(command) => not_implemented(match command {
            UserCommand::Add { .. } => "user add",
            UserCommand::List => "user list",
            UserCommand::Delete { .. } => "user delete",
            UserCommand::SetPassword { .. } => "user set-password",
            UserCommand::Enable { .. } => "user enable",
            UserCommand::Disable { .. } => "user disable",
        }),
        Command::AppPassword(command) => not_implemented(match command {
            AppPasswordCommand::Add { .. } => "app-password add",
            AppPasswordCommand::List { .. } => "app-password list",
            AppPasswordCommand::Delete { .. } => "app-password delete",
        }),
        Command::Rescan(_) => not_implemented("rescan"),
    }
}
