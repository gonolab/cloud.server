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
    cli::{Cli, Command, ConfigCommand},
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
        Command::User(command) => commands::user::run(config, command).await,
        Command::AppPassword(command) => commands::app_password::run(config, command).await,
        Command::Rescan(_) => not_implemented("rescan"),
    }
}
