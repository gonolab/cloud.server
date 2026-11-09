//! `gono-cloud`: command line entry point of Gono Cloud.

mod app;
mod auth;
mod cli;
mod client_ip;
mod commands;
mod janitor;
mod logging;
mod login_flow;
mod nextcloud;
mod password_input;
mod ratelimit;
mod request_log;
mod shutdown;
mod web;

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
