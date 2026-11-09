//! Command line definition.

use std::{num::NonZeroU32, path::PathBuf, str::FromStr};

use clap::{Args, Parser, Subcommand};
use gono_core::{Permission, Username};

/// Gono Cloud: a self-hosted WebDAV file server compatible with Nextcloud clients.
#[derive(Debug, Parser)]
#[command(name = "gono-cloud", version, propagate_version = true)]
pub struct Cli {
    /// Path to the configuration file.
    #[arg(
        long,
        short = 'c',
        global = true,
        env = "GONO_CLOUD_CONFIG",
        default_value = "config.toml",
        value_name = "PATH"
    )]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server until SIGTERM or Ctrl-C.
    Serve,

    /// Create the database, apply migrations and create the first admin account.
    Init(InitArgs),

    /// Inspect the configuration file.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Manage user accounts.
    #[command(subcommand)]
    User(UserCommand),

    /// Manage app passwords, the credentials devices sign in with.
    #[command(subcommand)]
    AppPassword(AppPasswordCommand),

    /// Re-read files that were changed directly in the data directory.
    ///
    /// The data directory belongs to the server. After changing files behind its back (SSH,
    /// Samba, rsync, ...), run this command so that clients see the changes.
    Rescan(RescanArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Username of the first admin account.
    #[arg(long, value_name = "USERNAME", default_value = "admin")]
    pub admin: Username,

    /// Display name of the admin account. Defaults to the username.
    #[arg(long, value_name = "NAME")]
    pub display_name: Option<String>,

    #[command(flatten)]
    pub password: PasswordSource,
}

/// Where a new web login password comes from. It is never accepted as a command line argument,
/// which would expose it in the process list and shell history.
#[derive(Debug, Clone, Copy, Args)]
pub struct PasswordSource {
    /// Read the web login password from the first line of standard input instead of prompting
    /// on the terminal.
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration file and print the effective settings.
    Check,
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// Create a user account. The web login password is prompted for or read from stdin.
    Add {
        /// Name of the new account.
        username: Username,

        /// Display name. Defaults to the username.
        #[arg(long, value_name = "NAME")]
        display_name: Option<String>,

        /// Grant access to the web admin UI.
        #[arg(long)]
        admin: bool,

        #[command(flatten)]
        password: PasswordSource,
    },

    /// List user accounts.
    List,

    /// Delete a user account with its app passwords, sessions and metadata.
    ///
    /// The user's files are not deleted: they are moved to `<data_dir>/deleted/` so that a new
    /// account can never inherit them. The last enabled admin cannot be deleted.
    Delete {
        /// Account to delete.
        username: Username,
    },

    /// Replace the web login password of a user.
    SetPassword {
        /// Account whose password changes.
        username: Username,

        #[command(flatten)]
        password: PasswordSource,
    },

    /// Allow a disabled user to sign in again.
    Enable {
        /// Account to enable.
        username: Username,
    },

    /// Block a user from signing in. Existing app passwords stop working too. The last enabled
    /// admin cannot be disabled.
    Disable {
        /// Account to disable.
        username: Username,
    },
}

#[derive(Debug, Subcommand)]
pub enum AppPasswordCommand {
    /// Create an app password and print it once.
    Add {
        /// Account the app password belongs to.
        username: Username,

        /// Name shown in listings, for example the device name.
        #[arg(long)]
        label: String,

        /// Mount a directory of the user's storage into the client's view, as
        /// `<MOUNT>=<STORAGE>:<view|full>`, for example `/Photos=/Media/Photos:view`. Repeat
        /// for several mounts; mount paths must not be nested inside each other. Without any
        /// `--scope` the app password gets full access to the user's whole storage
        /// (`/=/:full`).
        #[arg(long = "scope", value_name = "MOUNT=STORAGE:PERM")]
        scopes: Vec<ScopeArg>,

        /// Expire the app password after this many days. By default it never expires.
        #[arg(long, value_name = "DAYS")]
        expires_in_days: Option<NonZeroU32>,
    },

    /// List the app passwords of a user (never their values).
    List {
        /// Account whose app passwords are listed.
        username: Username,
    },

    /// Revoke an app password.
    Delete {
        /// Account the app password belongs to.
        username: Username,

        /// Id of the app password, as shown by `app-password list`.
        id: i64,
    },
}

#[derive(Debug, Args)]
pub struct RescanArgs {
    /// Account to rescan.
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    pub username: Option<Username>,

    /// Only rescan this directory, relative to the user's storage root.
    #[arg(long, value_name = "PATH", conflicts_with = "all")]
    pub path: Option<String>,

    /// Rescan every account.
    #[arg(long)]
    pub all: bool,
}

/// One `--scope <MOUNT>=<STORAGE>:<view|full>` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeArg {
    /// Path in the client's view, starting with `/`.
    pub mount_path: String,
    /// Path in the user's storage, starting with `/`.
    pub storage_path: String,
    /// Access level of the mount.
    pub permission: Permission,
}

impl FromStr for ScopeArg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        const FORMAT: &str =
            "expected <MOUNT>=<STORAGE>:<view|full>, for example /Photos=/Media:view";
        let (paths, permission) = value.rsplit_once(':').ok_or(FORMAT)?;
        let (mount_path, storage_path) = paths.split_once('=').ok_or(FORMAT)?;
        if !mount_path.starts_with('/') || !storage_path.starts_with('/') {
            return Err(format!("both paths must start with '/'; {FORMAT}"));
        }
        let permission = permission.parse().map_err(|err| format!("{err}"))?;
        Ok(Self {
            mount_path: mount_path.to_owned(),
            storage_path: storage_path.to_owned(),
            permission,
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("gono-cloud").chain(args.iter().copied()))
    }

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn config_path_defaults_and_overrides() {
        let cli = parse(&["serve"]).unwrap();
        // GONO_CLOUD_CONFIG may be set in the environment running the tests.
        if std::env::var_os("GONO_CLOUD_CONFIG").is_none() {
            assert_eq!(cli.config, PathBuf::from("config.toml"));
        }

        let cli = parse(&["config", "check", "--config", "/etc/gono-cloud/config.toml"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("/etc/gono-cloud/config.toml"));
        assert!(matches!(cli.command, Command::Config(ConfigCommand::Check)));
    }

    #[test]
    fn init_validates_the_admin_name() {
        let cli = parse(&["init", "--password-stdin"]).unwrap();
        let Command::Init(args) = cli.command else {
            panic!("expected init");
        };
        assert_eq!(args.admin.as_str(), "admin");
        assert!(args.password.password_stdin);

        assert!(parse(&["init", "--admin", "Not Valid"]).is_err());
    }

    #[test]
    fn passwords_are_not_accepted_as_arguments() {
        assert!(parse(&["init", "--password", "hunter22"]).is_err());
        assert!(parse(&["user", "add", "alice", "--password", "hunter22"]).is_err());
    }

    #[test]
    fn app_password_scopes_parse() {
        let cli = parse(&[
            "app-password",
            "add",
            "alice",
            "--label",
            "phone",
            "--scope",
            "/Photos=/Media/Photos:view",
            "--scope",
            "/Inbox=/Inbox:full",
            "--expires-in-days",
            "30",
        ])
        .unwrap();
        let Command::AppPassword(AppPasswordCommand::Add {
            scopes,
            expires_in_days,
            ..
        }) = cli.command
        else {
            panic!("expected app-password add");
        };
        assert_eq!(
            scopes,
            [
                ScopeArg {
                    mount_path: "/Photos".into(),
                    storage_path: "/Media/Photos".into(),
                    permission: Permission::View,
                },
                ScopeArg {
                    mount_path: "/Inbox".into(),
                    storage_path: "/Inbox".into(),
                    permission: Permission::Full,
                },
            ]
        );
        assert_eq!(expires_in_days.map(NonZeroU32::get), Some(30));

        for bad in [
            "/Photos:view",
            "/a=/b",
            "/a=/b:admin",
            "a=/b:view",
            "/a=b:full",
        ] {
            assert!(
                parse(&[
                    "app-password",
                    "add",
                    "alice",
                    "--label",
                    "x",
                    "--scope",
                    bad
                ])
                .is_err(),
                "{bad}"
            );
        }
        assert!(
            parse(&[
                "app-password",
                "add",
                "alice",
                "--label",
                "x",
                "--expires-in-days",
                "0"
            ])
            .is_err()
        );
    }

    #[test]
    fn rescan_needs_a_user_or_all() {
        assert!(parse(&["rescan"]).is_err());
        assert!(parse(&["rescan", "alice", "--all"]).is_err());
        assert!(parse(&["rescan", "--all", "--path", "/Photos"]).is_err());
        assert!(parse(&["rescan", "--all"]).is_ok());
        assert!(parse(&["rescan", "alice", "--path", "Photos/2024"]).is_ok());
    }

    #[test]
    fn every_user_subcommand_parses() {
        for args in [
            &["user", "add", "alice", "--display-name", "Alice", "--admin"][..],
            &["user", "list"],
            &["user", "delete", "alice"],
            &["user", "set-password", "alice", "--password-stdin"],
            &["user", "enable", "alice"],
            &["user", "disable", "alice"],
            &["app-password", "list", "alice"],
            &["app-password", "delete", "alice", "7"],
        ] {
            assert!(parse(args).is_ok(), "{args:?}");
        }
    }
}
