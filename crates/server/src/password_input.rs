//! Reading a new web login password from the operator.
//!
//! The password comes from an interactive prompt (input is not echoed) or, with
//! `--password-stdin`, from the first line of standard input. It is never taken from a command
//! line argument or an environment variable, and it is never printed or logged.

use std::io::{self, BufRead, IsTerminal};

use anyhow::{Context, bail};
use gono_core::{Username, password};
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroize};

use crate::cli::PasswordSource;

/// Reads a new web login password for `username` and checks it against the password policy.
///
/// Blocks on terminal or stdin I/O; call it from a blocking context.
pub fn read_new_password(
    source: PasswordSource,
    username: &Username,
) -> anyhow::Result<SecretString> {
    let password = if source.password_stdin {
        read_from_stdin()?
    } else if io::stdin().is_terminal() {
        prompt_twice(username)?
    } else {
        bail!(
            "standard input is not a terminal; pass --password-stdin to read the password from it"
        );
    };
    password::check_policy(&password)?;
    Ok(password)
}

fn read_from_stdin() -> anyhow::Result<SecretString> {
    let mut line = String::new();
    let read = io::stdin()
        .lock()
        .read_line(&mut line)
        .context("read password from standard input")?;
    if read == 0 {
        bail!("no password received on standard input");
    }
    let trimmed = line
        .strip_suffix('\n')
        .map(|rest| rest.strip_suffix('\r').unwrap_or(rest))
        .unwrap_or(&line);
    let password = SecretString::from(trimmed);
    line.zeroize();
    Ok(password)
}

fn prompt_twice(username: &Username) -> anyhow::Result<SecretString> {
    let first = prompt(&format!("Web login password for {username}: "))?;
    let second = prompt("Repeat the password: ")?;
    if first.expose_secret() != second.expose_secret() {
        bail!("the passwords do not match");
    }
    Ok(first)
}

/// Prompts on the controlling terminal without echo.
fn prompt(message: &str) -> anyhow::Result<SecretString> {
    let mut input =
        rpassword::prompt_password(message).context("read password from the terminal")?;
    let password = SecretString::from(input.as_str());
    // Wipe the plaintext copy that `SecretString` does not own.
    input.zeroize();
    Ok(password)
}
