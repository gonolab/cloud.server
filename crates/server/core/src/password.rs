//! Web login passwords.
//!
//! Every user has one web login password, chosen by the user. It is used **only** for Login
//! Flow v2 and the web admin UI, so the slow Argon2id hash is checked at most once per
//! interactive sign-in.
//!
//! Devices never use it: they authenticate with server-generated app passwords, which are
//! high-entropy random tokens stored as SHA-256 and looked up with a single indexed equality
//! match (`app_passwords.token_hash`).
//!
//! Plaintext passwords are carried in [`SecretString`], whose `Debug` output is redacted, so a
//! stray `?password` in a log statement cannot leak them.

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier},
};
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Error, Result};

/// Minimum length of a web login password, in characters.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// Maximum length of a web login password, in bytes. Bounds the hashing work per attempt.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Checks a new web login password against the password policy.
pub fn check_policy(password: &SecretString) -> Result<()> {
    let password = password.expose_secret();
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::InvalidPassword("must be at least 8 characters long"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Error::InvalidPassword("must be at most 1024 bytes long"));
    }
    if password.chars().any(char::is_control) {
        return Err(Error::InvalidPassword(
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// Hashes a web login password with Argon2id and a random salt.
///
/// Returns the PHC string stored in `users.password_hash`. This is deliberately slow; call it
/// from a blocking context (for example `tokio::task::spawn_blocking`) inside the server.
pub fn hash(password: &SecretString) -> Result<String> {
    Argon2::default()
        .hash_password(password.expose_secret().as_bytes())
        .map(|hash| hash.to_string())
        .map_err(Error::PasswordHash)
}

/// Checks `password` against a PHC string produced by [`hash`].
///
/// Returns `Ok(false)` for a wrong password and an error only if `phc` is malformed.
pub fn verify(password: &SecretString, phc: &str) -> Result<bool> {
    match Argon2::default().verify_password(password.expose_secret().as_bytes(), phc) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(err) => Err(Error::PasswordHash(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    #[test]
    fn hash_and_verify_round_trip() {
        let phc = hash(&secret("correct horse")).unwrap();
        assert!(phc.starts_with("$argon2id$"), "{phc}");
        assert!(!phc.contains("correct horse"));
        assert!(verify(&secret("correct horse"), &phc).unwrap());
        assert!(!verify(&secret("wrong horse"), &phc).unwrap());
    }

    #[test]
    fn hashes_are_salted() {
        let password = secret("correct horse");
        assert_ne!(hash(&password).unwrap(), hash(&password).unwrap());
    }

    #[test]
    fn malformed_hashes_are_errors() {
        assert!(verify(&secret("correct horse"), "not a phc string").is_err());
    }

    #[test]
    fn policy_rejects_weak_or_odd_passwords() {
        assert!(check_policy(&secret("12345678")).is_ok());
        assert!(
            check_policy(&secret("pässwörd")).is_ok(),
            "counts characters, not bytes"
        );
        assert!(check_policy(&secret("1234567")).is_err());
        assert!(check_policy(&secret("")).is_err());
        assert!(check_policy(&secret("line\nbreak")).is_err());
        assert!(check_policy(&secret(&"x".repeat(MAX_PASSWORD_BYTES + 1))).is_err());
    }

    #[test]
    fn errors_never_contain_the_password() {
        let err = check_policy(&secret("short")).unwrap_err();
        assert!(!format!("{err} {err:?}").contains("short"));
    }
}
