//! Random tokens and their digests.
//!
//! Every secret the server hands out (app passwords, session cookies, Login Flow tokens) is a
//! high-entropy random token. Only its SHA-256 [`digest`] is stored, so a lookup is a single
//! indexed equality match and a leaked database does not reveal usable credentials. A fast
//! hash is enough because the tokens cannot be guessed.

use rand::RngExt as _;
use secrecy::SecretString;
use sha2::{Digest, Sha256};

/// Characters of [`random_token`].
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A random token of `len` characters from `[A-Za-z0-9]` (5.95 bits per character).
pub fn random_token(len: usize) -> SecretString {
    let mut rng = rand::rng();
    let token: String = (0..len)
        .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
        .collect();
    SecretString::from(token)
}

/// SHA-256 of a token, the form in which tokens are stored.
pub fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Compares two byte strings in time that depends only on their lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;

    #[test]
    fn tokens_are_random_alphanumerics() {
        let a = random_token(43);
        let b = random_token(43);
        assert_eq!(a.expose_secret().len(), 43);
        assert!(a.expose_secret().bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(digest("a"), digest("b"));
    }

    #[test]
    fn comparison() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
