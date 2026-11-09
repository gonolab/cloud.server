//! Validated domain types.

use std::{fmt, str::FromStr};

use crate::error::Error;

/// Maximum length of a username in bytes.
pub const MAX_USERNAME_LEN: usize = 64;

/// A validated account name.
///
/// Usernames appear verbatim in WebDAV URLs (`/remote.php/dav/files/<username>/`) and in the
/// database, so they are restricted to a small, unambiguous character set:
///
/// - 1 to [`MAX_USERNAME_LEN`] bytes,
/// - lowercase ASCII letters, digits, `.`, `_`, `-` and `@`,
/// - starting with a letter or a digit.
///
/// Uppercase letters are rejected instead of folded so that the stored name, the URL and the
/// login name are always byte-for-byte identical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Username(String);

impl Username {
    /// Validates `value` and wraps it.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if let Err(reason) = Self::check(&value) {
            return Err(Error::InvalidUsername {
                username: value,
                reason,
            });
        }
        Ok(Self(value))
    }

    /// Returns the name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn check(value: &str) -> Result<(), &'static str> {
        if value.is_empty() {
            return Err("must not be empty");
        }
        if value.len() > MAX_USERNAME_LEN {
            return Err("must be at most 64 characters long");
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-@".contains(&b))
        {
            return Err("may only contain lowercase letters, digits, '.', '_', '-' and '@'");
        }
        if !value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err("must start with a lowercase letter or a digit");
        }
        Ok(())
    }
}

impl FromStr for Username {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Access level of an app password scope.
///
/// Stored as `'view'` or `'full'` in `app_password_scopes.permission`; the schema enforces the
/// same two values with a `CHECK` constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read-only access: listing and downloading.
    View,
    /// Read and write access.
    Full,
}

impl Permission {
    /// The value stored in the database and accepted on the command line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Full => "full",
        }
    }
}

impl FromStr for Permission {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "view" => Ok(Self::View),
            "full" => Ok(Self::Full),
            other => Err(Error::InvalidPermission(other.to_owned())),
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_usernames() {
        for name in [
            "alice",
            "a",
            "bob.smith",
            "carol_1",
            "dave-2",
            "eve@example.com",
            "9lives",
        ] {
            assert_eq!(Username::new(name).expect(name).as_str(), name);
        }
        let longest = "a".repeat(MAX_USERNAME_LEN);
        assert!(Username::new(longest).is_ok());
    }

    #[test]
    fn rejects_invalid_usernames() {
        let too_long = "a".repeat(MAX_USERNAME_LEN + 1);
        for name in [
            "", "Alice", ".hidden", "-dash", "_under", "@at", "a b", "a/b", "..", "é", &too_long,
        ] {
            assert!(Username::new(name).is_err(), "{name:?} should be rejected");
        }
    }

    #[test]
    fn permission_round_trips() {
        for permission in [Permission::View, Permission::Full] {
            assert_eq!(
                permission.as_str().parse::<Permission>().ok(),
                Some(permission)
            );
        }
        assert!("admin".parse::<Permission>().is_err());
        assert!("VIEW".parse::<Permission>().is_err());
    }
}
