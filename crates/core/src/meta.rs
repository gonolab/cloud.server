//! Rules for path-keyed metadata.
//!
//! File metadata lives in the `files` table and the tables keyed by it (`dead_props`,
//! `change_log`). [`MetaStore`] (in [`store`]) is the **only** code that writes to them: every
//! WebDAV operation becomes exactly one `BEGIN IMMEDIATE` transaction (see
//! [`crate::db::begin_immediate`]), and every change bumps the ETag and adjusts the recursive
//! size (`oc:size`) of all ancestor collections inside that same transaction. Each change is
//! logged in `change_log` and, after the commit, published as a [`ChangeEvent`] (see
//! [`changes`]).
//!
//! # `rel_path` format
//!
//! A `rel_path` is relative to the owner's root: no leading or trailing slash, components
//! separated by `/`, and the empty string for the root itself (`""`, `"Photos"`,
//! `"Photos/2024/a.jpg"`).
//!
//! # Comparison rules
//!
//! - `rel_path` columns use `BINARY` collation. Paths compare byte-for-byte: `Foo` and `foo`
//!   are different files, exactly like on the underlying file system.
//! - Subtree ("prefix") queries use a half-open range, **never `LIKE`**:
//!
//!   ```sql
//!   rel_path >= 'a/' AND rel_path < 'a0'
//!   ```
//!
//!   `'0'` is the byte after `'/'`, so the range holds exactly the paths that start with `a/`.
//!   `LIKE` would treat `_` and `%` in file names as wildcards and, in SQLite, compares ASCII
//!   case-insensitively, so it silently matches unrelated rows. The range form also uses the
//!   `(owner_id, rel_path)` index. [`descendant_bounds`] computes the two bounds.

pub mod changes;
mod store;

pub use changes::{ChangeEvent, ChangeOperation, ChangeSink};
pub use store::{DeadProp, DiskStat, FileRow, MetaStore, PropChange, derived_file_etag};

/// Returns the `[lower, upper)` bounds that select every strict descendant of `dir`.
///
/// Use them as `rel_path >= lower AND rel_path < upper`. Returns `None` for the root (`""`):
/// every other path of the owner is a descendant, so filter with `rel_path <> ''` instead.
///
/// This works for any UTF-8 path because `'/'` (0x2F) never occurs inside a multi-byte UTF-8
/// sequence and `'0'` (0x30) is the next byte value.
pub fn descendant_bounds(dir: &str) -> Option<(String, String)> {
    debug_assert!(
        !dir.starts_with('/') && !dir.ends_with('/'),
        "rel_path must not have leading or trailing slashes: {dir:?}"
    );
    if dir.is_empty() {
        return None;
    }
    Some((format!("{dir}/"), format!("{dir}0")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_select_only_descendants() {
        let (lower, upper) = descendant_bounds("a").unwrap();
        assert_eq!((lower.as_str(), upper.as_str()), ("a/", "a0"));

        let inside = |path: &str| path >= lower.as_str() && path < upper.as_str();
        for path in ["a/b", "a/b/c", "a/_", "a/%", "a/\u{1F600}"] {
            assert!(inside(path), "{path:?} is a descendant of \"a\"");
        }
        for path in ["a", "a0", "a.b", "a_b", "a%", "ab", "A/b", "b/a", ""] {
            assert!(!inside(path), "{path:?} is not a descendant of \"a\"");
        }
    }

    #[test]
    fn root_has_no_bounds() {
        assert_eq!(descendant_bounds(""), None);
    }
}
