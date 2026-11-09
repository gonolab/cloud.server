//! Storage paths.
//!
//! A [`RelPath`] names a file or directory inside one user's storage tree, relative to that
//! user's files root (see [`crate::storage`]). It is the form used for every `rel_path` column
//! and every file system access below the data directory, so all validation happens once, when
//! a [`RelPath`] is built:
//!
//! - Segments are valid UTF-8 in Unicode **NFC**. Clients on macOS send decomposed (NFD) names,
//!   Windows and Linux clients send composed (NFC) names; normalizing every incoming segment
//!   means both spellings address the same file and the same metadata row. Names on disk that
//!   are not NFC can only come from changes made behind the server's back; they are skipped in
//!   listings until `gono-cloud rescan` renames them.
//! - Segments are never empty, `.` or `..`, and contain neither `/` nor NUL, so a [`RelPath`]
//!   can be joined onto a root directory without escaping it lexically. (Symbolic links are a
//!   separate concern, handled by the code that touches the file system.)
//! - Segments are at most [`MAX_SEGMENT_BYTES`] bytes long, the limit of common file systems.
//!
//! The textual form has no leading or trailing slash and is `""` for the root, matching the
//! `rel_path` convention described in [`crate::meta`].

use std::{
    fmt,
    path::{Path, PathBuf},
};

use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};

/// Longest accepted path segment, in bytes (after NFC normalization).
pub const MAX_SEGMENT_BYTES: usize = 255;

/// Why a path segment was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The segment is not valid UTF-8.
    #[error("path segment is not valid UTF-8")]
    NotUtf8,
    /// The segment contains a NUL byte.
    #[error("path segment contains a NUL byte")]
    Nul,
    /// The segment contains `/` (for example from a percent-encoded `%2F`).
    #[error("path segment contains a slash")]
    Slash,
    /// The segment is `.` or `..`.
    #[error("path segment is a dot segment")]
    DotSegment,
    /// The segment is empty.
    #[error("path segment is empty")]
    Empty,
    /// The segment is longer than [`MAX_SEGMENT_BYTES`].
    #[error("path segment is longer than 255 bytes")]
    TooLong,
}

/// Validates one raw (already percent-decoded) path segment and returns it in NFC.
pub fn normalize_segment(raw: &[u8]) -> Result<String, PathError> {
    let segment = std::str::from_utf8(raw).map_err(|_| PathError::NotUtf8)?;
    check_segment_chars(segment)?;
    let segment = to_nfc(segment);
    check_segment_length(&segment)?;
    Ok(segment)
}

/// Checks a name read from disk: it must already be a valid, NFC-normalized segment.
///
/// Returns `None` for names a client could never address through [`normalize_segment`], so
/// that listings do not show entries that cannot be opened.
pub fn disk_segment(name: &std::ffi::OsStr) -> Option<&str> {
    let name = name.to_str()?;
    check_segment_chars(name).ok()?;
    check_segment_length(name).ok()?;
    is_nfc(name).then_some(name)
}

/// Whether `value` is in Unicode Normalization Form C.
pub fn is_nfc(value: &str) -> bool {
    match is_nfc_quick(value.chars()) {
        IsNormalized::Yes => true,
        IsNormalized::No => false,
        IsNormalized::Maybe => value.nfc().eq(value.chars()),
    }
}

fn to_nfc(value: &str) -> String {
    if is_nfc(value) {
        value.to_owned()
    } else {
        value.nfc().collect()
    }
}

fn check_segment_chars(segment: &str) -> Result<(), PathError> {
    match segment {
        "" => Err(PathError::Empty),
        "." | ".." => Err(PathError::DotSegment),
        _ if segment.contains('\0') => Err(PathError::Nul),
        _ if segment.contains('/') => Err(PathError::Slash),
        _ => Ok(()),
    }
}

fn check_segment_length(segment: &str) -> Result<(), PathError> {
    if segment.len() > MAX_SEGMENT_BYTES {
        Err(PathError::TooLong)
    } else {
        Ok(())
    }
}

/// A validated path inside one user's storage tree. See the [module documentation](self).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelPath(String);

impl RelPath {
    /// The root of the tree (`""`).
    pub const fn root() -> Self {
        Self(String::new())
    }

    /// Builds a path from raw segments, validating and normalizing each one.
    ///
    /// Empty segments (from doubled or trailing slashes) are skipped.
    pub fn from_raw_segments<'a>(
        segments: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, PathError> {
        let mut path = Self::root();
        for raw in segments {
            if raw.is_empty() {
                continue;
            }
            path.push_normalized(&normalize_segment(raw)?);
        }
        Ok(path)
    }

    /// Parses a slash-separated path such as `"/Photos/2024"` or `"Photos/2024/"`.
    ///
    /// Leading, trailing and doubled slashes are ignored; every segment is validated and
    /// normalized like [`RelPath::from_raw_segments`].
    pub fn parse(value: &str) -> Result<Self, PathError> {
        Self::from_raw_segments(value.split('/').map(str::as_bytes))
    }

    /// Wraps a value read from a `rel_path` column. Such values were validated on the way in.
    pub fn from_db(value: String) -> Self {
        debug_assert!(
            !value.starts_with('/') && !value.ends_with('/'),
            "rel_path must not have leading or trailing slashes: {value:?}"
        );
        Self(value)
    }

    /// The textual form: no leading or trailing slash, `""` for the root.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the root of the tree.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The segments from the root down.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|segment| !segment.is_empty())
    }

    /// The last segment, or `None` for the root.
    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            None
        } else {
            self.0.rsplit('/').next()
        }
    }

    /// The parent directory, or `None` for the root.
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.rfind('/') {
            Some(index) => Self(self.0[..index].to_owned()),
            None => Self::root(),
        })
    }

    /// Every strict ancestor, from the root down to the parent. Empty for the root.
    pub fn ancestors(&self) -> Vec<Self> {
        let mut ancestors = Vec::new();
        let mut current = self.parent();
        while let Some(path) = current {
            current = path.parent();
            ancestors.push(path);
        }
        ancestors.reverse();
        ancestors
    }

    /// Appends one segment that has already passed [`normalize_segment`] or [`disk_segment`].
    pub fn join(&self, segment: &str) -> Self {
        let mut path = self.clone();
        path.push_normalized(segment);
        path
    }

    /// Appends every segment of `other`.
    pub fn join_path(&self, other: &Self) -> Self {
        if other.is_root() {
            return self.clone();
        }
        if self.is_root() {
            return other.clone();
        }
        Self(format!("{}/{}", self.0, other.0))
    }

    /// Whether `self` is `prefix` or lies below it (segment-wise, so `ab` is not below `a`).
    pub fn starts_with(&self, prefix: &Self) -> bool {
        self.strip_prefix(prefix).is_some()
    }

    /// The part of `self` below `prefix`, or `None` if `self` is not `prefix` or below it.
    pub fn strip_prefix(&self, prefix: &Self) -> Option<Self> {
        if prefix.is_root() {
            return Some(self.clone());
        }
        let rest = self.0.strip_prefix(prefix.as_str())?;
        if rest.is_empty() {
            Some(Self::root())
        } else {
            rest.strip_prefix('/').map(|rest| Self(rest.to_owned()))
        }
    }

    /// The location of this path below `root` on disk.
    pub fn to_fs_path(&self, root: &Path) -> PathBuf {
        let mut path = root.to_path_buf();
        for segment in self.segments() {
            path.push(segment);
        }
        path
    }

    fn push_normalized(&mut self, segment: &str) {
        debug_assert!(normalize_segment(segment.as_bytes()).as_deref() == Ok(segment));
        if !self.0.is_empty() {
            self.0.push('/');
        }
        self.0.push_str(segment);
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NFD_E_ACUTE: &str = "e\u{301}";
    const NFC_E_ACUTE: &str = "\u{e9}";

    #[test]
    fn segments_are_normalized_to_nfc() {
        let nfd = format!("caf{NFD_E_ACUTE}.txt");
        let nfc = format!("caf{NFC_E_ACUTE}.txt");
        assert_eq!(normalize_segment(nfd.as_bytes()).unwrap(), nfc);
        assert_eq!(normalize_segment(nfc.as_bytes()).unwrap(), nfc);
        assert!(is_nfc(&nfc));
        assert!(!is_nfc(&nfd));
    }

    #[test]
    fn dangerous_segments_are_rejected() {
        for (raw, error) in [
            (&b""[..], PathError::Empty),
            (b".", PathError::DotSegment),
            (b"..", PathError::DotSegment),
            (b"a\0b", PathError::Nul),
            (b"a/b", PathError::Slash),
            (b"\xff\xfe", PathError::NotUtf8),
        ] {
            assert_eq!(normalize_segment(raw), Err(error), "{raw:?}");
        }
        assert_eq!(
            normalize_segment("x".repeat(256).as_bytes()),
            Err(PathError::TooLong)
        );
        assert!(normalize_segment("x".repeat(255).as_bytes()).is_ok());
        for fine in [
            "...",
            ".hidden",
            "a..b",
            "space name",
            "100%",
            "under_score",
        ] {
            assert_eq!(normalize_segment(fine.as_bytes()).unwrap(), fine);
        }
    }

    #[test]
    fn disk_names_must_already_be_valid_nfc() {
        use std::ffi::OsStr;
        assert_eq!(disk_segment(OsStr::new("ok.txt")), Some("ok.txt"));
        assert_eq!(disk_segment(OsStr::new(NFC_E_ACUTE)), Some(NFC_E_ACUTE));
        assert_eq!(disk_segment(OsStr::new(NFD_E_ACUTE)), None);
        assert_eq!(disk_segment(OsStr::new("..")), None);
    }

    #[test]
    fn parse_ignores_redundant_slashes() {
        let path = RelPath::parse("//Photos///2024/").unwrap();
        assert_eq!(path.as_str(), "Photos/2024");
        assert_eq!(path.to_string(), "/Photos/2024");
        assert!(RelPath::parse("/").unwrap().is_root());
        assert!(RelPath::parse("").unwrap().is_root());
        assert!(RelPath::parse("a/../b").is_err());
    }

    #[test]
    fn navigation() {
        let path = RelPath::parse("a/b/c.txt").unwrap();
        assert_eq!(path.file_name(), Some("c.txt"));
        assert_eq!(path.parent().unwrap().as_str(), "a/b");
        let ancestors: Vec<String> = path.ancestors().iter().map(|p| p.0.clone()).collect();
        assert_eq!(ancestors, ["", "a", "a/b"]);
        assert!(RelPath::root().ancestors().is_empty());
        assert_eq!(RelPath::root().parent(), None);
        assert_eq!(RelPath::root().join("x").as_str(), "x");
        assert_eq!(
            RelPath::parse("a").unwrap().join_path(&path).as_str(),
            "a/a/b/c.txt"
        );
    }

    #[test]
    fn prefixes_compare_whole_segments() {
        let a = RelPath::parse("a").unwrap();
        let ab = RelPath::parse("ab").unwrap();
        let a_b = RelPath::parse("a/b").unwrap();
        assert!(a_b.starts_with(&a));
        assert!(a.starts_with(&a));
        assert!(!ab.starts_with(&a));
        assert!(a.starts_with(&RelPath::root()));
        assert_eq!(a_b.strip_prefix(&a).unwrap().as_str(), "b");
        assert!(a.strip_prefix(&a).unwrap().is_root());
        assert_eq!(ab.strip_prefix(&a), None);
    }

    #[test]
    fn fs_paths_stay_below_the_root() {
        let root = Path::new("/srv/data/files/7");
        let path = RelPath::parse("a/b").unwrap();
        assert_eq!(path.to_fs_path(root), Path::new("/srv/data/files/7/a/b"));
        assert_eq!(RelPath::root().to_fs_path(root), root);
    }
}
