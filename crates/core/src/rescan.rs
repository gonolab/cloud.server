//! The file system side of `gono-cloud rescan`: walk a user's tree as it is on disk.
//!
//! [`walk`] lists a directory tree the way the WebDAV layer sees it, so that
//! [`MetaStore::reconcile`](crate::meta::MetaStore::reconcile) can bring the metadata in line:
//!
//! - **Symbolic links and special files** are skipped (WebDAV treats them as missing).
//! - **Names that are not NFC** (from changes made behind the server's back, typically on
//!   macOS) are renamed to their NFC form, so clients can see them. A rename never replaces
//!   anything: when another entry already has the NFC name (or a name the file system treats
//!   as the same), the entry is reported as a conflict and left alone, including what is below
//!   it. Names that cannot become valid at all (not UTF-8, too long, ...) are reported and
//!   skipped.
//! - A **dry run** renames nothing but reports the entries under the names they would get.
//! - An unreadable directory aborts the walk: reconciling without its content would remove the
//!   metadata of everything inside it.

use std::{collections::HashSet, ffi::OsString, fs, io, path::Path};

use crate::{
    error::{Error, Result},
    meta::DiskStat,
    path::{MAX_SEGMENT_BYTES, RelPath, disk_segment, normalize_segment},
    storage::lstat_beneath,
};

/// What [`walk`] found.
#[derive(Debug, Clone, Default)]
pub struct Walk {
    /// The strict ancestors of the scope that exist as directories, from the root down.
    pub ancestors: Vec<(RelPath, DiskStat)>,
    /// Whether the scope exists (as a directory or a file).
    pub scope_exists: bool,
    /// The scope and everything below it, parents before children.
    pub entries: Vec<(RelPath, DiskStat)>,
    /// Entries renamed to NFC (or that would be, in a dry run), under their new path.
    pub renamed: Vec<RelPath>,
    /// Entries left alone because their NFC name is taken.
    pub conflicts: Vec<Conflict>,
    /// Entries WebDAV cannot show and rescan cannot fix.
    pub skipped: Vec<Skipped>,
}

impl Walk {
    /// Number of directories among the entries.
    pub fn dirs(&self) -> usize {
        self.entries.iter().filter(|(_, stat)| stat.is_dir).count()
    }

    /// Number of files among the entries.
    pub fn files(&self) -> usize {
        self.entries.len() - self.dirs()
    }
}

/// A non-NFC name whose NFC form is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The name's NFC form, at the place it would take.
    pub path: RelPath,
}

/// Why an entry was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// A symbolic link.
    Symlink,
    /// A socket, FIFO or device.
    Special,
    /// A name that is not valid UTF-8.
    NotUtf8,
    /// A name that is not a valid path segment even in NFC.
    InvalidName,
}

impl SkipReason {
    /// A short description for reports.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Symlink => "symbolic link",
            Self::Special => "not a regular file or directory",
            Self::NotUtf8 => "name is not valid UTF-8",
            Self::InvalidName => "name cannot be used in a path",
        }
    }
}

/// An entry WebDAV cannot show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The directory holding it.
    pub dir: RelPath,
    /// The name as found on disk (lossy).
    pub name: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

fn io_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Walks `scope` below the user tree `root` (see the module documentation).
pub fn walk(root: &Path, scope: &RelPath, dry_run: bool) -> Result<Walk> {
    let mut walk = Walk::default();
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(io_error(root, io::ErrorKind::NotADirectory.into())),
        Err(err) => return Err(io_error(root, err)),
    }
    for ancestor in scope.ancestors() {
        match lstat_beneath(root, &ancestor).map_err(|err| io_error(root, err))? {
            Some(meta) if meta.is_dir() => {
                walk.ancestors
                    .push((ancestor, DiskStat::from_metadata(&meta)));
            }
            _ => return Ok(walk),
        }
    }
    let Some(meta) = lstat_beneath(root, scope).map_err(|err| io_error(root, err))? else {
        return Ok(walk);
    };
    walk.scope_exists = true;
    walk.entries
        .push((scope.clone(), DiskStat::from_metadata(&meta)));
    if meta.is_dir() {
        walk_dir(&scope.to_fs_path(root), scope, dry_run, &mut walk)?;
    }
    Ok(walk)
}

/// How a name read from disk can be used.
enum Name {
    /// Already a valid NFC segment.
    Valid(String),
    /// Valid once normalized to NFC.
    Normalize(String),
    /// Unusable.
    Invalid(SkipReason),
}

fn classify(name: &std::ffi::OsStr) -> Name {
    if let Some(valid) = disk_segment(name) {
        return Name::Valid(valid.to_owned());
    }
    let Some(text) = name.to_str() else {
        return Name::Invalid(SkipReason::NotUtf8);
    };
    match normalize_segment(text.as_bytes()) {
        Ok(nfc) if nfc != text && nfc.len() <= MAX_SEGMENT_BYTES => Name::Normalize(nfc),
        _ => Name::Invalid(SkipReason::InvalidName),
    }
}

fn walk_dir(dir: &Path, rel: &RelPath, dry_run: bool, walk: &mut Walk) -> Result<()> {
    let mut items: Vec<(OsString, fs::Metadata)> = Vec::new();
    for item in fs::read_dir(dir).map_err(|err| io_error(dir, err))? {
        let item = item.map_err(|err| io_error(dir, err))?;
        let path = item.path();
        match fs::symlink_metadata(&path) {
            Ok(meta) => items.push((item.file_name(), meta)),
            // Removed while we were looking.
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(io_error(&path, err)),
        }
    }
    items.sort_by(|(a, _), (b, _)| a.cmp(b));

    // Names that are taken as they are; NFC renames must not land on them.
    let mut taken: HashSet<String> = items
        .iter()
        .filter_map(|(name, _)| disk_segment(name).map(str::to_owned))
        .collect();

    for (raw, meta) in items {
        let kind = meta.file_type();
        let skip = |reason| Skipped {
            dir: rel.clone(),
            name: raw.to_string_lossy().into_owned(),
            reason,
        };
        if kind.is_symlink() {
            walk.skipped.push(skip(SkipReason::Symlink));
            continue;
        }
        if !kind.is_dir() && !kind.is_file() {
            walk.skipped.push(skip(SkipReason::Special));
            continue;
        }
        let (name, on_disk) = match classify(&raw) {
            Name::Valid(name) => (name, dir.join(&raw)),
            Name::Invalid(reason) => {
                walk.skipped.push(skip(reason));
                continue;
            }
            Name::Normalize(nfc) => {
                let from = dir.join(&raw);
                let to = dir.join(&nfc);
                if taken.contains(&nfc) || !rename_to_nfc(&from, &to, &meta, dry_run)? {
                    walk.conflicts.push(Conflict {
                        path: rel.join(&nfc),
                    });
                    continue;
                }
                taken.insert(nfc.clone());
                walk.renamed.push(rel.join(&nfc));
                (nfc, if dry_run { from } else { to })
            }
        };
        let child = rel.join(&name);
        let meta = if on_disk == dir.join(&raw) {
            meta
        } else {
            fs::symlink_metadata(&on_disk).map_err(|err| io_error(&on_disk, err))?
        };
        walk.entries
            .push((child.clone(), DiskStat::from_metadata(&meta)));
        if meta.is_dir() {
            walk_dir(&on_disk, &child, dry_run, walk)?;
        }
    }
    Ok(())
}

/// Renames `from` to its NFC form `to` unless `to` names another entry. Returns `false` for a
/// conflict. In a dry run, only checks.
fn rename_to_nfc(from: &Path, to: &Path, meta: &fs::Metadata, dry_run: bool) -> Result<bool> {
    // On file systems that ignore normalization (APFS) or case, `to` may already name `from`
    // itself, or a different entry that the file system considers equal.
    match fs::symlink_metadata(to) {
        Ok(existing) if same_file(&existing, meta) => {
            if !dry_run {
                fs::rename(from, to).map_err(|err| io_error(from, err))?;
            }
            return Ok(true);
        }
        Ok(_) => return Ok(false),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_error(to, err)),
    }
    if dry_run {
        return Ok(true);
    }
    match rename_no_replace(from, to) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(io_error(from, err)),
    }
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    false
}

/// Renames without ever replacing an existing entry: `renameat2(RENAME_NOREPLACE)` on Linux,
/// `renamex_np(RENAME_EXCL)` on macOS. Where the file system does not support that, a check
/// right before a plain rename has to do.
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(()),
            Err(errno)
                if errno != rustix::io::Errno::INVAL && errno != rustix::io::Errno::NOSYS =>
            {
                return Err(errno.into());
            }
            Err(_) => {}
        }
    }
    if fs::symlink_metadata(to).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    fs::rename(from, to)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NFD: &str = "Cafe\u{301}";
    const NFC: &str = "Caf\u{e9}";

    fn names(walk: &Walk) -> Vec<&str> {
        walk.entries.iter().map(|(rel, _)| rel.as_str()).collect()
    }

    #[test]
    fn lists_the_tree_parents_first_and_skips_what_webdav_hides() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/f.txt"), b"12345").unwrap();
        fs::write(root.join("top.txt"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("top.txt"), root.join("a/link")).unwrap();

        let walk = walk(root, &RelPath::root(), false).unwrap();
        assert!(walk.scope_exists);
        assert_eq!(names(&walk), ["", "a", "a/b", "a/b/f.txt", "top.txt"]);
        assert_eq!((walk.dirs(), walk.files()), (3, 2));
        assert_eq!(walk.entries[3].1.size, 5);
        #[cfg(unix)]
        assert_eq!(walk.skipped[0].reason, SkipReason::Symlink);

        let scoped = super::walk(root, &RelPath::parse("a/b").unwrap(), false).unwrap();
        let ancestors: Vec<&str> = scoped
            .ancestors
            .iter()
            .map(|(rel, _)| rel.as_str())
            .collect();
        assert_eq!(ancestors, ["", "a"]);
        assert_eq!(names(&scoped), ["a/b", "a/b/f.txt"]);

        let missing = super::walk(root, &RelPath::parse("a/gone").unwrap(), false).unwrap();
        assert!(!missing.scope_exists);
        assert!(missing.entries.is_empty());
    }

    #[test]
    fn non_nfc_names_are_renamed_unless_taken() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join(NFD)).unwrap();
        fs::write(root.join(NFD).join("inner.txt"), b"x").unwrap();
        // Whether the file system keeps both spellings apart decides what can happen.
        let distinct = fs::write(root.join("probe-\u{e9}"), b"").is_ok()
            && !root.join("probe-e\u{301}").exists();

        let dry = walk(root, &RelPath::root(), true).unwrap();
        assert_eq!(dry.renamed, [RelPath::parse(NFC).unwrap()]);
        assert!(names(&dry).contains(&format!("{NFC}/inner.txt").as_str()));
        assert!(
            fs::read_dir(root)
                .unwrap()
                .any(|item| item.unwrap().file_name() == NFD),
            "a dry run renames nothing"
        );

        let done = walk(root, &RelPath::root(), false).unwrap();
        assert_eq!(done.renamed, [RelPath::parse(NFC).unwrap()]);
        assert!(names(&done).contains(&format!("{NFC}/inner.txt").as_str()));
        assert!(root.join(NFC).join("inner.txt").exists());

        if distinct {
            // Another file already has the NFC name: report it, touch nothing.
            fs::write(root.join("Nai\u{308}ve"), b"decomposed").unwrap();
            fs::write(root.join("Na\u{ef}ve"), b"composed").unwrap();
            let conflict = walk(root, &RelPath::root(), false).unwrap();
            assert_eq!(conflict.conflicts.len(), 1);
            assert_eq!(fs::read(root.join("Nai\u{308}ve")).unwrap(), b"decomposed");
            assert_eq!(fs::read(root.join("Na\u{ef}ve")).unwrap(), b"composed");
        }
    }
}
