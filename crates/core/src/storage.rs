//! Layout of the data directory (`storage.data_dir`).
//!
//! ```text
//! <data_dir>/
//!   files/<user id>/     the user's file tree, served as their WebDAV root
//!   uploads/<user id>/   staging area of Nextcloud chunked uploads, one directory per
//!                        session (see [`DataLayout::upload_session_dir`])
//!   tmp/                 partial files of PUT requests in progress; emptied at startup
//!   deleted/             trees of deleted users, moved here by `user delete`
//! ```
//!
//! - Per-user directories are named by the numeric user id, not the username, so that renaming
//!   a user never has to move data.
//! - `files/`, `uploads/` and `tmp/` must live on the same file system: uploads are finished
//!   with an atomic `rename(2)` from `tmp/` or `uploads/` into `files/`, which fails across
//!   file systems. [`DataLayout::open`] and [`DataLayout::create_user`] check this.
//! - SQLite reuses the highest user id after that user is deleted. `user delete` therefore
//!   moves the user's directories to `deleted/`, and [`DataLayout::create_user`] refuses to
//!   adopt a non-empty leftover directory, so a new account never sees an old account's files.
//! - Directories are created with mode `0700` on Unix.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::{
    error::{Error, Result},
    path::RelPath,
};

/// Paths of the data directory. Cheap to clone.
#[derive(Debug, Clone)]
pub struct DataLayout {
    root: PathBuf,
}

impl DataLayout {
    /// Describes the layout below `data_dir`. Does not touch the file system.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: data_dir.into(),
        }
    }

    /// The data directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Parent of all user file trees.
    pub fn files_root(&self) -> PathBuf {
        self.root.join("files")
    }

    /// Parent of all chunked upload staging directories.
    pub fn uploads_root(&self) -> PathBuf {
        self.root.join("uploads")
    }

    /// Directory for partial files of PUT requests.
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Directory that receives the trees of deleted users.
    pub fn deleted_root(&self) -> PathBuf {
        self.root.join("deleted")
    }

    /// Root of one user's file tree.
    pub fn user_files(&self, user_id: i64) -> PathBuf {
        self.files_root().join(user_id.to_string())
    }

    /// One user's chunked upload staging directory.
    pub fn user_uploads(&self, user_id: i64) -> PathBuf {
        self.uploads_root().join(user_id.to_string())
    }

    /// Directory holding the chunks of one upload session: `uploads/<user id>/<digest>/`.
    ///
    /// Upload ids are chosen by clients, so the directory is named by the first 16 bytes of
    /// the SHA-256 of the id (32 hex digits) instead of the id itself: any id maps to a safe
    /// name, and ids that differ only in case stay apart on case-insensitive file systems.
    pub fn upload_session_dir(&self, user_id: i64, upload_id: &str) -> PathBuf {
        self.user_uploads(user_id)
            .join(upload_session_dir_name(upload_id))
    }

    /// Creates the data directory and its fixed subdirectories. Used by `init`; existing
    /// directories are kept.
    pub fn create(&self) -> Result<()> {
        for dir in [
            self.root.clone(),
            self.files_root(),
            self.uploads_root(),
            self.tmp_dir(),
            self.deleted_root(),
        ] {
            create_private_dir_all(&dir)?;
        }
        self.check_same_file_system(&[self.files_root(), self.uploads_root(), self.tmp_dir()])
    }

    /// Prepares an existing data directory for serving.
    ///
    /// Fails if the data directory does not exist (a typo in `storage.data_dir` must not start
    /// an empty installation), creates missing fixed subdirectories, checks that they share one
    /// file system, and removes partial files left in `tmp/` by an earlier crash.
    pub fn open(&self) -> Result<()> {
        if !self.root.is_dir() {
            return Err(Error::DataDirMissing {
                path: self.root.clone(),
            });
        }
        self.create()?;
        let tmp = self.tmp_dir();
        let entries = fs::read_dir(&tmp).map_err(|source| io_error(&tmp, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| io_error(&tmp, source))?;
            let path = entry.path();
            let result = match entry.file_type() {
                Ok(kind) if kind.is_dir() => fs::remove_dir_all(&path),
                _ => fs::remove_file(&path),
            };
            if let Err(err) = result {
                tracing::warn!(path = %path.display(), error = %err, "cannot remove stale temporary file");
            }
        }
        Ok(())
    }

    /// Creates the per-user directories of a new account.
    ///
    /// An existing but empty directory is accepted. A non-empty one is refused with
    /// [`Error::UserDirNotEmpty`]: it belongs to an earlier account with the same id.
    pub fn create_user(&self, user_id: i64) -> Result<()> {
        let files = self.user_files(user_id);
        let uploads = self.user_uploads(user_id);
        for dir in [&files, &uploads] {
            if is_non_empty_dir(dir)? {
                return Err(Error::UserDirNotEmpty { path: dir.clone() });
            }
        }
        self.ensure_user(user_id)
    }

    /// Creates the per-user directories if they are missing, keeping existing content.
    ///
    /// The server calls this on first access, so an account whose directories were not
    /// created (or were removed by an administrator) still works.
    pub fn ensure_user(&self, user_id: i64) -> Result<()> {
        let files = self.user_files(user_id);
        let uploads = self.user_uploads(user_id);
        create_private_dir_all(&files)?;
        create_private_dir_all(&uploads)?;
        self.check_same_file_system(&[files, uploads, self.tmp_dir()])
    }

    /// Moves the directories of a deleted account to `deleted/<id>-<username>-<unix time>/`.
    ///
    /// Returns the new location, or `None` if the account had no directories.
    pub fn retire_user(&self, user_id: i64, username: &str, now: i64) -> Result<Option<PathBuf>> {
        let files = self.user_files(user_id);
        let uploads = self.user_uploads(user_id);
        if !files.exists() && !uploads.exists() {
            return Ok(None);
        }
        let target = self
            .deleted_root()
            .join(format!("{user_id}-{username}-{now}"));
        create_private_dir_all(&target)?;
        for (source, name) in [(files, "files"), (uploads, "uploads")] {
            if source.exists() {
                let destination = target.join(name);
                fs::rename(&source, &destination).map_err(|err| io_error(&source, err))?;
            }
        }
        Ok(Some(target))
    }

    /// Whether the file system of the data directory treats names that differ only in case
    /// (`Report.pdf`, `report.pdf`) as the same name, like the default setups of macOS and
    /// Windows. Probes with a temporary file in `tmp/`.
    pub fn is_case_insensitive(&self) -> Result<bool> {
        let tmp = self.tmp_dir();
        let token = crate::secret::random_token(12);
        let upper = tmp.join(format!(
            "CaseProbe-{}",
            secrecy::ExposeSecret::expose_secret(&token)
        ));
        let lower = tmp.join(
            upper
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().to_lowercase()),
        );
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&upper)
            .map_err(|source| io_error(&upper, source))?;
        let insensitive = fs::symlink_metadata(&lower).is_ok();
        fs::remove_file(&upper).map_err(|source| io_error(&upper, source))?;
        Ok(insensitive)
    }

    /// Fails with [`Error::CrossDevice`] unless every path lies on the same file system.
    #[cfg(unix)]
    fn check_same_file_system(&self, paths: &[PathBuf]) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let mut first: Option<(&PathBuf, u64)> = None;
        for path in paths {
            let dev = fs::metadata(path)
                .map_err(|source| io_error(path, source))?
                .dev();
            match first {
                None => first = Some((path, dev)),
                Some((first_path, first_dev)) if first_dev != dev => {
                    return Err(Error::CrossDevice {
                        first: first_path.clone(),
                        second: path.clone(),
                    });
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_same_file_system(&self, _paths: &[PathBuf]) -> Result<()> {
        Ok(())
    }
}

fn io_error(path: &Path, source: io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn is_non_empty_dir(path: &Path) -> Result<bool> {
    match fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error(path, err)),
    }
}

/// Looks `rel` up below `root` without following symbolic links.
///
/// Every component is examined with `lstat(2)`. Returns `Ok(None)` when the path does not
/// exist, when a component other than the last is not a directory, or when any component
/// (including the last) is a symbolic link: links inside a user tree can only come from changes
/// made behind the server's back, and following them could leave the tree. Other file types
/// (sockets, FIFOs, devices) are reported as missing as well.
pub fn lstat_beneath(root: &Path, rel: &RelPath) -> io::Result<Option<fs::Metadata>> {
    let mut current = root.to_path_buf();
    let mut meta = match fs::metadata(&current) {
        Ok(meta) if meta.is_dir() => meta,
        Ok(_) => return Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    for segment in rel.segments() {
        if !meta.is_dir() {
            return Ok(None);
        }
        current.push(segment);
        meta = match fs::symlink_metadata(&current) {
            Ok(meta) => meta,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let kind = meta.file_type();
        if !(kind.is_dir() || kind.is_file()) {
            return Ok(None);
        }
    }
    Ok(Some(meta))
}

/// Creates `path` and missing parents; new directories get mode `0700` on Unix.
pub fn create_private_dir_all(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(path)
        .map_err(|source| io_error(path, source))
}

/// Name of the directory of an upload session (see [`DataLayout::upload_session_dir`]).
pub fn upload_session_dir_name(upload_id: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(upload_id.as_bytes())
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_probe_matches_the_file_system_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path().join("data"));
        layout.create().unwrap();
        fs::write(dir.path().join("Probe"), b"").unwrap();
        let expected = dir.path().join("probe").exists();
        assert_eq!(layout.is_case_insensitive().unwrap(), expected);
        assert_eq!(fs::read_dir(layout.tmp_dir()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn lookups_never_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("real/sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        fs::write(root.join("real/file.txt"), b"x").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink(outside.join("secret.txt"), root.join("real/link.txt")).unwrap();

        let lookup = |rel: &str| lstat_beneath(&root, &RelPath::parse(rel).unwrap()).unwrap();
        assert!(lookup("").unwrap().is_dir());
        assert!(lookup("real/sub").unwrap().is_dir());
        assert!(lookup("real/file.txt").unwrap().is_file());
        assert!(lookup("escape").is_none(), "symlinked directory");
        assert!(
            lookup("escape/secret.txt").is_none(),
            "path through a symlink"
        );
        assert!(lookup("real/link.txt").is_none(), "symlinked file");
        assert!(
            lookup("real/file.txt/below").is_none(),
            "file used as a directory"
        );
        assert!(lookup("missing/x").is_none());
    }

    #[test]
    fn create_builds_the_fixed_layout() {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path().join("data"));
        layout.create().unwrap();
        for sub in ["files", "uploads", "tmp", "deleted"] {
            assert!(layout.root().join(sub).is_dir(), "{sub}");
        }
        layout.create().expect("create is idempotent");
    }

    #[cfg(unix)]
    #[test]
    fn directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path().join("data"));
        layout.create().unwrap();
        layout.create_user(1).unwrap();
        for path in [layout.root().to_path_buf(), layout.user_files(1)] {
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", path.display());
        }
    }

    #[test]
    fn open_requires_an_existing_data_dir_and_cleans_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path().join("data"));
        assert!(matches!(layout.open(), Err(Error::DataDirMissing { .. })));

        layout.create().unwrap();
        fs::write(layout.tmp_dir().join("stale.part"), b"x").unwrap();
        fs::create_dir(layout.tmp_dir().join("stale-dir")).unwrap();
        layout.open().unwrap();
        assert_eq!(fs::read_dir(layout.tmp_dir()).unwrap().count(), 0);
    }

    #[test]
    fn user_directories_are_named_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path());
        layout.create().unwrap();
        layout.create_user(7).unwrap();
        assert!(dir.path().join("files/7").is_dir());
        assert!(dir.path().join("uploads/7").is_dir());
        layout.create_user(7).expect("empty directories are reused");
    }

    #[test]
    fn leftover_files_of_a_reused_id_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path());
        layout.create().unwrap();
        layout.create_user(3).unwrap();
        fs::write(layout.user_files(3).join("old.txt"), b"old").unwrap();
        assert!(matches!(
            layout.create_user(3),
            Err(Error::UserDirNotEmpty { .. })
        ));
        layout
            .ensure_user(3)
            .expect("ensure keeps existing content");
    }

    #[test]
    fn retired_users_move_to_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path());
        layout.create().unwrap();
        layout.create_user(3).unwrap();
        fs::write(layout.user_files(3).join("old.txt"), b"old").unwrap();

        let target = layout.retire_user(3, "bob", 1700).unwrap().unwrap();
        assert_eq!(target, layout.deleted_root().join("3-bob-1700"));
        assert!(target.join("files/old.txt").is_file());
        assert!(!layout.user_files(3).exists());
        layout.create_user(3).expect("the id is free again");
        assert_eq!(layout.retire_user(9, "nobody", 1).unwrap(), None);
    }
}
