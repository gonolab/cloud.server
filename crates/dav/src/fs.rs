//! `ScopedFs`: the `GuardedFileSystem<Ctx>` behind the single `DavHandler`.
//!
//! - **Path mapping and virtual directories**: [`crate::resolve`] turns the DAV path into a
//!   storage path below the user's files root, or into a virtual collection on the way to the
//!   identity's mounts.
//! - **Safe disk access**: every lookup walks the path with `lstat(2)` and treats symbolic
//!   links (and sockets, FIFOs, devices) as missing, so no request can leave the user's tree;
//!   names that are not NFC are hidden (they cannot be addressed, see [`gono_core::path`]).
//! - **Permissions**: every write checks the mount's permission. Virtual collections and mount
//!   roots can be neither written nor deleted nor renamed.
//! - **Metadata**: entries are reported as [`Entry`]s through [`DavMeta`] (one quoted ETag on
//!   every interface), and every change is recorded by the [`MetaStore`] right after the disk
//!   operation. The disk operation and its metadata update run in a detached task, so a client
//!   that disconnects mid-request cannot leave a change unrecorded.
//!
//! # Whole-subtree operations
//!
//! dav-server implements DELETE and COPY of collections by walking them and calling the file
//! system once per entry, which would make one metadata transaction per entry. Instead,
//! `remove_dir` removes a whole subtree and `create_dir` of a COPY's destination copies the
//! whole source subtree, each recorded in one MetaStore transaction with range queries.
//! `read_dir` therefore reports no children while handling DELETE, COPY and MOVE, so
//! dav-server does not recurse.

use std::{
    collections::HashSet,
    future::Future,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::UNIX_EPOCH,
};

use dav_server::{
    davpath::DavPath,
    fs::{
        DavDirEntry, DavFile, DavMetaData, DavProp, FsError, FsFuture, FsResult, FsStream,
        GuardedFileSystem, OpenOptions, ReadDirMeta,
    },
};
use futures_util::{FutureExt as _, StreamExt as _, stream};
use gono_core::{
    RelPath,
    meta::{DeadProp, DiskStat, FileRow, MetaStore, PropChange, derived_file_etag},
    path::disk_segment,
    storage::{DataLayout, lstat_beneath},
};
use http::{Method, StatusCode};
use rand::RngExt as _;
use sha2::{Digest, Sha256};

use crate::{
    ctx::{Ctx, PropfindKind},
    file::{CreatedFile, ReadFile, WriteFile},
    metadata::{DavMeta, Entry, Kind, time_from_ns},
    props,
    resolve::{self, Location},
};

/// The file system of every WebDAV request. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ScopedFs {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    layout: DataLayout,
    meta: MetaStore,
    instance_id: String,
    /// Users whose directories and root row are known to exist.
    ready: Mutex<HashSet<i64>>,
}

/// Runs blocking file system code on the blocking thread pool.
pub(crate) async fn blocking<T, F>(f: F) -> FsResult<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| FsError::GeneralFailure)?
        .map_err(io_error)
}

/// Runs `future` to completion even if the request that started it is dropped.
pub(crate) async fn detached<T, F>(future: F) -> FsResult<T>
where
    F: Future<Output = FsResult<T>> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(future)
        .await
        .map_err(|_| FsError::GeneralFailure)?
}

/// Maps I/O errors to dav-server's error codes.
///
/// dav-server's own conversion turns every error without an OS error code into
/// `NotImplemented` (501); the errors raised here by kind are mapped explicitly.
pub(crate) fn io_error(err: io::Error) -> FsError {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => FsError::NotFound,
        io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty => FsError::Exists,
        io::ErrorKind::PermissionDenied | io::ErrorKind::IsADirectory => FsError::Forbidden,
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => FsError::InsufficientStorage,
        _ if err.raw_os_error().is_some() => FsError::from(err),
        _ => FsError::GeneralFailure,
    }
}

fn db_error(err: gono_core::Error) -> FsError {
    tracing::error!(error = %err, "metadata update failed");
    FsError::GeneralFailure
}

pub(crate) fn disk_stat(meta: &std::fs::Metadata) -> DiskStat {
    DiskStat::from_metadata(meta)
}

impl ScopedFs {
    /// Creates the file system over a prepared data directory.
    pub fn new(layout: DataLayout, meta: MetaStore, instance_id: String) -> Self {
        Self {
            inner: Arc::new(Inner {
                layout,
                meta,
                instance_id,
                ready: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// The metadata store.
    pub fn meta(&self) -> &MetaStore {
        &self.inner.meta
    }

    /// The data directory layout.
    pub fn layout(&self) -> &DataLayout {
        &self.inner.layout
    }

    /// The installation's instance id (suffix of `oc:id`).
    pub fn instance_id(&self) -> &str {
        &self.inner.instance_id
    }

    /// Bytes stored by `owner` (the recursive size of the root) and the free space of the
    /// file system holding the data directory, if it can be determined. There are no per-user
    /// quotas in v1.
    pub async fn usage(&self, owner: i64) -> FsResult<(u64, Option<u64>)> {
        self.ensure_user(owner).await?;
        let used = self
            .inner
            .meta
            .get(owner, &RelPath::root())
            .await
            .map_err(db_error)?
            .map_or(0, |row| row.size);
        let root = self.user_root(owner);
        let free = blocking(move || Ok(free_space(&root))).await?;
        Ok((used, free))
    }

    pub(crate) fn user_root(&self, owner: i64) -> PathBuf {
        self.inner.layout.user_files(owner)
    }

    /// Creates the user's directories and root row on first access.
    async fn ensure_user(&self, owner: i64) -> FsResult<()> {
        if self
            .inner
            .ready
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&owner)
        {
            return Ok(());
        }
        let layout = self.inner.layout.clone();
        let root = self.user_root(owner);
        let stat = blocking(move || {
            layout.ensure_user(owner).map_err(io::Error::other)?;
            Ok(disk_stat(&std::fs::metadata(&root)?))
        })
        .await?;
        self.inner
            .meta
            .adopt(owner, &[(RelPath::root(), stat)])
            .await
            .map_err(db_error)?;
        self.inner
            .ready
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(owner);
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Lookups
    // -----------------------------------------------------------------------------------------

    /// Resolves `path` and describes what is there.
    pub async fn entry(&self, ctx: &Ctx, path: &DavPath) -> FsResult<Arc<Entry>> {
        let location = resolve::resolve(ctx.identity(), path)?;
        self.lookup(ctx, &location).await
    }

    async fn lookup(&self, ctx: &Ctx, location: &Location) -> FsResult<Arc<Entry>> {
        match location {
            Location::Virtual { client } => self.virtual_entry(ctx, client).await,
            Location::Storage { .. } => self.lookup_storage(ctx, location).await,
        }
    }

    async fn lookup_storage(&self, ctx: &Ctx, location: &Location) -> FsResult<Arc<Entry>> {
        let storage = location.storage().ok_or(FsError::NotFound)?;
        if let Some(entry) = ctx.cached(storage) {
            return Ok(entry);
        }
        let owner = ctx.identity().user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let rel = storage.clone();
        let meta = blocking(move || lstat_beneath(&root, &rel))
            .await?
            .ok_or(FsError::NotFound)?;
        let stat = disk_stat(&meta);
        let row = match self
            .inner
            .meta
            .get(owner, storage)
            .await
            .map_err(db_error)?
        {
            Some(row) => row,
            None => self.adopt_one(owner, storage, stat).await?,
        };
        let entry = Arc::new(self.storage_entry(ctx, location.clone(), &row, stat));
        ctx.remember(storage.clone(), entry.clone());
        Ok(entry)
    }

    async fn adopt_one(&self, owner: i64, rel: &RelPath, stat: DiskStat) -> FsResult<FileRow> {
        let rows = self
            .inner
            .meta
            .adopt(owner, &[(rel.clone(), stat)])
            .await
            .map_err(db_error)?;
        rows.into_iter().next().ok_or(FsError::GeneralFailure)
    }

    /// Combines a row with what the disk reports right now.
    fn storage_entry(&self, ctx: &Ctx, location: Location, row: &FileRow, stat: DiskStat) -> Entry {
        let identity = ctx.identity();
        let kind = if stat.is_dir { Kind::Dir } else { Kind::File };
        // A file changed behind the server's back no longer matches its row; report an ETag
        // derived from what is on disk so that clients never mistake it for the old version.
        let etag = if stat.is_dir
            || (row.mtime_ns == stat.mtime_ns && row.size == stat.size && !row.is_dir)
        {
            row.etag.clone()
        } else {
            derived_file_etag(row.id, stat.mtime_ns, stat.size)
        };
        Entry {
            permissions: props::permissions(
                kind,
                location.writable(identity),
                location.is_mount_root(identity),
                false,
            ),
            location,
            kind,
            file_id: Some(row.id),
            etag,
            modified: time_from_ns(stat.mtime_ns),
            size: if stat.is_dir { row.size } else { stat.size },
            favorite: row.favorite,
        }
    }

    /// Describes a virtual collection. Its ETag, size and time summarize the mounts below it,
    /// so a change inside any of them changes the virtual parents too.
    async fn virtual_entry(&self, ctx: &Ctx, client: &RelPath) -> FsResult<Arc<Entry>> {
        let identity = ctx.identity();
        let mut hasher = Sha256::new();
        let mut size = 0;
        let mut modified = UNIX_EPOCH;
        for mount in resolve::mounts_below(identity, client) {
            let location = resolve::resolve_client(identity, mount.mount_path.clone())?;
            match self.lookup_storage(ctx, &location).await {
                Ok(entry) => {
                    hasher.update(mount.mount_path.as_str().as_bytes());
                    hasher.update([0]);
                    hasher.update(entry.etag.as_bytes());
                    hasher.update([0]);
                    size += entry.size;
                    modified = modified.max(entry.modified);
                }
                Err(FsError::NotFound) => {}
                Err(err) => return Err(err),
            }
        }
        let digest = hasher.finalize();
        Ok(Arc::new(Entry {
            location: Location::Virtual {
                client: client.clone(),
            },
            kind: Kind::Dir,
            file_id: None,
            etag: digest.iter().take(10).map(|b| format!("{b:02x}")).collect(),
            modified,
            size,
            favorite: false,
            permissions: props::permissions(Kind::Dir, false, false, true),
        }))
    }

    /// Lists a storage directory: one `read_dir` on disk, one batched row lookup, and one
    /// adoption transaction for entries without rows.
    async fn list_storage(
        &self,
        ctx: &Ctx,
        location: &Location,
    ) -> FsResult<Vec<(String, Arc<Entry>)>> {
        let identity = ctx.identity();
        let Location::Storage { mount, storage, .. } = location else {
            return Err(FsError::NotFound);
        };
        let owner = identity.user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let dir = storage.clone();
        let listing = blocking(move || read_storage_dir(&root, &dir)).await?;

        let rels: Vec<RelPath> = listing.iter().map(|(name, _)| storage.join(name)).collect();
        let mut rows = self
            .inner
            .meta
            .get_many(owner, &rels)
            .await
            .map_err(db_error)?;
        let missing: Vec<(RelPath, DiskStat)> = rels
            .iter()
            .zip(&listing)
            .filter(|(rel, _)| !rows.contains_key(*rel))
            .map(|(rel, (_, stat))| (rel.clone(), *stat))
            .collect();
        for row in self
            .inner
            .meta
            .adopt(owner, &missing)
            .await
            .map_err(db_error)?
        {
            rows.insert(row.rel_path.clone(), row);
        }

        let mut entries = Vec::with_capacity(listing.len());
        for ((name, stat), rel) in listing.into_iter().zip(rels) {
            let Some(row) = rows.get(&rel) else { continue };
            let Some(client) = resolve::client_for_storage(identity, *mount, &rel) else {
                continue;
            };
            let child = Location::Storage {
                mount: *mount,
                client,
                storage: rel.clone(),
            };
            let entry = Arc::new(self.storage_entry(ctx, child, row, stat));
            ctx.remember(rel, entry.clone());
            entries.push((name, entry));
        }
        Ok(entries)
    }

    /// The favorites strictly below `path`, as client paths with whether each one is a
    /// collection, ordered by client path (the `filter-files` REPORT).
    ///
    /// Below a virtual collection, every mount is searched, including the mount roots. The
    /// result comes from the metadata alone; callers look every entry up again, which drops
    /// rows whose file disappeared behind the server's back.
    pub async fn favorites_below(
        &self,
        ctx: &Ctx,
        path: &DavPath,
    ) -> FsResult<Vec<(RelPath, bool)>> {
        let identity = ctx.identity();
        let location = resolve::resolve(identity, path)?;
        // 404 for a path that does not exist.
        self.lookup(ctx, &location).await?;
        let owner = identity.user_id;
        let searches: Vec<(usize, &RelPath, bool)> = match &location {
            Location::Storage { mount, storage, .. } => vec![(*mount, storage, false)],
            Location::Virtual { client } => identity
                .mounts
                .iter()
                .enumerate()
                .filter(|(_, mount)| mount.mount_path.starts_with(client))
                .map(|(index, mount)| (index, &mount.storage_path, true))
                .collect(),
        };
        let mut found = Vec::new();
        for (mount, dir, include_dir) in searches {
            let rows = self
                .inner
                .meta
                .favorites(owner, dir, include_dir)
                .await
                .map_err(db_error)?;
            found.extend(rows.into_iter().filter_map(|row| {
                resolve::client_for_storage(identity, mount, &row.rel_path)
                    .map(|client| (client, row.is_dir))
            }));
        }
        found.sort();
        Ok(found)
    }

    async fn list_virtual(
        &self,
        ctx: &Ctx,
        client: &RelPath,
    ) -> FsResult<Vec<(String, Arc<Entry>)>> {
        let identity = ctx.identity();
        let mut entries = Vec::new();
        for (name, child) in resolve::virtual_children(identity, client) {
            let location = resolve::resolve_client(identity, child)?;
            match self.lookup(ctx, &location).await {
                Ok(entry) if entry.is_dir() => entries.push((name, entry)),
                Ok(_) | Err(FsError::NotFound) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(entries)
    }

    // -----------------------------------------------------------------------------------------
    // Changes
    // -----------------------------------------------------------------------------------------

    /// Resolves a write target: it must be inside a writable mount.
    fn writable(ctx: &Ctx, path: &DavPath) -> FsResult<(Location, RelPath)> {
        let identity = ctx.identity();
        let location = match resolve::resolve(identity, path) {
            Ok(location) => location,
            // A new name directly inside a virtual collection: refused, not "parent missing".
            Err(FsError::NotFound) => {
                let parent = resolve::client_path(identity, path)?.parent();
                return Err(
                    match parent.map(|parent| resolve::resolve_client(identity, parent)) {
                        Some(Ok(Location::Virtual { .. })) => FsError::Forbidden,
                        _ => FsError::NotFound,
                    },
                );
            }
            Err(err) => return Err(err),
        };
        if !location.writable(ctx.identity()) {
            return Err(FsError::Forbidden);
        }
        let storage = location.storage().cloned().ok_or(FsError::Forbidden)?;
        Ok((location, storage))
    }

    /// Like [`Self::writable`], and the target must not be a mount root (those can be neither
    /// replaced, removed nor renamed).
    fn replaceable(ctx: &Ctx, path: &DavPath) -> FsResult<(Location, RelPath)> {
        let (location, storage) = Self::writable(ctx, path)?;
        if location.is_mount_root(ctx.identity()) {
            return Err(FsError::Forbidden);
        }
        Ok((location, storage))
    }

    pub(crate) async fn record_write(
        &self,
        ctx: &Ctx,
        location: Location,
        stat: DiskStat,
    ) -> FsResult<Arc<Entry>> {
        let storage = location.storage().cloned().ok_or(FsError::Forbidden)?;
        let row = self
            .inner
            .meta
            .record_write(ctx.identity().user_id, &storage, stat)
            .await
            .map_err(db_error)?;
        Ok(self.remember_row(ctx, location, &row, stat))
    }

    /// Caches the entry described by a freshly written row and returns it.
    fn remember_row(
        &self,
        ctx: &Ctx,
        location: Location,
        row: &FileRow,
        stat: DiskStat,
    ) -> Arc<Entry> {
        let storage = row.rel_path.clone();
        ctx.forget(&storage);
        let entry = Arc::new(self.storage_entry(ctx, location, row, stat));
        ctx.remember(storage, entry.clone());
        entry
    }

    async fn open_for_write(
        &self,
        ctx: &Ctx,
        path: &DavPath,
        options: OpenOptions,
    ) -> FsResult<Box<dyn DavFile>> {
        let (location, storage) = Self::replaceable(ctx, path)?;
        let owner = ctx.identity().user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let target = storage.to_fs_path(&root);

        // LOCK on an unmapped URL creates an empty resource (RFC 4918, 7.3).
        if is_method(ctx, "LOCK") {
            let fs = self.clone();
            let ctx2 = ctx.clone();
            let created = storage.clone();
            let entry = detached(async move {
                let stat = blocking(move || {
                    check_parent(&root, &created)?;
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    options.open(&target)?;
                    Ok(disk_stat(&std::fs::symlink_metadata(&target)?))
                })
                .await?;
                fs.record_write(&ctx2, location, stat).await
            })
            .await?;
            return Ok(Box::new(CreatedFile { entry }));
        }

        let tmp_dir = self.inner.layout.tmp_dir();
        let rel = storage.clone();
        let target_for_check = target.clone();
        let expected = options.size;
        let (temp, file) = blocking(move || {
            check_parent(&root, &rel)?;
            let existing = lstat_beneath(&root, &rel)?;
            match &existing {
                Some(meta) if meta.is_dir() => {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, "collection"));
                }
                Some(_) if options.create_new => {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                None if !options.create => return Err(io::ErrorKind::NotFound.into()),
                _ => {}
            }
            if let Some(size) = expected
                && free_space(&tmp_dir).is_some_and(|free| free < size)
            {
                return Err(io::ErrorKind::StorageFull.into());
            }
            let temp = tmp_dir.join(format!("{:032x}.part", rand::rng().random::<u128>()));
            let mut open = std::fs::OpenOptions::new();
            open.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
            if !options.truncate && existing.is_some() {
                // Partial updates (PATCH, Content-Range) start from the current content.
                std::fs::copy(&target_for_check, &temp)?;
                open.create_new(false);
            }
            if options.append {
                open.append(true);
            }
            let file = open.open(&temp)?;
            Ok((temp, file))
        })
        .await?;

        let ranged = !options.truncate;
        Ok(Box::new(WriteFile {
            fs: self.clone(),
            ctx: ctx.clone(),
            location,
            owner,
            storage,
            target,
            temp,
            file: Some(tokio::fs::File::from_std(file)),
            written: 0,
            expected: if ranged { None } else { expected },
            committed: None,
        }))
    }

    // -----------------------------------------------------------------------------------------
    // Files assembled outside dav-server (chunked upload)
    // -----------------------------------------------------------------------------------------

    /// Resolves the destination of an upload: it must be a writable location inside a mount
    /// that is not the mount root, exactly like the target of a PUT.
    pub fn upload_target(ctx: &Ctx, path: &DavPath) -> FsResult<Location> {
        Self::replaceable(ctx, path).map(|(location, _)| location)
    }

    /// What is at `location` now, or `None` if nothing is.
    pub async fn current(&self, ctx: &Ctx, location: &Location) -> FsResult<Option<Arc<Entry>>> {
        match self.lookup(ctx, location).await {
            Ok(entry) => Ok(Some(entry)),
            Err(FsError::NotFound) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Installs a finished file at `location` (from [`Self::upload_target`]), replacing the
    /// file there, and records the new version in the MetaStore.
    ///
    /// `temp` must be a complete, synced file on the data directory's file system (for
    /// example in `tmp/`). It is renamed into place atomically, after checking (again) that
    /// the parent is a real directory inside the tree and that the target is not a
    /// collection, and the parent directory is synced so that the rename survives a crash.
    /// Like every write, this runs to completion even if the request is dropped. On error,
    /// `temp` is left for the caller to remove.
    ///
    /// Returns the new entry and whether a file was replaced.
    pub async fn install_file(
        &self,
        ctx: &Ctx,
        location: Location,
        temp: PathBuf,
    ) -> FsResult<(Arc<Entry>, bool)> {
        if !location.writable(ctx.identity()) || location.is_mount_root(ctx.identity()) {
            return Err(FsError::Forbidden);
        }
        let storage = location.storage().cloned().ok_or(FsError::Forbidden)?;
        let owner = ctx.identity().user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let fs = self.clone();
        let ctx2 = ctx.clone();
        let (entry, replaced) = detached(async move {
            let rel = storage.clone();
            let (stat, replaced) = blocking(move || {
                check_parent(&root, &rel)?;
                let replaced = match lstat_beneath(&root, &rel)? {
                    Some(meta) if meta.is_dir() => {
                        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "collection"));
                    }
                    existing => existing.is_some(),
                };
                let target = rel.to_fs_path(&root);
                std::fs::rename(&temp, &target)?;
                if let Some(parent) = target.parent() {
                    std::fs::File::open(parent)?.sync_all()?;
                }
                Ok((disk_stat(&std::fs::symlink_metadata(&target)?), replaced))
            })
            .await?;
            let entry = fs.record_write(&ctx2, location, stat).await?;
            Ok((entry, replaced))
        })
        .await?;
        ctx.set_outcome(entry.clone());
        Ok((entry, replaced))
    }

    async fn open_for_read(&self, ctx: &Ctx, path: &DavPath) -> FsResult<Box<dyn DavFile>> {
        let entry = self.entry(ctx, path).await?;
        let storage = entry
            .location
            .storage()
            .cloned()
            .ok_or(FsError::Forbidden)?;
        if entry.is_dir() {
            return Err(FsError::Forbidden);
        }
        let path = storage.to_fs_path(&self.user_root(ctx.identity().user_id));
        let file = blocking(move || {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
            options.open(path)
        })
        .await?;
        Ok(Box::new(ReadFile {
            file: tokio::fs::File::from_std(file),
            entry,
        }))
    }

    async fn make_dir(&self, ctx: &Ctx, path: &DavPath) -> FsResult<()> {
        let (location, storage) = Self::writable(ctx, path)?;
        let owner = ctx.identity().user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let fs = self.clone();
        let ctx2 = ctx.clone();
        let entry = detached(async move {
            let rel = storage.clone();
            let stat = blocking(move || {
                check_parent(&root, &rel)?;
                if lstat_beneath(&root, &rel)?.is_some() {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                let dir = rel.to_fs_path(&root);
                std::fs::create_dir(&dir)?;
                Ok(disk_stat(&std::fs::symlink_metadata(&dir)?))
            })
            .await?;
            let row = fs
                .inner
                .meta
                .record_mkdir(owner, &storage, stat.mtime_ns)
                .await
                .map_err(db_error)?;
            Ok(fs.remember_row(&ctx2, location, &row, stat))
        })
        .await?;
        ctx.set_outcome(entry);
        Ok(())
    }

    /// The `create_dir` of a COPY: copies the whole source collection (see the module docs).
    async fn copy_collection(&self, ctx: &Ctx, destination: &DavPath) -> FsResult<()> {
        let source = ctx.request().path.clone().ok_or(FsError::GeneralFailure)?;
        let identity = ctx.identity();
        let from = resolve::resolve(identity, &source)?;
        let from = from.storage().cloned().ok_or(FsError::Forbidden)?;
        let (location, to) = Self::replaceable(ctx, destination)?;
        if to.starts_with(&from) {
            return Err(FsError::Forbidden);
        }
        let depth_zero = ctx.request().depth_zero;
        let owner = identity.user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let fs = self.clone();
        let ctx2 = ctx.clone();
        let entry = detached(async move {
            let (src, dst) = (from.clone(), to.clone());
            let entries = blocking(move || {
                match lstat_beneath(&root, &src)? {
                    Some(meta) if meta.is_dir() => {}
                    _ => return Err(io::ErrorKind::NotFound.into()),
                }
                check_parent(&root, &dst)?;
                if lstat_beneath(&root, &dst)?.is_some() {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                copy_tree(&src.to_fs_path(&root), &dst.to_fs_path(&root), depth_zero)
            })
            .await?;
            let top_stat = entries[0].1;
            let row = fs
                .inner
                .meta
                .record_copy(owner, &from, &to, &entries)
                .await
                .map_err(db_error)?;
            Ok(fs.remember_row(&ctx2, location, &row, top_stat))
        })
        .await?;
        ctx.set_outcome(entry);
        Ok(())
    }

    async fn remove(&self, ctx: &Ctx, path: &DavPath, dir: bool) -> FsResult<()> {
        let (_, storage) = Self::replaceable(ctx, path)?;
        let owner = ctx.identity().user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let fs = self.clone();
        let rel = storage.clone();
        detached(async move {
            let target = rel.clone();
            blocking(move || {
                let meta = lstat_beneath(&root, &target)?.ok_or(io::ErrorKind::NotFound)?;
                let path = target.to_fs_path(&root);
                match (meta.is_dir(), dir) {
                    // remove_dir_all removes symbolic links inside without following them.
                    (true, true) => std::fs::remove_dir_all(path),
                    (false, false) => std::fs::remove_file(path),
                    _ => Err(io::ErrorKind::PermissionDenied.into()),
                }
            })
            .await?;
            fs.inner
                .meta
                .record_delete(owner, &rel)
                .await
                .map_err(db_error)?;
            Ok(())
        })
        .await?;
        ctx.forget(&storage);
        Ok(())
    }

    async fn move_entry(&self, ctx: &Ctx, from: &DavPath, to: &DavPath) -> FsResult<()> {
        let (_, source) = Self::replaceable(ctx, from)?;
        let (location, target) = Self::replaceable(ctx, to)?;
        if target.starts_with(&source) || source.starts_with(&target) {
            return Err(FsError::Forbidden);
        }
        let owner = ctx.identity().user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let fs = self.clone();
        let ctx2 = ctx.clone();
        let (src, dst) = (source.clone(), target.clone());
        let entry = detached(async move {
            let (from, to) = (src.clone(), dst.clone());
            let stat = blocking(move || {
                lstat_beneath(&root, &from)?.ok_or(io::ErrorKind::NotFound)?;
                check_parent(&root, &to)?;
                let destination = to.to_fs_path(&root);
                std::fs::rename(from.to_fs_path(&root), &destination)?;
                Ok(disk_stat(&std::fs::symlink_metadata(&destination)?))
            })
            .await?;
            let row = fs
                .inner
                .meta
                .record_move(owner, &src, &dst, stat)
                .await
                .map_err(db_error)?;
            ctx2.forget(&src);
            Ok(fs.remember_row(&ctx2, location, &row, stat))
        })
        .await?;
        ctx.set_outcome(entry);
        Ok(())
    }

    async fn copy_file(&self, ctx: &Ctx, from: &DavPath, to: &DavPath) -> FsResult<()> {
        let source = resolve::resolve(ctx.identity(), from)?;
        let source = source.storage().cloned().ok_or(FsError::Forbidden)?;
        let (location, target) = Self::replaceable(ctx, to)?;
        let owner = ctx.identity().user_id;
        self.ensure_user(owner).await?;
        let root = self.user_root(owner);
        let tmp_dir = self.inner.layout.tmp_dir();
        let fs = self.clone();
        let ctx2 = ctx.clone();
        let entry = detached(async move {
            let (src, dst) = (source.clone(), target.clone());
            let stat = blocking(move || {
                let meta = lstat_beneath(&root, &src)?.ok_or(io::ErrorKind::NotFound)?;
                if !meta.is_file() {
                    return Err(io::ErrorKind::NotFound.into());
                }
                check_parent(&root, &dst)?;
                // Copy next to nothing visible, then rename into place.
                let temp = tmp_dir.join(format!("{:032x}.part", rand::rng().random::<u128>()));
                let result = copy_file_preserving_mtime(&src.to_fs_path(&root), &temp)
                    .and_then(|()| std::fs::rename(&temp, dst.to_fs_path(&root)));
                if result.is_err() {
                    let _ = std::fs::remove_file(&temp);
                }
                result?;
                Ok(disk_stat(&std::fs::symlink_metadata(
                    dst.to_fs_path(&root),
                )?))
            })
            .await?;
            let row = fs
                .inner
                .meta
                .record_copy(owner, &source, &target, &[(RelPath::root(), stat)])
                .await
                .map_err(db_error)?;
            Ok(fs.remember_row(&ctx2, location, &row, stat))
        })
        .await?;
        ctx.set_outcome(entry);
        Ok(())
    }

    async fn patch(
        &self,
        ctx: &Ctx,
        path: &DavPath,
        patch: Vec<(bool, DavProp)>,
    ) -> FsResult<Vec<(StatusCode, DavProp)>> {
        let (_, _) = Self::writable(ctx, path)?;
        let entry = self.entry(ctx, path).await?;
        let file_id = entry.file_id.ok_or(FsError::Forbidden)?;

        let mut statuses = Vec::with_capacity(patch.len());
        let mut favorite = None;
        let mut changes = Vec::new();
        for (is_set, prop) in patch {
            let status = if props::is_settable_live(&prop) {
                match if is_set {
                    props::parse_favorite(&prop)
                } else {
                    Some(false)
                } {
                    Some(value) => {
                        favorite = Some(value);
                        StatusCode::OK
                    }
                    None => StatusCode::CONFLICT,
                }
            } else if props::is_live(&prop) {
                StatusCode::FORBIDDEN
            } else {
                let namespace = prop.namespace.clone().unwrap_or_default();
                changes.push(if is_set {
                    PropChange::Set(DeadProp {
                        namespace,
                        name: prop.name.clone(),
                        xml: prop.xml.clone().unwrap_or_default(),
                    })
                } else {
                    PropChange::Remove(namespace, prop.name.clone())
                });
                StatusCode::OK
            };
            statuses.push((status, without_value(prop)));
        }

        // PROPPATCH is atomic: if anything failed, nothing is applied.
        if statuses.iter().any(|(status, _)| *status != StatusCode::OK) {
            return Ok(statuses
                .into_iter()
                .map(|(status, prop)| {
                    if status == StatusCode::OK {
                        (StatusCode::FAILED_DEPENDENCY, prop)
                    } else {
                        (status, prop)
                    }
                })
                .collect());
        }
        let meta = self.inner.meta.clone();
        detached(async move {
            if let Some(favorite) = favorite {
                meta.set_favorite(file_id, favorite)
                    .await
                    .map_err(db_error)?;
            }
            if !changes.is_empty() {
                meta.patch_dead_props(file_id, &changes)
                    .await
                    .map_err(db_error)?;
            }
            Ok(())
        })
        .await?;
        if let Some(storage) = entry.location.storage() {
            ctx.forget(storage);
        }
        Ok(statuses)
    }
}

fn without_value(prop: DavProp) -> DavProp {
    DavProp { xml: None, ..prop }
}

/// The parent of `rel` must be a real directory inside the tree.
fn check_parent(root: &Path, rel: &RelPath) -> io::Result<()> {
    let parent = rel.parent().ok_or(io::ErrorKind::PermissionDenied)?;
    match lstat_beneath(root, &parent)? {
        Some(meta) if meta.is_dir() => Ok(()),
        _ => Err(io::ErrorKind::NotFound.into()),
    }
}

/// Lists a directory of the tree: regular files and directories with valid NFC names.
fn read_storage_dir(root: &Path, dir: &RelPath) -> io::Result<Vec<(String, DiskStat)>> {
    match lstat_beneath(root, dir)? {
        Some(meta) if meta.is_dir() => {}
        Some(_) => return Err(io::ErrorKind::NotADirectory.into()),
        None => return Err(io::ErrorKind::NotFound.into()),
    }
    let path = dir.to_fs_path(root);
    let mut entries = Vec::new();
    for item in std::fs::read_dir(&path)? {
        let item = item?;
        let file_name = item.file_name();
        let Some(name) = disk_segment(&file_name) else {
            tracing::warn!(
                directory = %dir,
                name = ?file_name,
                "hiding a file name that is not valid NFC UTF-8; run `gono-cloud rescan`"
            );
            continue;
        };
        let meta = match std::fs::symlink_metadata(item.path()) {
            Ok(meta) => meta,
            // Removed between read_dir and lstat.
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        if meta.is_dir() || meta.is_file() {
            entries.push((name.to_owned(), disk_stat(&meta)));
        }
    }
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(entries)
}

/// Copies a file and gives the copy the source's modification time.
fn copy_file_preserving_mtime(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::copy(from, to)?;
    let mtime = std::fs::symlink_metadata(from)?.modified()?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(to)?
        .set_modified(mtime)
}

/// Copies the collection `from` to the new collection `to`, skipping symbolic links, special
/// files and names that are not NFC. Returns every created entry relative to `to`, parents
/// first. On failure the partial copy is removed.
fn copy_tree(from: &Path, to: &Path, depth_zero: bool) -> io::Result<Vec<(RelPath, DiskStat)>> {
    fn walk(
        from: &Path,
        to: &Path,
        rel: &RelPath,
        entries: &mut Vec<(RelPath, DiskStat)>,
    ) -> io::Result<()> {
        let mut children: Vec<(String, std::fs::Metadata)> = Vec::new();
        for item in std::fs::read_dir(from)? {
            let item = item?;
            let file_name = item.file_name();
            let Some(name) = disk_segment(&file_name) else {
                continue;
            };
            let meta = std::fs::symlink_metadata(item.path())?;
            children.push((name.to_owned(), meta));
        }
        children.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (name, meta) in children {
            let (source, target, child) = (from.join(&name), to.join(&name), rel.join(&name));
            if meta.is_dir() {
                std::fs::create_dir(&target)?;
                entries.push((
                    child.clone(),
                    disk_stat(&std::fs::symlink_metadata(&target)?),
                ));
                walk(&source, &target, &child, entries)?;
            } else if meta.is_file() {
                copy_file_preserving_mtime(&source, &target)?;
                entries.push((child, disk_stat(&std::fs::symlink_metadata(&target)?)));
            }
        }
        Ok(())
    }

    std::fs::create_dir(to)?;
    let mut entries = vec![(RelPath::root(), disk_stat(&std::fs::symlink_metadata(to)?))];
    if depth_zero {
        return Ok(entries);
    }
    if let Err(err) = walk(from, to, &RelPath::root(), &mut entries) {
        let _ = std::fs::remove_dir_all(to);
        return Err(err);
    }
    // Directory mtimes changed while they were filled.
    for (rel, stat) in entries.iter_mut().filter(|(_, stat)| stat.is_dir) {
        *stat = disk_stat(&std::fs::symlink_metadata(rel.to_fs_path(to))?);
    }
    Ok(entries)
}

/// Free space for unprivileged users on the file system holding `path`.
#[cfg(unix)]
pub fn free_space(path: &Path) -> Option<u64> {
    disk_space(path).map(|(free, _)| free)
}

/// Free space for unprivileged users and total size of the file system holding `path`.
#[cfg(unix)]
pub fn disk_space(path: &Path) -> Option<(u64, u64)> {
    let stat = rustix::fs::statvfs(path).ok()?;
    Some((
        stat.f_bavail.saturating_mul(stat.f_frsize),
        stat.f_blocks.saturating_mul(stat.f_frsize),
    ))
}

/// Free and total space of the file system holding `path` (unknown here).
#[cfg(not(unix))]
pub fn disk_space(_path: &Path) -> Option<(u64, u64)> {
    None
}

/// Free space for unprivileged users on the file system holding `path` (unknown here).
#[cfg(not(unix))]
pub fn free_space(_path: &Path) -> Option<u64> {
    None
}

/// One entry of a listing; dav-server asks for its metadata without further I/O.
struct DirEntry {
    name: String,
    meta: DavMeta,
}

impl DavDirEntry for DirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: Box<dyn DavMetaData> = Box::new(self.meta.clone());
        std::future::ready(Ok(meta)).boxed()
    }

    fn is_dir(&self) -> FsFuture<'_, bool> {
        std::future::ready(Ok(self.meta.entry().is_dir())).boxed()
    }

    fn is_file(&self) -> FsFuture<'_, bool> {
        std::future::ready(Ok(!self.meta.entry().is_dir())).boxed()
    }

    fn is_symlink(&self) -> FsFuture<'_, bool> {
        std::future::ready(Ok(false)).boxed()
    }
}

fn is_method(ctx: &Ctx, name: &str) -> bool {
    ctx.request().method.as_str() == name
}

impl GuardedFileSystem<Ctx> for ScopedFs {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
        ctx: &'a Ctx,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        async move {
            if options.write || options.append || options.create || options.create_new {
                self.open_for_write(ctx, path, options).await
            } else {
                self.open_for_read(ctx, path).await
            }
        }
        .boxed()
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
        ctx: &'a Ctx,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        async move {
            // See "Whole-subtree operations" in the module documentation.
            if ["DELETE", "COPY", "MOVE"].iter().any(|m| is_method(ctx, m)) {
                let empty: FsStream<Box<dyn DavDirEntry>> = stream::empty().boxed();
                return Ok(empty);
            }
            let location = resolve::resolve(ctx.identity(), path)?;
            let entries = match &location {
                Location::Virtual { client } => self.list_virtual(ctx, client).await?,
                Location::Storage { .. } => self.list_storage(ctx, &location).await?,
            };
            let quoted = is_method(ctx, "PROPFIND");
            let items: Vec<FsResult<Box<dyn DavDirEntry>>> = entries
                .into_iter()
                .map(|(name, entry)| {
                    Ok(Box::new(DirEntry {
                        name,
                        meta: DavMeta::new(entry, quoted),
                    }) as Box<dyn DavDirEntry>)
                })
                .collect();
            Ok(stream::iter(items).boxed())
        }
        .boxed()
    }

    fn metadata<'a>(
        &'a self,
        path: &'a DavPath,
        ctx: &'a Ctx,
    ) -> FsFuture<'a, Box<dyn DavMetaData>> {
        async move {
            let entry = self.entry(ctx, path).await?;
            if (ctx.is(&Method::GET) || ctx.is(&Method::HEAD))
                && ctx.request().path.as_ref() == Some(path)
            {
                ctx.set_outcome(entry.clone());
            }
            let meta: Box<dyn DavMetaData> =
                Box::new(DavMeta::new(entry, is_method(ctx, "PROPFIND")));
            Ok(meta)
        }
        .boxed()
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath, ctx: &'a Ctx) -> FsFuture<'a, ()> {
        async move {
            if is_method(ctx, "COPY") {
                self.copy_collection(ctx, path).await
            } else {
                self.make_dir(ctx, path).await
            }
        }
        .boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath, ctx: &'a Ctx) -> FsFuture<'a, ()> {
        async move { self.remove(ctx, path, true).await }.boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath, ctx: &'a Ctx) -> FsFuture<'a, ()> {
        async move { self.remove(ctx, path, false).await }.boxed()
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath, ctx: &'a Ctx) -> FsFuture<'a, ()> {
        async move { self.move_entry(ctx, from, to).await }.boxed()
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath, ctx: &'a Ctx) -> FsFuture<'a, ()> {
        async move { self.copy_file(ctx, from, to).await }.boxed()
    }

    fn have_props<'a>(
        &'a self,
        _path: &'a DavPath,
        _ctx: &'a Ctx,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        std::future::ready(true).boxed()
    }

    fn patch_props<'a>(
        &'a self,
        path: &'a DavPath,
        patch: Vec<(bool, DavProp)>,
        ctx: &'a Ctx,
    ) -> FsFuture<'a, Vec<(StatusCode, DavProp)>> {
        async move { self.patch(ctx, path, patch).await }.boxed()
    }

    fn get_props<'a>(
        &'a self,
        path: &'a DavPath,
        _do_content: bool,
        ctx: &'a Ctx,
    ) -> FsFuture<'a, Vec<DavProp>> {
        async move {
            // dav-server adds these to every PROPFIND response; only `allprop` asks for them.
            if ctx.request().propfind != PropfindKind::AllProp {
                return Ok(Vec::new());
            }
            let entry = self.entry(ctx, path).await?;
            let Some(file_id) = entry.file_id else {
                return Ok(Vec::new());
            };
            let props = self
                .inner
                .meta
                .dead_props(file_id)
                .await
                .map_err(db_error)?;
            Ok(props
                .into_iter()
                .map(|prop| DavProp {
                    name: prop.name,
                    prefix: None,
                    namespace: (!prop.namespace.is_empty()).then_some(prop.namespace),
                    xml: Some(prop.xml),
                })
                .collect())
        }
        .boxed()
    }

    fn get_prop<'a>(
        &'a self,
        path: &'a DavPath,
        prop: DavProp,
        ctx: &'a Ctx,
    ) -> FsFuture<'a, Vec<u8>> {
        async move {
            let entry = self.entry(ctx, path).await?;
            if props::is_live(&prop) {
                return props::live_prop(&prop, &entry, self.instance_id())
                    .ok_or(FsError::NotFound);
            }
            let file_id = entry.file_id.ok_or(FsError::NotFound)?;
            self.inner
                .meta
                .dead_prop(file_id, prop.namespace.as_deref().unwrap_or(""), &prop.name)
                .await
                .map_err(db_error)?
                .ok_or(FsError::NotFound)
        }
        .boxed()
    }

    fn get_quota<'a>(&'a self, ctx: &'a Ctx) -> FsFuture<'a, (u64, Option<u64>)> {
        async move {
            let (used, free) = self.usage(ctx.identity().user_id).await?;
            Ok((used, free.map(|free| used.saturating_add(free))))
        }
        .boxed()
    }
}
