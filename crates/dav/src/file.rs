//! `DavFile` implementations: reading a stored file, and writing a new version atomically.

use std::{
    fmt,
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use bytes::{Buf, Bytes, BytesMut};
use dav_server::fs::{DavFile, DavMetaData, FsError, FsFuture, FsResult};
use futures_util::FutureExt as _;
use gono_core::RelPath;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::{
    ctx::Ctx,
    fs::{ScopedFs, blocking, detached, disk_stat, io_error},
    metadata::{DavMeta, Entry},
    resolve::Location,
};

/// An open stored file, for GET.
pub struct ReadFile {
    pub(crate) file: tokio::fs::File,
    pub(crate) entry: Arc<Entry>,
}

impl fmt::Debug for ReadFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadFile")
            .field("entry", &self.entry.location)
            .finish_non_exhaustive()
    }
}

impl DavFile for ReadFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: Box<dyn DavMetaData> = Box::new(DavMeta::new(self.entry.clone(), false));
        std::future::ready(Ok(meta)).boxed()
    }

    fn write_buf(&mut self, _buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        std::future::ready(Err(FsError::Forbidden)).boxed()
    }

    fn write_bytes(&mut self, _buf: Bytes) -> FsFuture<'_, ()> {
        std::future::ready(Err(FsError::Forbidden)).boxed()
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        async move {
            let mut buf = BytesMut::zeroed(count);
            let mut filled = 0;
            while filled < count {
                let read = self.file.read(&mut buf[filled..]).await.map_err(io_error)?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            buf.truncate(filled);
            Ok(buf.freeze())
        }
        .boxed()
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        async move { self.file.seek(pos).await.map_err(io_error) }.boxed()
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        std::future::ready(Ok(())).boxed()
    }
}

/// A new version of a file being written by PUT (or PATCH).
///
/// Data goes to a private file in the data directory's `tmp/`. [`DavFile::flush`], which
/// dav-server calls once after the whole body has arrived, checks the length against
/// `Content-Length`, syncs the data, applies `X-OC-MTime`, renames the file over the target and
/// records the new version in the MetaStore. Until then the old version stays untouched; a
/// failed or aborted upload only leaves the temporary file, which is removed on drop (or at
/// the next start).
pub struct WriteFile {
    pub(crate) fs: ScopedFs,
    pub(crate) ctx: Ctx,
    pub(crate) location: Location,
    pub(crate) owner: i64,
    pub(crate) storage: RelPath,
    pub(crate) target: PathBuf,
    pub(crate) temp: PathBuf,
    pub(crate) file: Option<tokio::fs::File>,
    /// Bytes written through this handle.
    pub(crate) written: u64,
    /// `Content-Length` of a full-body PUT; checked before the version is committed.
    pub(crate) expected: Option<u64>,
    pub(crate) committed: Option<Arc<Entry>>,
}

impl fmt::Debug for WriteFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteFile")
            .field("storage", &self.storage)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl WriteFile {
    fn file(&mut self) -> FsResult<&mut tokio::fs::File> {
        self.file.as_mut().ok_or(FsError::GeneralFailure)
    }

    async fn write_all(&mut self, data: &[u8]) -> FsResult<()> {
        self.file()?.write_all(data).await.map_err(io_error)?;
        self.written += u64::try_from(data.len()).unwrap_or(u64::MAX);
        Ok(())
    }

    async fn commit(&mut self) -> FsResult<()> {
        if self.committed.is_some() {
            return Ok(());
        }
        if let Some(expected) = self.expected
            && expected != self.written
        {
            tracing::warn!(
                path = %self.storage,
                expected,
                written = self.written,
                "upload length does not match Content-Length; discarding it"
            );
            return Err(FsError::GeneralFailure);
        }
        let mut file = self.file.take().ok_or(FsError::GeneralFailure)?;
        file.flush().await.map_err(io_error)?;
        file.sync_all().await.map_err(io_error)?;
        let file = file.into_std().await;
        if let Some(mtime) = self.ctx.request().oc_mtime {
            let time = UNIX_EPOCH + Duration::from_secs(u64::try_from(mtime).unwrap_or(0));
            blocking(move || file.set_modified(time)).await?;
        } else {
            drop(file);
        }

        let fs = self.fs.clone();
        let storage = self.storage.clone();
        let temp = self.temp.clone();
        let target = self.target.clone();
        let root = self.fs.user_root(self.owner);
        let ctx = self.ctx.clone();
        let location = self.location.clone();
        let entry = detached(async move {
            let stat = blocking(move || install(&root, &storage, &temp, &target)).await?;
            fs.record_write(&ctx, location, stat).await
        })
        .await?;
        self.ctx.set_outcome(entry.clone());
        self.committed = Some(entry);
        Ok(())
    }
}

/// Moves the finished temporary file over the target, after checking (again) that the parent
/// is still a real directory inside the tree. Returns the target's stat.
fn install(
    root: &Path,
    storage: &RelPath,
    temp: &Path,
    target: &Path,
) -> std::io::Result<gono_core::meta::DiskStat> {
    let parent = storage.parent().unwrap_or_default();
    match gono_core::storage::lstat_beneath(root, &parent)? {
        Some(meta) if meta.is_dir() => {}
        _ => return Err(std::io::ErrorKind::NotFound.into()),
    }
    std::fs::rename(temp, target)?;
    let meta = std::fs::symlink_metadata(target)?;
    Ok(disk_stat(&meta))
}

impl DavFile for WriteFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let result = self
            .committed
            .clone()
            .map_or(Err(FsError::NotFound), |entry| {
                Ok(Box::new(DavMeta::new(entry, false)) as Box<dyn DavMetaData>)
            });
        std::future::ready(result).boxed()
    }

    fn write_buf(&mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        async move {
            while buf.has_remaining() {
                let chunk = buf.chunk().to_vec();
                self.write_all(&chunk).await?;
                buf.advance(chunk.len());
            }
            Ok(())
        }
        .boxed()
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<'_, ()> {
        async move { self.write_all(&buf).await }.boxed()
    }

    fn read_bytes(&mut self, _count: usize) -> FsFuture<'_, Bytes> {
        std::future::ready(Err(FsError::Forbidden)).boxed()
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        async move { self.file()?.seek(pos).await.map_err(io_error) }.boxed()
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        async move { self.commit().await }.boxed()
    }
}

impl Drop for WriteFile {
    fn drop(&mut self) {
        if self.committed.is_none() {
            // The rename never happened (aborted upload, length mismatch, ...).
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// A file that needs no I/O: the empty resource created by LOCK on an unmapped URL.
#[derive(Debug)]
pub struct CreatedFile {
    pub(crate) entry: Arc<Entry>,
}

impl DavFile for CreatedFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: Box<dyn DavMetaData> = Box::new(DavMeta::new(self.entry.clone(), false));
        std::future::ready(Ok(meta)).boxed()
    }

    fn write_buf(&mut self, _buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        std::future::ready(Err(FsError::Forbidden)).boxed()
    }

    fn write_bytes(&mut self, _buf: Bytes) -> FsFuture<'_, ()> {
        std::future::ready(Err(FsError::Forbidden)).boxed()
    }

    fn read_bytes(&mut self, _count: usize) -> FsFuture<'_, Bytes> {
        std::future::ready(Ok(Bytes::new())).boxed()
    }

    fn seek(&mut self, _pos: SeekFrom) -> FsFuture<'_, u64> {
        std::future::ready(Ok(0)).boxed()
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        std::future::ready(Ok(())).boxed()
    }
}
