//! What the file system reports to dav-server about an entry.
//!
//! Every entry is described by an [`Entry`], built once from the disk and the `files` row, and
//! handed to dav-server wrapped in [`DavMeta`]. All methods report the **same** ETag:
//!
//! - dav-server puts `DavMetaData::etag()` into the `ETag` header of GET, HEAD and PUT and into
//!   the If-Match/If-None-Match comparisons, adding the quotes itself;
//! - it puts the same value into PROPFIND's `DAV:getetag` verbatim.
//!
//! RFC 4918 defines `getetag` as a quoted entity tag, as Nextcloud reports it, so during
//! PROPFIND (where no conditional headers are evaluated) [`DavMeta::etag`] returns the value
//! with quotes, and without them everywhere else. The result is one quoted ETag on every
//! interface, and dav-server's XML is never touched.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dav_server::fs::{DavMetaData, FsResult};

use crate::resolve::Location;

/// Kind of entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory or a virtual collection.
    Dir,
}

/// Everything known about one entry. Shared between dav-server's metadata objects, the live
/// properties and the OC-* response headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Where the entry is.
    pub location: Location,
    /// File or directory.
    pub kind: Kind,
    /// Numeric file id (`oc:fileid`); `None` for virtual collections.
    pub file_id: Option<i64>,
    /// ETag without quotes.
    pub etag: String,
    /// Modification time.
    pub modified: SystemTime,
    /// File length or recursive folder size (`oc:size`).
    pub size: u64,
    /// `oc:favorite`.
    pub favorite: bool,
    /// `oc:permissions` / `X-NC-Permissions`.
    pub permissions: &'static str,
}

impl Entry {
    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.kind == Kind::Dir
    }
}

/// Converts UNIX nanoseconds to a `SystemTime`.
pub fn time_from_ns(ns: i64) -> SystemTime {
    let ns = u64::try_from(ns).unwrap_or(0);
    UNIX_EPOCH + Duration::from_nanos(ns)
}

/// Converts a `SystemTime` to UNIX nanoseconds (0 before the epoch).
pub fn ns_from_time(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// The `DavMetaData` handed to dav-server.
#[derive(Debug, Clone)]
pub struct DavMeta {
    entry: Arc<Entry>,
    quoted_etag: bool,
}

impl DavMeta {
    /// Wraps an entry. `quoted_etag` is set while handling PROPFIND (see the module docs).
    pub fn new(entry: Arc<Entry>, quoted_etag: bool) -> Self {
        Self { entry, quoted_etag }
    }

    /// The described entry.
    pub fn entry(&self) -> &Arc<Entry> {
        &self.entry
    }
}

impl DavMetaData for DavMeta {
    fn len(&self) -> u64 {
        self.entry.size
    }

    fn modified(&self) -> FsResult<SystemTime> {
        Ok(self.entry.modified)
    }

    fn is_dir(&self) -> bool {
        self.entry.is_dir()
    }

    fn etag(&self) -> Option<String> {
        Some(if self.quoted_etag {
            format!("\"{}\"", self.entry.etag)
        } else {
            self.entry.etag.clone()
        })
    }
}
