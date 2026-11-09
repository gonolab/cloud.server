//! WebDAV layer of Gono Cloud, built on [`dav_server`].
//!
//! The server builds exactly **one** `DavHandler<Ctx>` at startup and calls `handle_guarded`
//! for every request under `/remote.php/dav/files/<user>/` (and the legacy `/remote.php/webdav/`
//! alias). `Ctx` carries the authenticated user and the scopes of the app password used for the
//! request, so per-request state never requires building a new handler.
//!
//! - [`service`]: `DavService`, the entry point: request checks, `handle_guarded`, and the
//!   response information for the OC-* headers.
//! - [`ctx`]: `Ctx`, the per-request credentials value (identity, request details, caches).
//! - [`resolve`]: mapping of DAV paths through the app password's mounts.
//! - [`fs`]: `ScopedFs`, the `GuardedFileSystem<Ctx>` implementation (path mapping, virtual
//!   directories, permission checks).
//! - [`metadata`]: the `DavMetaData` wrapper that gives every entry a single ETag source.
//! - [`props`]: Nextcloud live properties and permissions.
//! - [`locks`]: the persistent `DavLockSystem`, keyed by storage path.
//! - [`report`]: the `oc:filter-files` favorites REPORT, served next to dav-server.
//! - [`oc_headers`]: the tower layer adding `OC-ETag`, `OC-FileId` and `X-NC-Permissions`.
//! - [`xml_limits`]: the size and nesting limits for XML request bodies.
//!
//! All metadata writes go through the `MetaStore` (see [`gono_server_core::meta`]).

pub mod ctx;
mod file;
pub mod fs;
pub mod identity;
pub mod locks;
pub mod metadata;
pub mod oc_headers;
pub mod props;
pub mod report;
pub mod resolve;
pub mod service;
pub mod xml_limits;

pub use ctx::{Ctx, PropfindKind, RequestInfo};
pub use fs::ScopedFs;
pub use identity::{Identity, Mount};
pub use oc_headers::OcHeadersLayer;
pub use service::{DavBody, DavService, OcInfo};
