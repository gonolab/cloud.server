//! WebDAV layer of Gono Cloud, built on [`dav_server`].
//!
//! The server builds exactly **one** `DavHandler<Ctx>` at startup and calls `handle_guarded`
//! for every request under `/remote.php/dav/files/<user>/` (and the legacy `/remote.php/webdav/`
//! alias). `Ctx` carries the authenticated user and the scopes of the app password used for the
//! request, so per-request state never requires building a new handler.
//!
//! - [`fs`]: `ScopedFs`, the `GuardedFileSystem<Ctx>` implementation (path mapping, virtual
//!   directories, permission checks).
//! - [`metadata`]: the `DavMetaData` wrapper that gives every entry a single ETag source.
//! - [`locks`]: the persistent `DavLockSystem`.
//!
//! All metadata writes go through the `MetaStore` (see [`gono_core::meta`]).

pub mod ctx;
mod file;
pub mod fs;
pub mod identity;
pub mod locks;
pub mod metadata;
pub mod props;
pub mod resolve;

pub use ctx::{Ctx, PropfindKind, RequestInfo};
pub use fs::ScopedFs;
pub use identity::{Identity, Mount};
