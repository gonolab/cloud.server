//! Chunked upload v2 (`/remote.php/dav/uploads/<user>/<upload_id>/`).
//!
//! - `MKCOL` starts an upload session (`upload_sessions`) and records the `Destination` header
//!   and the optional `OC-Total-Length`.
//! - `PUT` of numbered chunks writes them into a staging directory on the same file system as
//!   the data directory.
//! - `MOVE` of `.file` to the destination assembles the chunks, verifies the total length and
//!   commits the result through the `MetaStore` as one change.
//! - `DELETE` aborts the upload; expired sessions and their chunks are purged in the
//!   background.
