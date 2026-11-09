//! `ScopedFs`: the `GuardedFileSystem<Ctx>` behind the single `DavHandler`.
//!
//! Responsibilities:
//!
//! - **Path mapping.** Translate the DAV path seen by the client into a storage `rel_path`
//!   inside the owner's directory below `storage.data_dir`, through the mount table of the
//!   app password in `Ctx` (`app_password_scopes`: `mount_path` -> `storage_path`). Reject
//!   `..`, absolute components and anything that would escape the owner's root, including
//!   through symlinks.
//! - **Virtual directories.** When scopes mount storage paths at nested client paths (for
//!   example `/Photos/Phone`), synthesize the read-only parent collections that do not exist in
//!   storage so clients can browse down to the mounts.
//! - **Permission checks.** Allow only reads through `view` scopes and refuse writes, moves and
//!   deletes that touch a virtual directory or cross between mounts with different permissions.
//! - **Metadata.** Report entries through the [`crate::metadata`] wrapper and route every
//!   change through the `MetaStore`, so ETags, file ids and the change log stay consistent with
//!   the file system.
