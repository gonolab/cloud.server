//! Who a request acts as, and what it may reach.

use std::sync::Arc;

use gono_core::{Permission, RelPath, Username, app_passwords::Device};

/// One mount of the client's tree: `mount_path` (client side) shows `storage_path` (inside the
/// owner's storage) with read-only or read-write access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Path in the tree the client sees.
    pub mount_path: RelPath,
    /// Directory of the owner's storage shown there.
    pub storage_path: RelPath,
    /// Whether writes are allowed below this mount.
    pub writable: bool,
}

/// An authenticated device: the user, the app password it used, and that password's mounts.
///
/// Built once per request by the authenticator and shared (`Arc`) by everything that handles
/// the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Owner of every storage path this identity can reach.
    pub user_id: i64,
    /// Login name; also the WebDAV principal.
    pub username: Username,
    /// Display name of the user.
    pub display_name: String,
    /// The app password that authenticated the request.
    pub app_password_id: i64,
    /// Mounts, ordered by mount path. Mount paths are never nested.
    pub mounts: Vec<Mount>,
}

impl Identity {
    /// Wraps an authenticated app password.
    pub fn from_device(device: Device) -> Arc<Self> {
        Arc::new(Self {
            user_id: device.user_id,
            username: device.username,
            display_name: device.display_name,
            app_password_id: device.app_password_id,
            mounts: device
                .scopes
                .into_iter()
                .map(|scope| Mount {
                    mount_path: scope.mount_path,
                    storage_path: scope.storage_path,
                    writable: scope.permission == Permission::Full,
                })
                .collect(),
        })
    }

    /// Whether any mount allows writes.
    pub fn can_write_somewhere(&self) -> bool {
        self.mounts.iter().any(|mount| mount.writable)
    }
}
