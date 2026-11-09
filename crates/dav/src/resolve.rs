//! Mapping of DAV paths to storage locations.
//!
//! The single `DavHandler` runs without a path prefix, so the file system sees full request
//! paths. A path is first stripped of its WebDAV root, which must belong to the authenticated
//! user:
//!
//! - `/remote.php/dav/files/<username>` (the Nextcloud endpoint), or
//! - `/remote.php/webdav` (the legacy alias, always the authenticated user).
//!
//! The rest is the *client path*: validated and NFC-normalized like every storage path (see
//! [`gono_core::path`]). The identity's mounts then decide what it is:
//!
//! - inside a mount: a storage path below the mount's `storage_path`;
//! - a strict ancestor of one or more mount paths: a read-only *virtual* collection that only
//!   lists the way to the mounts (for an app password with mounts at `/a` and `/b`, `/` is
//!   virtual);
//! - anything else does not exist for this identity.
//!
//! All of this is lexical; nothing here touches the disk.

use dav_server::{davpath::DavPath, fs::FsError};
use gono_core::{RelPath, path::PathError};

use crate::identity::{Identity, Mount};

/// Prefix of the per-user Nextcloud WebDAV endpoint (followed by the username).
pub const FILES_ROOT: &str = "/remote.php/dav/files/";

/// The legacy WebDAV alias of the authenticated user's files.
pub const WEBDAV_ROOT: &str = "/remote.php/webdav";

/// Where a client path leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// Inside a mount.
    Storage {
        /// Index into [`Identity::mounts`].
        mount: usize,
        /// The client path.
        client: RelPath,
        /// The path inside the owner's storage.
        storage: RelPath,
    },
    /// A collection on the way to one or more mounts.
    Virtual {
        /// The client path.
        client: RelPath,
    },
}

impl Location {
    /// The client path.
    pub fn client(&self) -> &RelPath {
        match self {
            Self::Storage { client, .. } | Self::Virtual { client } => client,
        }
    }

    /// The storage path, unless this is a virtual collection.
    pub fn storage(&self) -> Option<&RelPath> {
        match self {
            Self::Storage { storage, .. } => Some(storage),
            Self::Virtual { .. } => None,
        }
    }

    /// The mount, unless this is a virtual collection.
    pub fn mount<'a>(&self, identity: &'a Identity) -> Option<&'a Mount> {
        match self {
            Self::Storage { mount, .. } => identity.mounts.get(*mount),
            Self::Virtual { .. } => None,
        }
    }

    /// Whether this is the root of its mount (which can be neither deleted nor renamed).
    pub fn is_mount_root(&self, identity: &Identity) -> bool {
        self.mount(identity)
            .is_some_and(|mount| mount.mount_path == *self.client())
    }

    /// Whether writes are allowed here.
    pub fn writable(&self, identity: &Identity) -> bool {
        self.mount(identity).is_some_and(|mount| mount.writable)
    }
}

/// Length in bytes of the WebDAV root at the start of `path`, if it is one of the identity's
/// roots and is followed by the end of the path or a `/`.
pub fn dav_root_len(identity: &Identity, path: &[u8]) -> Option<usize> {
    let user_root = format!("{FILES_ROOT}{}", identity.username);
    [user_root.as_bytes(), WEBDAV_ROOT.as_bytes()]
        .into_iter()
        .find(|root| path.starts_with(root) && matches!(path.get(root.len()), None | Some(b'/')))
        .map(<[u8]>::len)
}

/// Splits a full DAV path into the client path.
pub fn client_path(identity: &Identity, path: &DavPath) -> Result<RelPath, FsError> {
    let bytes = path.as_bytes();
    let root = dav_root_len(identity, bytes).ok_or(FsError::NotFound)?;
    RelPath::from_raw_segments(bytes[root..].split(|&b| b == b'/')).map_err(|err| match err {
        PathError::TooLong => FsError::PathTooLong,
        _ => FsError::Forbidden,
    })
}

/// Resolves a full DAV path for `identity`.
pub fn resolve(identity: &Identity, path: &DavPath) -> Result<Location, FsError> {
    resolve_client(identity, client_path(identity, path)?)
}

/// Resolves a client path for `identity`.
pub fn resolve_client(identity: &Identity, client: RelPath) -> Result<Location, FsError> {
    for (index, mount) in identity.mounts.iter().enumerate() {
        if let Some(below) = client.strip_prefix(&mount.mount_path) {
            let storage = mount.storage_path.join_path(&below);
            return Ok(Location::Storage {
                mount: index,
                client,
                storage,
            });
        }
    }
    if identity
        .mounts
        .iter()
        .any(|mount| mount.mount_path.starts_with(&client))
    {
        return Ok(Location::Virtual { client });
    }
    Err(FsError::NotFound)
}

/// The names listed in the virtual collection `client`, each with its client path.
pub fn virtual_children(identity: &Identity, client: &RelPath) -> Vec<(String, RelPath)> {
    let mut children: Vec<(String, RelPath)> = Vec::new();
    for mount in &identity.mounts {
        let Some(below) = mount.mount_path.strip_prefix(client) else {
            continue;
        };
        let Some(name) = below.segments().next() else {
            continue;
        };
        if !children.iter().any(|(existing, _)| existing == name) {
            children.push((name.to_owned(), client.join(name)));
        }
    }
    children
}

/// The mounts at or below the virtual collection `client`.
pub fn mounts_below<'a>(identity: &'a Identity, client: &RelPath) -> Vec<&'a Mount> {
    identity
        .mounts
        .iter()
        .filter(|mount| mount.mount_path.starts_with(client))
        .collect()
}

/// The client path at which `storage` is visible through the mount `mount_index`, if it is.
pub fn client_for_storage(
    identity: &Identity,
    mount_index: usize,
    storage: &RelPath,
) -> Option<RelPath> {
    let mount = identity.mounts.get(mount_index)?;
    let below = storage.strip_prefix(&mount.storage_path)?;
    Some(mount.mount_path.join_path(&below))
}

/// Builds the DAV path `<root><client path>` from a WebDAV root such as
/// `/remote.php/dav/files/alice`.
pub fn dav_path(root: &[u8], client: &RelPath, collection: bool) -> Option<DavPath> {
    let mut url = String::from_utf8_lossy(root).into_owned();
    for segment in client.segments() {
        url.push('/');
        url.push_str(&encode_segment(segment));
    }
    if collection || client.is_root() {
        url.push('/');
    }
    DavPath::new(&url).ok()
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use gono_core::Username;

    use super::*;

    fn mount(mount: &str, storage: &str, writable: bool) -> Mount {
        Mount {
            mount_path: RelPath::parse(mount).unwrap(),
            storage_path: RelPath::parse(storage).unwrap(),
            writable,
        }
    }

    fn identity(mounts: Vec<Mount>) -> Identity {
        Identity {
            user_id: 7,
            username: Username::new("alice").unwrap(),
            display_name: "Alice".into(),
            app_password_id: 1,
            mounts,
        }
    }

    fn dav(path: &str) -> DavPath {
        DavPath::new(path).unwrap()
    }

    #[test]
    fn strips_both_webdav_roots_of_the_user_only() {
        let id = identity(vec![mount("/", "/", true)]);
        for (path, client) in [
            ("/remote.php/dav/files/alice", ""),
            ("/remote.php/dav/files/alice/", ""),
            ("/remote.php/dav/files/alice/a/b.txt", "a/b.txt"),
            ("/remote.php/webdav/a", "a"),
            ("/remote.php/webdav", ""),
        ] {
            assert_eq!(
                client_path(&id, &dav(path)).unwrap().as_str(),
                client,
                "{path}"
            );
        }
        for path in [
            "/remote.php/dav/files/bob/a",
            "/remote.php/dav/files/alicex/a",
            "/remote.php/webdavx",
            "/other",
        ] {
            assert_eq!(
                client_path(&id, &dav(path)),
                Err(FsError::NotFound),
                "{path}"
            );
        }
    }

    #[test]
    fn client_paths_are_normalized_to_nfc() {
        let id = identity(vec![mount("/", "/", true)]);
        let nfd = client_path(&id, &dav("/remote.php/webdav/caf%65%CC%81")).unwrap();
        assert_eq!(nfd.as_str(), "caf\u{e9}");
        let long = format!("/remote.php/webdav/{}", "x".repeat(300));
        assert_eq!(client_path(&id, &dav(&long)), Err(FsError::PathTooLong));
    }

    #[test]
    fn mounts_map_client_paths_to_storage() {
        let id = identity(vec![
            mount("/acc-full", "/acc-scope/full", true),
            mount("/acc-view", "/acc-scope/view", false),
        ]);
        let location = resolve(&id, &dav("/remote.php/webdav/acc-view/x/y.txt")).unwrap();
        assert_eq!(
            location.storage().unwrap().as_str(),
            "acc-scope/view/x/y.txt"
        );
        assert!(!location.writable(&id));
        assert!(!location.is_mount_root(&id));

        let root = resolve(&id, &dav("/remote.php/webdav/acc-full")).unwrap();
        assert!(root.is_mount_root(&id));
        assert!(root.writable(&id));

        assert_eq!(
            resolve(&id, &dav("/remote.php/webdav/")).unwrap(),
            Location::Virtual {
                client: RelPath::root()
            }
        );
        assert_eq!(
            resolve(&id, &dav("/remote.php/webdav/acc-scope/view")),
            Err(FsError::NotFound),
            "storage paths are not client paths"
        );
        assert_eq!(
            resolve(&id, &dav("/remote.php/webdav/acc-ful")),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn virtual_collections_list_the_way_to_the_mounts() {
        let id = identity(vec![
            mount("/a/b", "/x", true),
            mount("/a/c/d", "/y", false),
            mount("/e", "/z", false),
        ]);
        let names = |client: &str| -> Vec<String> {
            virtual_children(&id, &RelPath::parse(client).unwrap())
                .into_iter()
                .map(|(name, _)| name)
                .collect()
        };
        assert_eq!(names(""), ["a", "e"]);
        assert_eq!(names("a"), ["b", "c"]);
        assert_eq!(names("a/c"), ["d"]);
        assert!(matches!(
            resolve(&id, &dav("/remote.php/webdav/a/c")).unwrap(),
            Location::Virtual { .. }
        ));
        assert_eq!(mounts_below(&id, &RelPath::parse("a").unwrap()).len(), 2);
    }

    #[test]
    fn storage_paths_map_back_to_client_paths() {
        let id = identity(vec![mount("/Photos", "/Media/Photos", false)]);
        let storage = RelPath::parse("Media/Photos/2024/a b.jpg").unwrap();
        let client = client_for_storage(&id, 0, &storage).unwrap();
        assert_eq!(client.as_str(), "Photos/2024/a b.jpg");
        assert_eq!(
            client_for_storage(&id, 0, &RelPath::parse("Media").unwrap()),
            None
        );

        let path = dav_path(b"/remote.php/dav/files/alice", &client, false).unwrap();
        assert_eq!(
            path.as_bytes(),
            b"/remote.php/dav/files/alice/Photos/2024/a b.jpg"
        );
        let root = dav_path(b"/remote.php/webdav", &RelPath::root(), true).unwrap();
        assert_eq!(root.as_bytes(), b"/remote.php/webdav/");
    }
}
