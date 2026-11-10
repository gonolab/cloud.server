//! `Ctx`: the per-request credentials value passed to every `GuardedFileSystem` call.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use dav_server::davpath::DavPath;
use gono_server_core::{RelPath, meta::DeadProp};
use http::Method;

use crate::{identity::Identity, metadata::Entry};

/// What a PROPFIND request body asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PropfindKind {
    /// `<D:prop>`: only the listed properties.
    Prop,
    /// `<D:allprop>` or an empty body: live properties and all dead properties.
    #[default]
    AllProp,
    /// `<D:propname>`: property names only.
    PropName,
}

/// The parts of the request that file system calls depend on.
///
/// dav-server hands the file system single paths. A few operations need more context: the
/// collection COPY is performed as one subtree copy (see [`crate::fs`]), the PUT applies
/// `X-OC-MTime`, PROPFIND lists dead properties only for `allprop`.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// HTTP method.
    pub method: Method,
    /// Request target, normalized the way dav-server normalizes it.
    pub path: Option<DavPath>,
    /// `Destination` of COPY and MOVE, normalized the same way.
    pub destination: Option<DavPath>,
    /// `Depth: 0` was sent.
    pub depth_zero: bool,
    /// `X-OC-MTime` of a PUT, UNIX seconds.
    pub oc_mtime: Option<i64>,
    /// `X-OC-CTime` of a PUT or of the `MOVE` that completes a chunked upload, UNIX seconds:
    /// the creation time to record for the written file.
    pub oc_ctime: Option<i64>,
    /// Kind of PROPFIND body.
    pub propfind: PropfindKind,
}

impl RequestInfo {
    /// Information for a request that only reads (used by tests and internal lookups).
    pub fn new(method: Method) -> Self {
        Self {
            method,
            path: None,
            destination: None,
            depth_zero: false,
            oc_mtime: None,
            oc_ctime: None,
            propfind: PropfindKind::default(),
        }
    }

    /// Extracts what the file system needs from the request head. The PROPFIND body kind is
    /// set separately (see [`PropfindKind::of_body`]).
    pub fn from_parts(parts: &http::request::Parts) -> Self {
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
        };
        Self {
            method: parts.method.clone(),
            path: DavPath::new(parts.uri.path()).ok(),
            destination: header("destination").and_then(destination_path),
            depth_zero: header("depth") == Some("0"),
            oc_mtime: header("x-oc-mtime")
                .and_then(oc_time_seconds)
                .filter(|&mtime| mtime > 0),
            oc_ctime: oc_ctime(&parts.headers),
            propfind: PropfindKind::default(),
        }
    }
}

/// `X-OC-CTime` (UNIX seconds, a fraction truncated), if sent and positive.
pub fn oc_ctime(headers: &http::HeaderMap) -> Option<i64> {
    headers
        .get("x-oc-ctime")
        .and_then(|value| value.to_str().ok())
        .and_then(oc_time_seconds)
        .filter(|&ctime| ctime > 0)
}

/// Parses an `X-OC-MTime` or `X-OC-CTime` value the way Nextcloud does: UNIX seconds, where a
/// fraction is accepted and truncated (NextcloudKit, the iOS app, sends `1700000000.25`).
/// `None` for anything that is not a plain decimal number.
pub fn oc_time_seconds(value: &str) -> Option<i64> {
    let value = value.trim();
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let digits = whole.strip_prefix(['+', '-']).unwrap_or(whole);
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    whole.parse().ok()
}

/// Parses a `Destination` header (absolute URL or absolute path) the way dav-server does.
pub fn destination_path(value: &str) -> Option<DavPath> {
    if value.starts_with('/') {
        return DavPath::new(value).ok();
    }
    let url = url::Url::parse(value).ok()?;
    DavPath::new(url.path()).ok()
}

impl PropfindKind {
    /// Classifies a PROPFIND body. Bodies that do not parse are left to dav-server, which
    /// rejects them.
    pub fn of_body(body: &[u8]) -> Self {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Self::AllProp;
        }
        let Ok(root) = xmltree::Element::parse(body) else {
            return Self::AllProp;
        };
        let has = |name: &str| {
            root.children.iter().any(|child| {
                child.as_element().is_some_and(|element| {
                    element.name == name && element.namespace.as_deref() == Some("DAV:")
                })
            })
        };
        if has("prop") {
            Self::Prop
        } else if has("propname") {
            Self::PropName
        } else {
            Self::AllProp
        }
    }
}

/// The value dav-server passes to every file system call of one request. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Ctx(Arc<CtxInner>);

#[derive(Debug)]
struct CtxInner {
    identity: Arc<Identity>,
    request: RequestInfo,
    /// Entries resolved during this request, keyed by storage path. dav-server asks for each
    /// live property separately with only the path; the cache answers those calls without
    /// touching the disk or the database again.
    cache: Mutex<HashMap<RelPath, Arc<Entry>>>,
    /// The entry the response is about (OC-ETag, OC-FileId, X-NC-Permissions headers).
    outcome: Mutex<Option<Arc<Entry>>>,
    /// Dead properties of entries, by file id. dav-server asks for every requested property
    /// of every entry separately, and clients request dozens of properties the server does not
    /// know; the cache loads each entry's dead properties once (a whole listing at once, see
    /// `ScopedFs::read_dir`) instead of querying for each property.
    dead_props: Mutex<HashMap<i64, Arc<[DeadProp]>>>,
}

impl Ctx {
    /// Creates the context of one request.
    pub fn new(identity: Arc<Identity>, request: RequestInfo) -> Self {
        Self(Arc::new(CtxInner {
            identity,
            request,
            cache: Mutex::new(HashMap::new()),
            outcome: Mutex::new(None),
            dead_props: Mutex::new(HashMap::new()),
        }))
    }

    /// Who the request acts as.
    pub fn identity(&self) -> &Identity {
        &self.0.identity
    }

    /// The request.
    pub fn request(&self) -> &RequestInfo {
        &self.0.request
    }

    /// Whether the request is handled with the given method.
    pub fn is(&self, method: &Method) -> bool {
        self.0.request.method == *method
    }

    pub(crate) fn cached(&self, storage: &RelPath) -> Option<Arc<Entry>> {
        lock(&self.0.cache).get(storage).cloned()
    }

    pub(crate) fn remember(&self, storage: RelPath, entry: Arc<Entry>) {
        lock(&self.0.cache).insert(storage, entry);
    }

    pub(crate) fn forget(&self, storage: &RelPath) {
        let mut cache = lock(&self.0.cache);
        cache.retain(|path, _| !path.starts_with(storage));
    }

    pub(crate) fn cached_dead_props(&self, file_id: i64) -> Option<Arc<[DeadProp]>> {
        lock(&self.0.dead_props).get(&file_id).cloned()
    }

    pub(crate) fn remember_dead_props(&self, file_id: i64, props: Arc<[DeadProp]>) {
        lock(&self.0.dead_props).insert(file_id, props);
    }

    pub(crate) fn forget_dead_props(&self, file_id: i64) {
        lock(&self.0.dead_props).remove(&file_id);
    }

    /// Records the entry the response describes.
    pub(crate) fn set_outcome(&self, entry: Arc<Entry>) {
        *lock(&self.0.outcome) = Some(entry);
    }

    /// The entry the response describes, if the request produced or read one.
    pub fn outcome(&self) -> Option<Arc<Entry>> {
        lock(&self.0.outcome).clone()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::oc_time_seconds;

    #[test]
    fn oc_times_accept_fractions_like_nextcloud() {
        assert_eq!(oc_time_seconds("1700000000"), Some(1_700_000_000));
        // NextcloudKit sends `timeIntervalSince1970` as is.
        assert_eq!(oc_time_seconds("1700000000.123456"), Some(1_700_000_000));
        assert_eq!(oc_time_seconds(" 1700000000.9 "), Some(1_700_000_000));
        assert_eq!(oc_time_seconds("1700000000."), Some(1_700_000_000));
        assert_eq!(oc_time_seconds("+5.5"), Some(5));
        assert_eq!(oc_time_seconds("-5.5"), Some(-5));
        for malformed in [
            "",
            ".5",
            "abc",
            "1.7e9",
            "0x10",
            "1.2.3",
            "1 2",
            "1700000000.5s",
        ] {
            assert_eq!(oc_time_seconds(malformed), None, "{malformed:?}");
        }
    }
}
