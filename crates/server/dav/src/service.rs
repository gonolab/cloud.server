//! `DavService`: one `DavHandler<Ctx>` for every WebDAV request of an authenticated identity.
//!
//! Before a request reaches dav-server, a few checks run that dav-server cannot express
//! through the file system, all of them answered without touching dav-server's output:
//!
//! - Request paths and `Destination` headers whose segments decode to `.`, `..`, contain NUL
//!   or an encoded `/` are rejected with 400. (dav-server would resolve `..` itself, so
//!   `a/%2e%2e/b` would silently become `b`.)
//! - A `Destination` outside the identity's WebDAV roots (for example another user's tree) is
//!   refused with 403.
//! - `PROPFIND` with `Depth: infinity` is refused with 403 and `<D:propfind-finite-depth/>`.
//! - `LOCK` on a read-only location is refused with 403 (a lock system can only say 423), as
//!   are `MOVE` from and `COPY`/`MOVE` into read-only locations, so that clients get a plain
//!   403 instead of a multistatus.
//! - `GET`/`HEAD` on a collection answer 200 with an empty body, as Nextcloud does; dav-server
//!   would redirect or refuse.
//! - `X-OC-MTime` and `X-OC-CTime` with a fraction of a second (NextcloudKit sends them) are
//!   truncated to whole seconds, as Nextcloud does; dav-server would refuse them with 400.
//!
//! Everything else is handled by dav-server through `handle_guarded`. Afterwards the entry the
//! request produced or read (PUT, MKCOL, MOVE, COPY, GET, HEAD) is attached to the response as
//! an [`OcInfo`] extension, from which [`crate::oc_headers::OcHeadersLayer`] adds the
//! `OC-ETag`, `OC-FileId` and `X-NC-Permissions` headers.

use std::{io, sync::Arc};

use bytes::Bytes;
use dav_server::{DavHandler, davpath::DavPath, fs::FsError};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body::Body;
use http_body_util::{BodyExt as _, Empty, Full, Limited, combinators::UnsyncBoxBody};

use crate::{
    ctx::{Ctx, PropfindKind, RequestInfo, destination_path, oc_time_seconds},
    fs::ScopedFs,
    identity::Identity,
    locks::{CtxBody, with_ctx},
    metadata::Entry,
    props,
    resolve::{self, Location},
};

/// Response body of [`DavService::handle`].
pub type DavBody = UnsyncBoxBody<Bytes, io::Error>;

/// Largest accepted PROPFIND body (dav-server's own limit for request bodies it parses).
const MAX_PROPFIND_BODY: usize = 64 * 1024;

/// What the OC-* response headers report, attached to responses as an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcInfo {
    /// Quoted ETag (`OC-ETag`).
    pub etag: String,
    /// `oc:id` of the entry (`OC-FileId`), if it has one.
    pub file_id: Option<String>,
    /// `oc:permissions` (`X-NC-Permissions`).
    pub permissions: &'static str,
    /// `X-OC-MTime` was applied (`X-OC-MTime: accepted`).
    pub mtime_accepted: bool,
}

impl OcInfo {
    /// The headers describing `entry`.
    pub fn for_entry(entry: &Entry, instance_id: &str, mtime_accepted: bool) -> Self {
        Self {
            etag: format!("\"{}\"", entry.etag),
            file_id: entry.file_id.map(|id| props::oc_id(id, instance_id)),
            permissions: entry.permissions,
            mtime_accepted,
        }
    }
}

/// The WebDAV endpoint. Cheap to clone.
#[derive(Clone)]
pub struct DavService {
    handler: DavHandler<Ctx>,
    fs: ScopedFs,
}

impl std::fmt::Debug for DavService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DavService").finish_non_exhaustive()
    }
}

/// An empty response with `status`.
pub(crate) fn simple(status: StatusCode) -> Response<DavBody> {
    let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

/// A response with an XML body.
pub(crate) fn xml_body(status: StatusCode, body: String) -> Response<DavBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

fn xml_error(status: StatusCode, condition: &str) -> Response<DavBody> {
    xml_body(
        status,
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error xmlns:D=\"DAV:\"><D:{condition}/></D:error>\n"
        ),
    )
}

/// Whether every segment of a percent-encoded path is acceptable (see the module docs).
/// Rewrites `X-OC-MTime` and `X-OC-CTime` values with a fraction (`1700000000.25`, as
/// NextcloudKit sends them) to whole seconds. dav-server only parses whole seconds and answers
/// 400 otherwise, while Nextcloud truncates. Values that are not numbers stay as they are, so
/// dav-server still refuses them.
fn truncate_oc_times(headers: &mut HeaderMap) {
    for name in ["x-oc-mtime", "x-oc-ctime"] {
        let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) else {
            continue;
        };
        if !value.contains('.') {
            continue;
        }
        if let Some(seconds) = oc_time_seconds(value)
            && let Ok(whole) = HeaderValue::from_str(&seconds.to_string())
        {
            headers.insert(name, whole);
        }
    }
}

pub fn path_is_clean(raw: &str) -> bool {
    raw.split('/').all(|segment| {
        let decoded: Vec<u8> = percent_decode(segment.as_bytes());
        !(decoded == b"." || decoded == b".." || decoded.contains(&0) || decoded.contains(&b'/'))
    })
}

fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%'
            && let Some(hex) = input.get(index + 1..index + 3)
            && let Ok(hex) = std::str::from_utf8(hex)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(input[index]);
        index += 1;
    }
    out
}

/// The raw (percent-encoded) path of a `Destination` header, exactly as sent.
///
/// URL parsers resolve dot segments (including `%2e%2e`) while parsing, which would hide them
/// from [`path_is_clean`], so the path is cut out of the header text instead.
fn raw_destination(value: &str) -> Option<String> {
    let path = if value.starts_with('/') {
        value
    } else {
        let (scheme, rest) = value.split_once("://")?;
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            return None;
        }
        &rest[rest.find('/')?..]
    };
    Some(path.split(['?', '#']).next().unwrap_or_default().to_owned())
}

/// Parses a `Destination` header of `identity` with the checks [`DavService::handle`] applies:
/// `400` for a malformed value or one whose path has dot segments, NUL bytes or encoded
/// slashes, `403` for a location outside the identity's WebDAV roots (another user's tree).
pub fn parse_destination(identity: &Identity, value: &str) -> Result<DavPath, StatusCode> {
    let raw = raw_destination(value).ok_or(StatusCode::BAD_REQUEST)?;
    if !path_is_clean(&raw) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if resolve::dav_root_len(identity, &percent_decode(raw.as_bytes())).is_none() {
        return Err(StatusCode::FORBIDDEN);
    }
    destination_path(value).ok_or(StatusCode::BAD_REQUEST)
}

impl DavService {
    /// Wraps the single handler and its file system.
    pub fn new(handler: DavHandler<Ctx>, fs: ScopedFs) -> Self {
        Self { handler, fs }
    }

    /// The file system behind the handler.
    pub fn fs(&self) -> &ScopedFs {
        &self.fs
    }

    /// Handles one WebDAV request of `identity`.
    pub async fn handle<B>(&self, identity: Arc<Identity>, request: Request<B>) -> Response<DavBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let (mut parts, body) = request.into_parts();
        if !path_is_clean(parts.uri.path()) {
            return simple(StatusCode::BAD_REQUEST);
        }
        truncate_oc_times(&mut parts.headers);
        let destination = parts
            .headers
            .get(header::HeaderName::from_static("destination"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if let Some(destination) = &destination
            && let Err(status) = parse_destination(&identity, destination)
        {
            return simple(status);
        }

        let mut info = RequestInfo::from_parts(&parts);
        let method = parts.method.clone();
        let is_propfind = method.as_str() == "PROPFIND";
        if is_propfind
            && parts
                .headers
                .get("depth")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|depth| depth.trim().eq_ignore_ascii_case("infinity"))
        {
            return xml_error(StatusCode::FORBIDDEN, "propfind-finite-depth");
        }

        // PROPFIND bodies are small and parsed by dav-server anyway; read them here to learn
        // whether dead properties are wanted.
        let mut body = Some(body);
        let propfind_body = if is_propfind {
            let body = body.take().expect("the body is read once");
            match Limited::new(body, MAX_PROPFIND_BODY).collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    info.propfind = PropfindKind::of_body(&bytes);
                    Some(bytes)
                }
                Err(_) => return simple(StatusCode::PAYLOAD_TOO_LARGE),
            }
        } else {
            None
        };

        let ctx = Ctx::new(identity.clone(), info);
        if let Some(response) = self.preflight(&ctx, &method).await {
            return response;
        }

        let principal = identity.username.to_string();
        let response = match propfind_body {
            Some(bytes) => {
                let request = Request::from_parts(parts, Full::new(bytes));
                with_ctx(
                    ctx.clone(),
                    self.handler.handle_guarded(request, principal, ctx.clone()),
                )
                .await
            }
            None => {
                let body = body.take().expect("only PROPFIND bodies are read here");
                let request = Request::from_parts(parts, body);
                with_ctx(
                    ctx.clone(),
                    self.handler.handle_guarded(request, principal, ctx.clone()),
                )
                .await
            }
        };

        let (mut parts, body) = response.into_parts();
        if parts.status.is_success()
            && matches!(
                method.as_str(),
                "GET" | "HEAD" | "PUT" | "MKCOL" | "MOVE" | "COPY"
            )
            && let Some(entry) = ctx.outcome()
        {
            let mtime_accepted = method == Method::PUT && ctx.request().oc_mtime.is_some();
            parts
                .extensions
                .insert(self.oc_info(&entry, mtime_accepted));
        }
        Response::from_parts(parts, CtxBody::new(ctx, body).boxed_unsync())
    }

    fn oc_info(&self, entry: &Entry, mtime_accepted: bool) -> OcInfo {
        OcInfo::for_entry(entry, self.fs.instance_id(), mtime_accepted)
    }

    /// The checks described in the module documentation. Returns a response when the request
    /// is answered here.
    async fn preflight(&self, ctx: &Ctx, method: &Method) -> Option<Response<DavBody>> {
        let identity = ctx.identity();
        let path = ctx.request().path.as_ref()?;
        match method.as_str() {
            "LOCK" => match resolve::resolve(identity, path) {
                Ok(location) if !location.writable(identity) => Some(simple(StatusCode::FORBIDDEN)),
                Err(FsError::NotFound) if !writable_target(identity, path) => {
                    Some(simple(StatusCode::FORBIDDEN))
                }
                _ => None,
            },
            "MOVE" | "COPY" => {
                let destination = ctx.request().destination.as_ref()?;
                let source_ok = method.as_str() == "COPY"
                    || resolve::resolve(identity, path)
                        .is_ok_and(|l| l.writable(identity) && !l.is_mount_root(identity));
                let destination_ok = match resolve::resolve(identity, destination) {
                    Ok(location) => {
                        location.writable(identity) && !location.is_mount_root(identity)
                    }
                    Err(_) => writable_target(identity, destination),
                };
                (!source_ok || !destination_ok).then(|| simple(StatusCode::FORBIDDEN))
            }
            "GET" | "HEAD" => {
                let entry = self.fs.entry(ctx, path).await.ok()?;
                if !entry.is_dir() {
                    return None;
                }
                let mut response = simple(StatusCode::OK);
                if let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", entry.etag)) {
                    response.headers_mut().insert(header::ETAG, etag);
                }
                response
                    .extensions_mut()
                    .insert(self.oc_info(&entry, false));
                Some(response)
            }
            _ => None,
        }
    }
}

/// Whether a path that does not exist yet could be created: its parent must lie inside a
/// writable mount (the file system enforces the details).
fn writable_target(identity: &Identity, path: &DavPath) -> bool {
    let Ok(client) = resolve::client_path(identity, path) else {
        return false;
    };
    let Some(parent) = client.parent() else {
        return false;
    };
    matches!(
        resolve::resolve_client(identity, parent),
        Ok(location @ Location::Storage { .. }) if location.writable(identity)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_segments_nul_and_encoded_slashes_are_unclean() {
        for clean in [
            "/a/b",
            "/remote.php/dav/files/a/x%20y",
            "/a/...",
            "/a/.hidden/",
        ] {
            assert!(path_is_clean(clean), "{clean}");
        }
        for dirty in [
            "/a/../b",
            "/a/%2e%2e/b",
            "/a/%2E./b",
            "/a/./b",
            "/a/%2e",
            "/a/x%00y",
            "/a/..%2Fb",
            "/a/%2f",
        ] {
            assert!(!path_is_clean(dirty), "{dirty}");
        }
    }

    #[test]
    fn destinations_are_parsed_like_dav_server() {
        assert_eq!(
            raw_destination("http://h/remote.php/webdav/a%20b?x").as_deref(),
            Some("/remote.php/webdav/a%20b")
        );
        assert_eq!(raw_destination("/a/b?q").as_deref(), Some("/a/b"));
        assert_eq!(raw_destination("not a url"), None);
        assert_eq!(
            raw_destination("http://h:8080/x/nested/%2e%2e/e.txt").as_deref(),
            Some("/x/nested/%2e%2e/e.txt"),
            "dot segments are kept for the check"
        );
        assert!(destination_path("http://h/remote.php/webdav/a%20b").is_some());
    }
}
