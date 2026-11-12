//! File operations of the web UI as in-process WebDAV requests.
//!
//! Every change goes through the same [`DavService`](gono_server_dav::DavService) as the sync
//! clients' requests, with the session's identity: path checks, permissions, locks, ETag and
//! file id bookkeeping, the change log and notify_push all apply unchanged. The requests use
//! the legacy root `/remote.php/webdav/`, which always means the identity's own files.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use gono_server_core::RelPath;
use gono_server_dav::{DavBody, Identity, resolve::WEBDAV_ROOT};

use super::view::encode_segment;
use crate::{app::AppState, i18n::Text};

/// Why an operation failed, as the UI explains it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpError {
    /// Something with that name exists.
    Exists,
    /// The name is not allowed.
    Name,
    /// The entry or its folder is gone.
    NotFound,
    /// The location cannot be changed.
    Forbidden,
    /// A WebDAV lock of another client.
    Locked,
    /// Not enough free space.
    Storage,
    /// A folder into itself.
    IntoItself,
    /// Anything else (logged).
    Failed,
}

impl OpError {
    /// The code carried in a redirect's query.
    pub fn code(self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::Name => "name",
            Self::NotFound => "gone",
            Self::Forbidden => "forbidden",
            Self::Locked => "locked",
            Self::Storage => "storage",
            Self::IntoItself => "into-itself",
            Self::Failed => "failed",
        }
    }

    /// The error a redirect's code names.
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "exists" => Self::Exists,
            "name" => Self::Name,
            "gone" => Self::NotFound,
            "forbidden" => Self::Forbidden,
            "locked" => Self::Locked,
            "storage" => Self::Storage,
            "into-itself" => Self::IntoItself,
            "failed" => Self::Failed,
            _ => return None,
        })
    }

    /// The explanation.
    pub fn message(self, t: &Text) -> &'static str {
        match self {
            Self::Exists => t.err_exists,
            Self::Name => t.err_name,
            Self::NotFound => t.err_not_found,
            Self::Forbidden => t.err_forbidden,
            Self::Locked => t.err_locked,
            Self::Storage => t.err_storage,
            Self::IntoItself => t.err_into_itself,
            Self::Failed => t.err_failed,
        }
    }

    /// The failure a WebDAV status stands for; `None` for success.
    pub fn from_status(status: StatusCode) -> Option<Self> {
        if status.is_success() {
            return None;
        }
        Some(match status {
            StatusCode::NOT_FOUND | StatusCode::CONFLICT => Self::NotFound,
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Self::Forbidden,
            StatusCode::METHOD_NOT_ALLOWED | StatusCode::PRECONDITION_FAILED => Self::Exists,
            StatusCode::LOCKED => Self::Locked,
            StatusCode::INSUFFICIENT_STORAGE | StatusCode::PAYLOAD_TOO_LARGE => Self::Storage,
            StatusCode::BAD_REQUEST => Self::Name,
            _ => Self::Failed,
        })
    }
}

/// The WebDAV path of client path `rel` (collections end with `/`).
pub fn dav_path(rel: &RelPath, collection: bool) -> String {
    let mut out = String::from(WEBDAV_ROOT);
    for segment in rel.segments() {
        out.push('/');
        out.push_str(&encode_segment(segment));
    }
    if collection || rel.is_root() {
        out.push('/');
    }
    out
}

/// Sends one WebDAV request for `identity`.
pub async fn dav(
    state: &AppState,
    identity: &Arc<Identity>,
    method: &str,
    uri: &str,
    headers: &[(HeaderName, HeaderValue)],
    body: Body,
) -> Response<DavBody> {
    let mut request = Request::new(body);
    *request.method_mut() = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    match uri.parse() {
        Ok(parsed) => *request.uri_mut() = parsed,
        Err(_) => {
            let mut response = Response::new(DavBody::default());
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return response;
        }
    }
    for (name, value) in headers {
        request.headers_mut().append(name.clone(), value.clone());
    }
    state.dav.handle(identity.clone(), request).await
}

/// Logs an unexpected failure.
fn checked(status: StatusCode, what: &str, rel: &RelPath) -> Result<(), OpError> {
    match OpError::from_status(status) {
        None => Ok(()),
        Some(OpError::Failed) => {
            tracing::warn!(%status, path = %rel, "web file UI: {what} failed");
            Err(OpError::Failed)
        }
        Some(err) => Err(err),
    }
}

/// Creates folder `rel`.
pub async fn mkdir(
    state: &AppState,
    identity: &Arc<Identity>,
    rel: &RelPath,
) -> Result<(), OpError> {
    let response = dav(
        state,
        identity,
        "MKCOL",
        &dav_path(rel, true),
        &[],
        Body::empty(),
    )
    .await;
    checked(response.status(), "MKCOL", rel)
}

/// Deletes `rel` (a folder with everything inside).
pub async fn delete(
    state: &AppState,
    identity: &Arc<Identity>,
    rel: &RelPath,
    is_dir: bool,
) -> Result<(), OpError> {
    let response = dav(
        state,
        identity,
        "DELETE",
        &dav_path(rel, is_dir),
        &[],
        Body::empty(),
    )
    .await;
    checked(response.status(), "DELETE", rel)
}

/// Moves (or renames) `from` to `to`, never over an existing entry.
pub async fn move_to(
    state: &AppState,
    identity: &Arc<Identity>,
    from: &RelPath,
    to: &RelPath,
    is_dir: bool,
) -> Result<(), OpError> {
    if is_dir && to.starts_with(from) {
        return Err(OpError::IntoItself);
    }
    if from == to {
        return Ok(());
    }
    let Ok(destination) = HeaderValue::from_str(&dav_path(to, is_dir)) else {
        return Err(OpError::Name);
    };
    let headers = [
        (HeaderName::from_static("destination"), destination),
        (
            HeaderName::from_static("overwrite"),
            HeaderValue::from_static("F"),
        ),
    ];
    let response = dav(
        state,
        identity,
        "MOVE",
        &dav_path(from, is_dir),
        &headers,
        Body::empty(),
    )
    .await;
    checked(response.status(), "MOVE", from)
}
