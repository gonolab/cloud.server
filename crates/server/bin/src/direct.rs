//! Direct download links, which the Nextcloud apps need to play video and audio that is not
//! downloaded yet: they hand a URL to the system media player (AVPlayer or VLC on iOS, Media3
//! on Android), and that player sends no credentials.
//!
//! - `POST /ocs/v2.php/apps/dav/api/v1/direct` (and the other OCS aliases, through
//!   [`crate::nextcloud`]), authenticated with an app password, with the form or query
//!   parameters `fileId` (the `oc:fileid`) and optionally `expirationTime` (seconds, at most a
//!   day): answers `{"url": "<base_url>/remote.php/direct/<token>"}`. Only files the app
//!   password can read qualify; folders are refused with 400, as on Nextcloud.
//! - `GET`/`HEAD /remote.php/direct/<token>`, without credentials: the file, through the same
//!   WebDAV `GET` as `/remote.php/dav/files/...` with the link's app password, so ranges,
//!   ETags and conditional requests behave the same. Only the range and condition headers of
//!   the request are passed on. Like every WebDAV download, the file is an attachment named
//!   after the file (not the token) and the response is sandboxed (see [`crate::app`]): a link
//!   to an HTML file must not run a page on the server's origin for whoever opens it.
//!
//! Every way a link can fail (unknown, expired, revoked app password, disabled account,
//! deleted file, file outside the mounts) answers a plain 404. The token is part of the path,
//! so the request log redacts it ([`crate::request_log`]). How links are stored and when they
//! end is described in [`gono_server_core::direct_downloads`].

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use gono_server_core::{app_passwords, db, direct_downloads};
use gono_server_dav::{Identity, resolve};
use secrecy::ExposeSecret as _;

use crate::app::AppState;

/// Path prefix of the links; the token follows.
pub const DIRECT_PATH: &str = "/remote.php/direct/";

/// What a client asked for when requesting a link.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    /// `fileId`.
    pub file_id: Option<String>,
    /// `expirationTime`.
    pub expiration: Option<String>,
}

impl LinkRequest {
    /// Collects the parameters from the query and then the form body; the body wins.
    pub fn parse(query: Option<&str>, body: &[u8]) -> Self {
        let mut request = Self::default();
        let pairs = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .chain(url::form_urlencoded::parse(body));
        for (name, value) in pairs {
            match name.as_ref() {
                "fileId" => request.file_id = Some(value.into_owned()),
                "expirationTime" => request.expiration = Some(value.into_owned()),
                _ => {}
            }
        }
        request
    }
}

/// Outcome of [`create_link`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// The URL of the new link.
    Created(String),
    /// `fileId` or `expirationTime` is missing or invalid, or the id names a folder.
    BadRequest,
    /// The app password cannot reach a file with that id.
    NotFound,
}

/// Creates a link to a file `identity` can read.
pub async fn create_link(
    state: &AppState,
    identity: &Identity,
    request: &LinkRequest,
) -> Result<Link, StatusCode> {
    let Some(file_id) = request
        .file_id
        .as_deref()
        .and_then(|id| id.trim().parse::<i64>().ok())
    else {
        return Ok(Link::BadRequest);
    };
    let lifetime = match request.expiration.as_deref().map(str::trim) {
        None | Some("") => direct_downloads::DEFAULT_LIFETIME_SECS,
        Some(value) => match value.parse::<i64>() {
            Ok(secs) if (1..=direct_downloads::MAX_LIFETIME_SECS).contains(&secs) => secs,
            _ => return Ok(Link::BadRequest),
        },
    };
    match state.dav.fs().locate_by_id(identity, file_id).await {
        Ok(Some((_, false))) => {}
        Ok(Some((_, true))) => return Ok(Link::BadRequest),
        Ok(None) => return Ok(Link::NotFound),
        Err(err) => {
            tracing::error!(error = ?err, "cannot look up a file for a direct link");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    let token = direct_downloads::create(
        &state.db,
        identity.app_password_id,
        file_id,
        db::unix_now(),
        lifetime,
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "cannot store a direct link");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let origin = state.base_url.as_str().trim_end_matches('/');
    Ok(Link::Created(format!(
        "{origin}{DIRECT_PATH}{}",
        token.expose_secret()
    )))
}

/// Request headers passed on to the WebDAV `GET`.
const PASSED_HEADERS: [header::HeaderName; 6] = [
    header::RANGE,
    header::IF_RANGE,
    header::IF_MATCH,
    header::IF_NONE_MATCH,
    header::IF_MODIFIED_SINCE,
    header::IF_UNMODIFIED_SINCE,
];

/// `GET`/`HEAD /remote.php/direct/<token>` (axum routes `HEAD` to `GET` handlers).
pub async fn download(
    State(state): State<AppState>,
    Path(token): Path<String>,
    request: Request,
) -> Response {
    let now = db::unix_now();
    let link = match direct_downloads::lookup(&state.db, &token, now).await {
        Ok(Some(link)) => link,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return unavailable(&err),
    };
    let device = match app_passwords::device(&state.db, link.app_password_id, now).await {
        Ok(Some(device)) => device,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => return unavailable(&err),
    };
    let identity = Identity::from_device(device);
    let client = match state.dav.fs().locate_by_id(&identity, link.file_id).await {
        Ok(Some((client, false))) => client,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(error = ?err, "cannot look up the file of a direct link");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let root = format!("{}{}", resolve::FILES_ROOT, identity.username);
    let Some(path) = resolve::dav_path(root.as_bytes(), &client, false) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let mut inner = Request::builder()
        .method(request.method().clone())
        .uri(path.as_url_string());
    for name in PASSED_HEADERS {
        if let Some(value) = request.headers().get(&name) {
            inner = inner.header(name, value.clone());
        }
    }
    let Ok(inner) = inner.body(Body::empty()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    state.dav.handle(identity, inner).await.map(Body::new)
}

fn unavailable(err: &gono_server_core::Error) -> Response {
    tracing::error!(error = %err, "direct link lookup failed");
    let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_requests_read_the_query_and_the_form() {
        let request = LinkRequest::parse(Some("format=json&fileId=1"), b"fileId=42");
        assert_eq!(request.file_id.as_deref(), Some("42"), "the body wins");
        assert_eq!(request.expiration, None);
        let request = LinkRequest::parse(None, b"fileId=7&expirationTime=60&format=json");
        assert_eq!(request.file_id.as_deref(), Some("7"));
        assert_eq!(request.expiration.as_deref(), Some("60"));
        assert_eq!(LinkRequest::parse(None, b""), LinkRequest::default());
    }
}
