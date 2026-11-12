//! Uploads from the browser.
//!
//! - **Form** (no script): `POST <folder>/?upload` with `multipart/form-data`: the CSRF token
//!   first, an optional `replace`, then the files. Each file streams into a WebDAV `PUT`; it
//!   is never held in memory. Without `replace`, existing files are skipped
//!   (`If-None-Match: *`).
//! - **Script**, every request with the session's CSRF token in `X-Gono-CSRF`:
//!   - `PUT <file>`: the whole file as the body (a WebDAV `PUT`; `If-Match`,
//!     `If-None-Match` and `X-OC-MTime` are passed on).
//!   - `MKCOL <folder>/`: a folder (for folder uploads).
//!   - Chunked upload v2 for large files, in the namespace of the chunked uploads of the sync
//!     clients ([`ChunkedUploads`](gono_server_nextcloud::chunking::ChunkedUploads)), with the
//!     same guarantees (length check, free space, atomic assembly, 24 h expiry):
//!     `POST <file>?chunked=start&id=<id>&total=<bytes>`,
//!     `PUT <file>?chunked=part&id=<id>&start=<first byte>&end=<last byte>` (byte-range chunk
//!     names), `POST <file>?chunked=finish&id=<id>&total=<bytes>` and
//!     `DELETE <file>?chunked=cancel&id=<id>`. The session id is `web-<id>`.

use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{FromRequest, Multipart, Request},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use gono_server_core::{RelPath, path::normalize_segment};
use gono_server_dav::Identity;
use gono_server_nextcloud::chunking::UPLOADS_ROOT;
use tokio::sync::mpsc;

use super::{
    ops::{OpError, dav, dav_path},
    view::encode_segment,
};
use crate::app::AppState;

/// Request headers passed on to the WebDAV `PUT`s and the assembly.
const PASSED_ON: [&str; 4] = ["if-match", "if-none-match", "x-oc-mtime", "content-length"];

/// What a form upload did.
#[derive(Debug, Default)]
pub struct Outcome {
    pub uploaded: usize,
    pub skipped: usize,
    /// The first failure, if any.
    pub error: Option<OpError>,
}

/// A file name from a form: the last component (some browsers send paths), NFC.
fn file_name(raw: &str) -> Option<String> {
    let name = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    normalize_segment(name.as_bytes()).ok()
}

/// `POST <folder>/?upload` (see the module documentation). `check_csrf` validates the token
/// field, which must come before the first file.
pub async fn form(
    state: &AppState,
    identity: &Arc<Identity>,
    dir: &RelPath,
    request: Request,
    check_csrf: impl Fn(&str) -> bool,
) -> Result<Outcome, StatusCode> {
    let mut multipart = Multipart::from_request(request, state)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut csrf_ok = false;
    let mut replace = false;
    let mut outcome = Outcome::default();
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        };
        match field.name() {
            Some("csrf") => {
                let value = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                csrf_ok = check_csrf(&value);
            }
            Some("replace") => {
                replace = field.text().await.is_ok_and(|value| value == "1");
            }
            Some("file") => {
                if !csrf_ok {
                    return Err(StatusCode::FORBIDDEN);
                }
                // An empty file input sends a part without a file name.
                let Some(raw_name) = field
                    .file_name()
                    .map(str::to_owned)
                    .filter(|n| !n.is_empty())
                else {
                    continue;
                };
                let Some(name) = file_name(&raw_name) else {
                    outcome.error.get_or_insert(OpError::Name);
                    continue;
                };
                let target = dir.join(&name);
                // Stream the part into the PUT through a channel: the PUT's body must own its
                // data, the part borrows the multipart reader.
                let (sender, receiver) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
                let body = Body::from_stream(futures_util::stream::unfold(
                    receiver,
                    |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) },
                ));
                let mut headers = Vec::new();
                if !replace {
                    headers.push((header::IF_NONE_MATCH, HeaderValue::from_static("*")));
                }
                let uri = dav_path(&target, false);
                let put = dav(state, identity, "PUT", &uri, &headers, body);
                let mut field = field;
                let pump = async move {
                    loop {
                        match field.chunk().await {
                            Ok(Some(chunk)) => {
                                if sender.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                            Ok(None) => return,
                            Err(err) => {
                                let _ = sender.send(Err(std::io::Error::other(err))).await;
                                return;
                            }
                        }
                    }
                };
                let (response, ()) = tokio::join!(put, pump);
                match response.status() {
                    StatusCode::PRECONDITION_FAILED if !replace => outcome.skipped += 1,
                    status => match OpError::from_status(status) {
                        None => outcome.uploaded += 1,
                        Some(err) => {
                            if err == OpError::Failed {
                                tracing::warn!(%status, path = %target, "web upload failed");
                            }
                            outcome.error.get_or_insert(err);
                        }
                    },
                }
            }
            _ => {}
        }
    }
    if !csrf_ok {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(outcome)
}

/// Copies the headers in [`PASSED_ON`] from the browser's request.
fn passed_on(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    PASSED_ON
        .iter()
        .filter_map(|name| {
            let value = headers.get(*name)?;
            Some((HeaderName::from_static(name), value.clone()))
        })
        .collect()
}

/// A short JSON answer for the script.
fn reply(status: StatusCode) -> Response {
    let mut response = (
        status,
        axum::Json(serde_json::json!({ "status": status.as_u16() })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `PUT <file>` from the script.
pub async fn put(
    state: &AppState,
    identity: &Arc<Identity>,
    rel: &RelPath,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let response = dav(
        state,
        identity,
        "PUT",
        &dav_path(rel, false),
        &passed_on(headers),
        body,
    )
    .await;
    reply(response.status())
}

/// `MKCOL <folder>/` from the script; an existing folder is fine.
pub async fn mkcol(state: &AppState, identity: &Arc<Identity>, rel: &RelPath) -> Response {
    let response = dav(
        state,
        identity,
        "MKCOL",
        &dav_path(rel, true),
        &[],
        Body::empty(),
    )
    .await;
    let status = response.status();
    if status == StatusCode::METHOD_NOT_ALLOWED {
        // Exists already: a folder upload continues into it.
        return reply(StatusCode::OK);
    }
    reply(status)
}

/// The chunked upload request of the script.
#[derive(Debug, Default)]
pub struct Chunked {
    pub step: String,
    pub id: String,
    pub total: Option<u64>,
    pub start: Option<u64>,
    pub end: Option<u64>,
}

/// A valid upload id of the script: 8 to 64 letters and digits.
fn session_id(id: &str) -> Option<String> {
    ((8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| format!("web-{id}"))
}

/// The chunked upload steps (see the module documentation).
pub async fn chunked(
    state: &AppState,
    identity: &Arc<Identity>,
    rel: &RelPath,
    method: &str,
    request: &Chunked,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let Some(id) = session_id(&request.id) else {
        return reply(StatusCode::BAD_REQUEST);
    };
    let session = format!(
        "{UPLOADS_ROOT}{}/{id}",
        encode_segment(identity.username.as_str())
    );
    let Ok(destination) = HeaderValue::from_str(&dav_path(rel, false)) else {
        return reply(StatusCode::BAD_REQUEST);
    };
    let total = request
        .total
        .and_then(|total| HeaderValue::from_str(&total.to_string()).ok());
    let destination_header = (HeaderName::from_static("destination"), destination);
    let (dav_method, uri, mut extra) = match (method, request.step.as_str()) {
        ("POST", "start") => {
            let mut extra = vec![destination_header];
            if let Some(total) = total {
                extra.push((HeaderName::from_static("oc-total-length"), total));
            }
            ("MKCOL", session, extra)
        }
        ("PUT", "part") => {
            let (Some(start), Some(end)) = (request.start, request.end) else {
                return reply(StatusCode::BAD_REQUEST);
            };
            if end < start {
                return reply(StatusCode::BAD_REQUEST);
            }
            let mut extra = vec![destination_header];
            if let Some(length) = headers.get(header::CONTENT_LENGTH) {
                extra.push((header::CONTENT_LENGTH, length.clone()));
            }
            ("PUT", format!("{session}/{start}-{end}"), extra)
        }
        ("POST", "finish") => {
            let mut extra = vec![destination_header];
            if let Some(total) = total {
                extra.push((HeaderName::from_static("oc-total-length"), total));
            }
            for (name, value) in passed_on(headers) {
                if name != header::CONTENT_LENGTH {
                    extra.push((name, value));
                }
            }
            ("MOVE", format!("{session}/.file"), extra)
        }
        ("DELETE", "cancel") => ("DELETE", session, Vec::new()),
        _ => return reply(StatusCode::BAD_REQUEST),
    };
    let Ok(uri) = uri.parse::<axum::http::Uri>() else {
        return reply(StatusCode::BAD_REQUEST);
    };
    let mut upstream = axum::http::Request::new(if dav_method == "PUT" {
        body
    } else {
        Body::empty()
    });
    *upstream.method_mut() =
        axum::http::Method::from_bytes(dav_method.as_bytes()).unwrap_or(axum::http::Method::GET);
    *upstream.uri_mut() = uri;
    for (name, value) in extra.drain(..) {
        upstream.headers_mut().append(name, value);
    }
    let response = state.uploads.handle(identity.clone(), upstream).await;
    reply(response.status())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_file_names_lose_their_folders() {
        assert_eq!(file_name("a.txt").as_deref(), Some("a.txt"));
        assert_eq!(file_name("C:\\Users\\x\\b.txt").as_deref(), Some("b.txt"));
        assert_eq!(file_name("dir/c.txt").as_deref(), Some("c.txt"));
        assert_eq!(file_name(".."), None);
        assert_eq!(file_name("dir/"), None);
    }

    #[test]
    fn upload_ids_are_plain() {
        assert_eq!(session_id("abcd1234").as_deref(), Some("web-abcd1234"));
        assert_eq!(session_id("short"), None);
        assert_eq!(session_id("../../etc/passwd!"), None);
    }
}
