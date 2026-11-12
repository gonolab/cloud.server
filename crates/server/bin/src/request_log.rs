//! One log line per request, with secrets removed from the request target.
//!
//! Some endpoints carry credentials in the URL: Login Flow v2 puts its login token into the
//! path (`/login/v2/flow/<token>`), so do direct download links (`/remote.php/direct/<token>`),
//! and clients may put tokens into query strings. The logged
//! target keeps the path but replaces those parts with `<redacted>`; query parameter names are
//! kept, their values are dropped (except a few harmless ones such as `format`). Headers, and
//! with them `Authorization`, are never logged.

use std::{net::SocketAddr, time::Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::Uri,
    middleware::Next,
    response::Response,
};

use crate::{app::AppState, client_ip::client_ip};

/// Path prefixes followed by a secret token.
const TOKEN_PATHS: &[&str] = &[
    "/login/v2/flow/",
    "/index.php/login/v2/flow/",
    crate::direct::DIRECT_PATH,
];

/// Query parameters whose values may be logged. The web file UI's names, search texts and
/// upload ids stay redacted; its switches carry nothing personal.
const PLAIN_QUERY_PARAMS: &[&str] = &[
    "format", "sort", "order", "page", "view", "action", "done", "error", "chunked",
];

const REDACTED: &str = "<redacted>";

/// The request target as it may appear in logs.
pub fn redact(uri: &Uri) -> String {
    let path = uri.path();
    let mut target = TOKEN_PATHS
        .iter()
        .find_map(|prefix| {
            path.strip_prefix(prefix)
                .filter(|rest| !rest.is_empty())
                .map(|_| format!("{prefix}{REDACTED}"))
        })
        .unwrap_or_else(|| path.to_owned());
    if let Some(query) = uri.query() {
        let params: Vec<String> = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((name, value)) if PLAIN_QUERY_PARAMS.contains(&name) => {
                    format!("{name}={value}")
                }
                Some((name, _)) => format!("{name}={REDACTED}"),
                None => pair.to_owned(),
            })
            .collect();
        target.push('?');
        target.push_str(&params.join("&"));
    }
    target
}

/// Logs method, redacted target, status, duration and client address of every request.
pub async fn log_requests(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = request.method().clone();
    let target = redact(request.uri());
    let client = client_ip(peer.ip(), request.headers(), &state.trusted_proxies);
    let response = next.run(request).await;
    tracing::info!(
        %method,
        %target,
        status = response.status().as_u16(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        %client,
        "request"
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redacted(target: &str) -> String {
        redact(&target.parse().unwrap())
    }

    #[test]
    fn tokens_never_reach_the_log() {
        assert_eq!(
            redacted("/index.php/login/v2/flow/s3cr3t-token"),
            "/index.php/login/v2/flow/<redacted>"
        );
        assert_eq!(
            redacted("/login/v2/flow/abc/extra"),
            "/login/v2/flow/<redacted>"
        );
        assert_eq!(
            redacted("/remote.php/direct/s3cr3t"),
            "/remote.php/direct/<redacted>"
        );
        assert_eq!(
            redacted("/index.php/login/v2/poll?token=s3cr3t&format=json"),
            "/index.php/login/v2/poll?token=<redacted>&format=json"
        );
        assert_eq!(redacted("/x?flag"), "/x?flag");
    }

    #[test]
    fn ordinary_targets_are_kept() {
        assert_eq!(
            redacted("/remote.php/dav/files/alice/a%20b.txt"),
            "/remote.php/dav/files/alice/a%20b.txt"
        );
        assert_eq!(redacted("/login/v2/flow/"), "/login/v2/flow/");
    }
}
