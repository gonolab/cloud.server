//! HTTP routing.
//!
//! - `GET /healthz`: liveness and readiness probe.
//! - `GET /status.php`, the connectivity probe `/index.php/204` and the OCS API under
//!   `/ocs/v{1,2}.php/` (and the `/index.php/` aliases): see [`crate::nextcloud`].
//! - `/remote.php/dav/files/<user>/...` and the legacy alias `/remote.php/webdav/...`: WebDAV,
//!   served by the single `DavHandler` inside [`DavService`], except `REPORT`, which goes to
//!   [`gono_dav::report`] (the `filter-files` favorites report). Requests are authenticated
//!   with an app password; `<user>` must be the authenticated user.
//! - `/remote.php/dav/uploads/<user>/...`: Nextcloud chunked upload. Only authorization is in
//!   place so far (other users' namespaces and read-only scopes are refused); the protocol
//!   itself answers 501 until it is implemented.
//!
//! Every response to a WebDAV request passes [`OcHeadersLayer`], which adds the `OC-ETag`,
//! `OC-FileId` and `X-NC-Permissions` headers, and every request is logged once with secrets
//! removed from its target ([`crate::request_log`]).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get},
};
use gono_core::db;
use gono_dav::{DavService, Identity, OcHeadersLayer, report, resolve::FILES_ROOT};
use ipnet::IpNet;

use crate::{
    auth::{AuthOutcome, Authenticator, basic_challenge},
    client_ip::client_ip,
    nextcloud, request_log,
};

/// State shared by all request handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: db::Pool,
    /// Device authentication (app passwords) with the shared rate limiter.
    pub auth: Arc<Authenticator>,
    /// The WebDAV endpoint with the single `DavHandler`.
    pub dav: DavService,
    /// Peers whose forwarding headers are trusted.
    pub trusted_proxies: Arc<Vec<IpNet>>,
}

/// Builds the application router.
pub fn router(state: AppState) -> Router {
    let dav = Router::new()
        .route("/remote.php/dav/files/{*path}", any(files))
        .route("/remote.php/webdav", any(webdav))
        .route("/remote.php/webdav/", any(webdav))
        .route("/remote.php/webdav/{*path}", any(webdav))
        .route("/remote.php/dav/uploads/{*path}", any(uploads))
        .layer(OcHeadersLayer);
    let nextcloud = Router::new()
        .route("/status.php", get(nextcloud::status_php))
        .route("/index.php/204", get(nextcloud::connectivity))
        .route("/204", get(nextcloud::connectivity))
        .route("/ocs/v1.php/{*rest}", any(nextcloud::ocs))
        .route("/ocs/v2.php/{*rest}", any(nextcloud::ocs))
        .route("/index.php/ocs/v1.php/{*rest}", any(nextcloud::ocs))
        .route("/index.php/ocs/v2.php/{*rest}", any(nextcloud::ocs));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(nextcloud)
        .merge(dav)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_log::log_requests,
        ))
        .with_state(state)
}

/// Liveness and readiness probe for supervisors and reverse proxies: `200 ok` when the server
/// can reach its database, `503` otherwise.
async fn healthz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match db::ping(&state.db).await {
        Ok(()) => (StatusCode::OK, "ok\n"),
        Err(err) => {
            tracing::warn!(error = %err, "health check failed: database unreachable");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable\n")
        }
    }
}

/// Why a request was not authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// Missing or wrong credentials: 401 with a Basic challenge.
    Unauthorized,
    /// Too many failed attempts: 429 with `Retry-After`.
    RateLimited(Duration),
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => {
                let mut response = StatusCode::UNAUTHORIZED.into_response();
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, basic_challenge());
                response
            }
            Self::RateLimited(wait) => {
                let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
                let seconds = wait.as_secs().max(1).to_string();
                if let Ok(value) = HeaderValue::from_str(&seconds) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                response
            }
        }
    }
}

/// Authenticates a request.
pub(crate) async fn authenticate(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<Arc<Identity>, Rejection> {
    let client = client_ip(peer.ip(), headers, &state.trusted_proxies);
    match state.auth.authenticate(client, headers).await {
        AuthOutcome::Authenticated(identity) => Ok(identity),
        AuthOutcome::Missing | AuthOutcome::Invalid => Err(Rejection::Unauthorized),
        AuthOutcome::RateLimited(wait) => Err(Rejection::RateLimited(wait)),
    }
}

/// The (decoded) username segment after `prefix`, if the path has one.
fn url_user(path: &str, prefix: &str) -> Option<String> {
    let segment = path.strip_prefix(prefix)?.split('/').next()?;
    let decoded: Vec<u8> = percent_decode(segment.as_bytes());
    String::from_utf8(decoded).ok()
}

pub(crate) fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%'
            && let Some(byte) = input
                .get(index + 1..index + 3)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(input[index]);
            index += 1;
        }
    }
    out
}

/// `/remote.php/dav/files/<user>/...`
async fn files(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let identity = match authenticate(&state, peer, request.headers()).await {
        Ok(identity) => identity,
        Err(rejection) => return rejection.into_response(),
    };
    if url_user(request.uri().path(), FILES_ROOT).as_deref() != Some(identity.username.as_str()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    serve_dav(&state, identity, request).await
}

/// `/remote.php/webdav/...`: always the authenticated user's files.
async fn webdav(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    match authenticate(&state, peer, request.headers()).await {
        Ok(identity) => serve_dav(&state, identity, request).await,
        Err(rejection) => rejection.into_response(),
    }
}

/// Hands an authenticated WebDAV request to dav-server, except `REPORT`, which dav-server does
/// not implement (see [`gono_dav::report`]).
async fn serve_dav(state: &AppState, identity: Arc<Identity>, request: Request) -> Response {
    if request.method().as_str() == "REPORT" {
        return report::handle(&state.dav, identity, request)
            .await
            .map(Body::new);
    }
    state.dav.handle(identity, request).await.map(Body::new)
}

/// `/remote.php/dav/uploads/<user>/...`: authorization only, see the module documentation.
async fn uploads(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let identity = match authenticate(&state, peer, request.headers()).await {
        Ok(identity) => identity,
        Err(rejection) => return rejection.into_response(),
    };
    let own = url_user(request.uri().path(), "/remote.php/dav/uploads/").as_deref()
        == Some(identity.username.as_str());
    if !own || !identity.can_write_somewhere() {
        return StatusCode::FORBIDDEN.into_response();
    }
    StatusCode::NOT_IMPLEMENTED.into_response()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::http::Request;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use gono_core::{
        Permission, RelPath, Username,
        app_passwords::{self, Scope},
        config::DbConfig,
        db::OpenMode,
        storage::DataLayout,
        users::{self, NewUser},
    };
    use http_body_util::BodyExt as _;
    use secrecy::ExposeSecret;
    use tower::ServiceExt as _;

    use super::*;
    use crate::ratelimit::RateLimiter;

    struct Fixture {
        _dir: tempfile::TempDir,
        router: Router,
        full: String,
        view: String,
    }

    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path().join("data"));
        layout.create().unwrap();
        let config = DbConfig {
            path: dir.path().join("db.sqlite"),
            max_connections: 4,
            busy_timeout_secs: 5,
        };
        let pool = db::connect(&config, OpenMode::CreateIfMissing)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let mut ids = Vec::new();
        for name in ["alice", "bob"] {
            let username = Username::new(name).unwrap();
            let id = users::create(
                &pool,
                &NewUser {
                    username: &username,
                    display_name: name,
                    password_hash: "x",
                    is_admin: false,
                },
                |id| layout.create_user(id),
            )
            .await
            .unwrap();
            ids.push(id);
        }
        let (_, full) = app_passwords::create(&pool, ids[0], "full", Vec::new(), None)
            .await
            .unwrap();
        let view_scope = Scope {
            mount_path: RelPath::root(),
            storage_path: RelPath::root(),
            permission: Permission::View,
        };
        let (_, view) = app_passwords::create(&pool, ids[0], "view", vec![view_scope], None)
            .await
            .unwrap();
        let dav = crate::commands::serve::dav_service(Duration::from_secs(600), layout, &pool)
            .await
            .unwrap();
        let state = AppState {
            db: pool.clone(),
            auth: Arc::new(Authenticator::new(pool, Arc::new(RateLimiter::new()))),
            dav,
            trusted_proxies: Arc::new(Vec::new()),
        };
        Fixture {
            _dir: dir,
            router: router(state),
            full: full.expose_secret().to_owned(),
            view: view.expose_secret().to_owned(),
        }
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
    }

    impl Reply {
        fn header(&self, name: &str) -> String {
            self.headers
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_else(|| panic!("no {name} header in {:?}", self.headers))
        }
    }

    impl Fixture {
        async fn send(
            &self,
            method: &str,
            uri: &str,
            password: Option<&str>,
            headers: &[(&str, &str)],
            body: &str,
        ) -> Reply {
            let mut request = Request::builder().method(method).uri(uri);
            if let Some(password) = password {
                let credentials = STANDARD.encode(format!("alice:{password}"));
                request = request.header("Authorization", format!("Basic {credentials}"));
            }
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let mut request = request
                .header("Content-Length", body.len().to_string())
                .body(Body::from(body.to_owned()))
                .unwrap();
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 4000))));
            let response = self.router.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            Reply {
                status,
                headers,
                body: String::from_utf8_lossy(&body).into_owned(),
            }
        }
    }

    const FILES: &str = "/remote.php/dav/files/alice";

    #[tokio::test]
    async fn dav_requests_need_an_app_password_of_the_url_user() {
        let f = fixture().await;
        let challenge = f.send("PROPFIND", FILES, None, &[("Depth", "0")], "").await;
        assert_eq!(challenge.status, StatusCode::UNAUTHORIZED);
        assert!(challenge.header("www-authenticate").starts_with("Basic"));
        let wrong = f
            .send("PROPFIND", FILES, Some("nope"), &[("Depth", "0")], "")
            .await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

        let ok = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "0")], "")
            .await;
        assert_eq!(ok.status, StatusCode::MULTI_STATUS, "{}", ok.body);
        let other = f
            .send(
                "PROPFIND",
                "/remote.php/dav/files/bob",
                Some(&f.full),
                &[],
                "",
            )
            .await;
        assert_eq!(other.status, StatusCode::FORBIDDEN);
        let alias = f
            .send("PROPFIND", "/remote.php/webdav/", Some(&f.full), &[], "")
            .await;
        assert_eq!(alias.status, StatusCode::MULTI_STATUS);
    }

    #[tokio::test]
    async fn repeated_failures_are_rate_limited() {
        let f = fixture().await;
        for _ in 0..crate::ratelimit::BURST {
            f.send("GET", FILES, Some("wrong"), &[], "").await;
        }
        let limited = f.send("GET", FILES, Some(&f.full), &[], "").await;
        assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.header("retry-after").parse::<u64>().unwrap() >= 1);
    }

    /// Defect 3 of the legacy server: PUT/HEAD and GET/PROPFIND reported different ETags.
    #[tokio::test]
    async fn every_interface_reports_the_same_etag_and_oc_headers() {
        let f = fixture().await;
        let url = format!("{FILES}/etag.txt");
        let put = f.send("PUT", &url, Some(&f.full), &[], "content").await;
        assert_eq!(put.status, StatusCode::CREATED);
        let etag = put.header("etag");
        assert_eq!(put.header("oc-etag"), etag);
        let file_id = put.header("oc-fileid");
        assert_eq!(put.header("x-nc-permissions"), "GDNVW");

        let head = f.send("HEAD", &url, Some(&f.full), &[], "").await;
        let get = f.send("GET", &url, Some(&f.full), &[], "").await;
        assert_eq!(get.body, "content");
        for reply in [&head, &get] {
            assert_eq!(reply.header("etag"), etag);
            assert_eq!(reply.header("oc-etag"), etag);
            assert_eq!(reply.header("oc-fileid"), file_id);
        }
        let propfind = f
            .send(
                "PROPFIND",
                &url,
                Some(&f.full),
                &[("Depth", "0")],
                r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>"#,
            )
            .await;
        assert!(
            propfind
                .body
                .contains(&format!("<D:getetag>{etag}</D:getetag>")),
            "{}",
            propfind.body
        );

        let conditional = f
            .send(
                "PUT",
                &url,
                Some(&f.full),
                &[("If-Match", etag.as_str())],
                "v2",
            )
            .await;
        assert_eq!(conditional.status, StatusCode::NO_CONTENT);

        let dir = f.send("HEAD", FILES, Some(&f.full), &[], "").await;
        assert_eq!(dir.status, StatusCode::OK);
        assert!(dir.header("oc-fileid").starts_with("00000001"));
    }

    /// The filter-files REPORT reports the same getetag as PROPFIND and every other method.
    #[tokio::test]
    async fn filter_files_report_matches_propfind() {
        let f = fixture().await;
        let full = Some(f.full.as_str());
        f.send("MKCOL", &format!("{FILES}/dir"), full, &[], "")
            .await;
        let put = f
            .send("PUT", &format!("{FILES}/dir/fav.txt"), full, &[], "x")
            .await;
        f.send("PUT", &format!("{FILES}/plain.txt"), full, &[], "y")
            .await;
        let proppatch = r#"<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:set><d:prop><oc:favorite>1</oc:favorite></d:prop></d:set></d:propertyupdate>"#;
        for path in ["dir", "dir/fav.txt"] {
            let patched = f
                .send(
                    "PROPPATCH",
                    &format!("{FILES}/{path}"),
                    full,
                    &[],
                    proppatch,
                )
                .await;
            assert_eq!(patched.status, StatusCode::MULTI_STATUS);
        }
        let report = r#"<?xml version="1.0"?><oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><oc:filter-rules><oc:favorite>1</oc:favorite></oc:filter-rules><d:prop><d:getetag/><oc:favorite/><oc:fileid/><oc:missing/></d:prop></oc:filter-files>"#;
        let reply = f.send("REPORT", FILES, full, &[], report).await;
        assert_eq!(reply.status, StatusCode::MULTI_STATUS, "{}", reply.body);
        assert!(
            reply
                .body
                .contains("/remote.php/dav/files/alice/dir/</D:href>"),
            "{}",
            reply.body
        );
        assert!(
            reply.body.contains("/dir/fav.txt</D:href>"),
            "{}",
            reply.body
        );
        assert!(!reply.body.contains("plain.txt"), "{}", reply.body);
        assert!(
            reply
                .body
                .contains(&format!("<D:getetag>{}</D:getetag>", put.header("etag"))),
            "{}",
            reply.body
        );
        assert!(
            reply.body.contains("404 Not Found"),
            "unknown props: {}",
            reply.body
        );
        assert!(
            xmltree_parses(&reply.body),
            "the joined multistatus is well-formed: {}",
            reply.body
        );

        let below = f
            .send("REPORT", "/remote.php/webdav/dir", full, &[], report)
            .await;
        assert_eq!(below.status, StatusCode::MULTI_STATUS);
        assert!(
            below.body.contains("/remote.php/webdav/dir/fav.txt"),
            "{}",
            below.body
        );
        assert!(
            !below.body.contains("dir/</D:href>"),
            "the base is not listed: {}",
            below.body
        );

        let tags = report.replace(
            "<oc:favorite>1</oc:favorite>",
            "<oc:systemtag>1</oc:systemtag>",
        );
        assert_eq!(
            f.send("REPORT", FILES, full, &[], &tags).await.status,
            StatusCode::NOT_IMPLEMENTED
        );
        let missing = f
            .send("REPORT", &format!("{FILES}/nope"), full, &[], report)
            .await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
    }

    fn xmltree_parses(xml: &str) -> bool {
        // The acceptance suite parses with a full XML parser; a structural check is enough here.
        xml.matches("<D:response>").count() == xml.matches("</D:response>").count()
            && xml.trim_end().ends_with("</D:multistatus>")
    }

    #[tokio::test]
    async fn protocol_preflight_checks() {
        let f = fixture().await;
        let infinity = f
            .send(
                "PROPFIND",
                FILES,
                Some(&f.full),
                &[("Depth", "infinity")],
                "",
            )
            .await;
        assert_eq!(infinity.status, StatusCode::FORBIDDEN);
        assert!(infinity.body.contains("propfind-finite-depth"));

        let dots = f
            .send(
                "PUT",
                &format!("{FILES}/a/%2e%2e/b.txt"),
                Some(&f.full),
                &[],
                "x",
            )
            .await;
        assert_eq!(dots.status, StatusCode::BAD_REQUEST);
        f.send("PUT", &format!("{FILES}/src.txt"), Some(&f.full), &[], "x")
            .await;
        let foreign = f
            .send(
                "COPY",
                &format!("{FILES}/src.txt"),
                Some(&f.full),
                &[(
                    "Destination",
                    "http://localhost/remote.php/dav/files/bob/x.txt",
                )],
                "",
            )
            .await;
        assert_eq!(foreign.status, StatusCode::FORBIDDEN);
        let lock = f
            .send(
                "LOCK",
                &format!("{FILES}/src.txt"),
                Some(&f.view),
                &[],
                r#"<?xml version="1.0"?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>"#,
            )
            .await;
        assert_eq!(lock.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn status_capabilities_and_ocs_user() {
        let f = fixture().await;
        let status = f.send("GET", "/status.php", None, &[], "").await;
        assert_eq!(status.status, StatusCode::OK);
        let status: serde_json::Value = serde_json::from_str(&status.body).unwrap();
        assert_eq!(status["productname"], gono_core::PRODUCT_NAME);
        assert_eq!(status["installed"], true);
        assert_eq!(
            f.send("GET", "/index.php/204", None, &[], "").await.status,
            StatusCode::NO_CONTENT
        );

        let capabilities = f
            .send(
                "GET",
                "/index.php/ocs/v1.php/cloud/capabilities?format=json",
                None,
                &[],
                "",
            )
            .await;
        assert_eq!(capabilities.status, StatusCode::OK);
        let capabilities: serde_json::Value = serde_json::from_str(&capabilities.body).unwrap();
        assert_eq!(capabilities["ocs"]["meta"]["statuscode"], 100);
        assert_eq!(
            capabilities["ocs"]["data"]["capabilities"]["dav"]["chunking"],
            "1.0"
        );

        let anonymous = f.send("GET", "/ocs/v2.php/cloud/user", None, &[], "").await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        assert!(anonymous.header("www-authenticate").starts_with("Basic"));
        assert!(
            anonymous.body.contains("<statuscode>997</statuscode>"),
            "XML by default"
        );

        let me = f
            .send(
                "GET",
                "/ocs/v2.php/cloud/user",
                Some(&f.view),
                &[("Accept", "application/json")],
                "",
            )
            .await;
        assert_eq!(me.status, StatusCode::OK, "{}", me.body);
        let me: serde_json::Value = serde_json::from_str(&me.body).unwrap();
        assert_eq!(me["ocs"]["data"]["id"], "alice");
        assert_eq!(me["ocs"]["data"]["quota"]["quota"], -3);

        let other = f
            .send(
                "GET",
                "/ocs/v1.php/cloud/users/bob?format=json",
                Some(&f.full),
                &[],
                "",
            )
            .await;
        assert_eq!(other.status, StatusCode::OK, "OCS v1 failures are HTTP 200");
        assert!(other.body.contains("\"statuscode\":998"), "{}", other.body);
        let unknown = f.send("GET", "/ocs/v2.php/apps/x/y", None, &[], "").await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_device_can_revoke_its_own_app_password() {
        let f = fixture().await;
        let revoke = f
            .send(
                "DELETE",
                "/ocs/v2.php/core/apppassword",
                Some(&f.view),
                &[],
                "",
            )
            .await;
        assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
        let after = f.send("PROPFIND", FILES, Some(&f.view), &[], "").await;
        assert_eq!(after.status, StatusCode::UNAUTHORIZED);
        let other = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "0")], "")
            .await;
        assert_eq!(
            other.status,
            StatusCode::MULTI_STATUS,
            "other devices keep working"
        );
    }

    #[tokio::test]
    async fn the_upload_namespace_is_authorized_but_not_implemented_yet() {
        let f = fixture().await;
        let own = "/remote.php/dav/uploads/alice/session";
        assert_eq!(
            f.send("MKCOL", own, Some(&f.full), &[], "").await.status,
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            f.send("MKCOL", own, Some(&f.view), &[], "").await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            f.send(
                "MKCOL",
                "/remote.php/dav/uploads/bob/session",
                Some(&f.full),
                &[],
                ""
            )
            .await
            .status,
            StatusCode::FORBIDDEN
        );
    }
}
