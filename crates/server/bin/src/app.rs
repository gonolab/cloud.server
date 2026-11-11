//! HTTP routing.
//!
//! - `GET /healthz`: liveness and readiness probe.
//! - `GET /status.php`, the connectivity probe `/index.php/204` and the OCS API under
//!   `/ocs/v{1,2}.php/` (and the `/index.php/` aliases): see [`crate::nextcloud`].
//! - Login Flow v2 under `/index.php/login/v2` and `/login/v2`: see [`crate::login_flow`].
//! - `/remote.php/dav/files/<user>/...` and the legacy alias `/remote.php/webdav/...`: WebDAV,
//!   served by the single `DavHandler` inside [`DavService`], except `REPORT`, which goes to
//!   [`gono_server_dav::report`] (the `filter-files` favorites report). Requests are authenticated
//!   with an app password; `<user>` must be the authenticated user.
//! - `/remote.php/dav/uploads/<user>/...`: Nextcloud chunked upload v2
//!   ([`gono_server_nextcloud::chunking`]). Other users' namespaces and app passwords without any
//!   writable mount are refused with 403 before the protocol is looked at.
//! - `GET`/`HEAD /remote.php/direct/<token>`: direct download links for media players, without
//!   credentials (see [`crate::direct`]).
//! - Everything else under `/remote.php/dav`, the root included: authenticated first, then 404
//!   ([`dav_namespace`]), so that anonymous probes see a Basic challenge as on Nextcloud.
//! - On both WebDAV routes, after authentication, the XML body of `PROPFIND`, `PROPPATCH`,
//!   `LOCK` and `REPORT` is read here and refused with 400 when its elements nest too deeply
//!   ([`check_xml_body`]): the XML parsers behind these routes recurse once per level, and a
//!   few thousand levels would overflow the stack and abort the whole server.
//! - notify_push, when `notify_push.enabled`: the WebSocket at `/push/ws` and the pre-auth
//!   endpoint `/index.php/apps/notify_push/pre_auth`: see [`crate::notify_push`].
//! - The web admin UI under `admin.path`, when `admin.enabled`: see [`crate::admin`].
//!
//! Every response to a WebDAV request passes [`OcHeadersLayer`], which adds the `OC-ETag`,
//! `OC-FileId` and `X-NC-Permissions` headers, and [`DavPrefixLayer`], which writes the `DAV:`
//! prefix of XML bodies as `d:` (the Nextcloud iOS app finds no entries otherwise) and leaves
//! `@`, `:`, `(` and `)` unencoded in hrefs (Nextcloud Android cannot list the folders of a user
//! whose name contains `@` otherwise). Every response of the WebDAV routes and of direct links
//! carries a sandboxing `Content-Security-Policy` and `X-Content-Type-Options: nosniff`
//! ([`sandbox_user_content`]), and file contents are sent as attachments, so that user files
//! never run as part of the site. Every request is logged once with secrets removed from its
//! target ([`crate::request_log`]).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use gono_server_core::db;
use gono_server_dav::{
    DavPrefixLayer, DavService, Identity, OcHeadersLayer, RewrittenXml, report,
    resolve::FILES_ROOT, xml_limits,
};
use gono_server_nextcloud::{
    chunking::{ChunkedUploads, UPLOADS_ROOT},
    notify_push::{Hub, PRE_AUTH_PATH, WEBSOCKET_PATH},
};
use ipnet::IpNet;
use tower_http::compression::{CompressionLayer, Predicate};
use url::Url;

use crate::{
    admin::{self, Admin},
    auth::{AuthOutcome, Authenticator, basic_challenge},
    client_ip::client_ip,
    direct, login_flow, nextcloud, notify_push,
    ratelimit::RateLimiter,
    request_log,
    web::Web,
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
    /// Chunked upload v2.
    pub uploads: ChunkedUploads,
    /// Sessions, sign-in and CSRF checks of the HTML pages.
    pub web: Arc<Web>,
    /// Public origin of the server (`server.base_url`).
    pub base_url: Arc<Url>,
    /// Per-client limit on starting Login Flow v2 sign-ins (separate from the failed sign-in
    /// limiter: starting a flow is not a failure).
    pub flow_starts: Arc<RateLimiter>,
    /// Peers whose forwarding headers are trusted.
    pub trusted_proxies: Arc<Vec<IpNet>>,
    /// The notify_push hub, when `notify_push.enabled`.
    pub push: Option<Arc<Hub>>,
    /// The web admin UI, when `admin.enabled`.
    pub admin: Option<Arc<Admin>>,
}

/// Compresses the XML bodies of WebDAV responses (PROPFIND, REPORT, error documents) when the
/// client accepts gzip, as Nextcloud does for PROPFIND: a listing of 20,000 photos is about
/// 70 MB of XML and under 1 MB compressed. File contents are never compressed, so `GET` keeps
/// its `Content-Length`, ETags and ranges. Clients that send no `Accept-Encoding` (Nextcloud
/// Android's WebDAV client) get plain XML.
#[derive(Debug, Clone, Copy)]
struct DavXmlOnly;

impl Predicate for DavXmlOnly {
    fn should_compress<B>(&self, response: &axum::http::Response<B>) -> bool
    where
        B: axum::body::HttpBody,
    {
        response.extensions().get::<RewrittenXml>().is_some()
    }
}

/// `Content-Security-Policy` of every response that can carry user files: no resource may load
/// and the document gets a unique origin, without scripts, forms or plugins.
const USER_CONTENT_CSP: &str = "default-src 'none'; sandbox";

/// Adds [`USER_CONTENT_CSP`] and `X-Content-Type-Options: nosniff` to a response of the
/// WebDAV routes or a direct link.
///
/// The web login and the admin UI share the server's origin and keep their sessions in cookies
/// for the whole origin. A user's HTML or SVG file opened in a browser (a direct link needs no
/// credentials, so anyone can be sent one) must therefore never run as part of the site. File
/// contents are already sent as attachments ([`gono_server_dav::DavService`]); this policy also
/// covers browsers that show them anyway and every other response on these routes.
async fn sandbox_user_content(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(USER_CONTENT_CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Builds the application router.
pub fn router(state: AppState) -> Router {
    let dav = Router::new()
        .route("/remote.php/dav/files/{*path}", any(files))
        .route("/remote.php/webdav", any(webdav))
        .route("/remote.php/webdav/", any(webdav))
        .route("/remote.php/webdav/{*path}", any(webdav))
        .route("/remote.php/dav/uploads/{*path}", any(uploads))
        .route("/remote.php/dav", any(dav_namespace))
        .route("/remote.php/dav/", any(dav_namespace))
        .route("/remote.php/dav/{*rest}", any(dav_namespace))
        .layer(OcHeadersLayer)
        .layer(DavPrefixLayer)
        .layer(CompressionLayer::new().gzip(true).compress_when(DavXmlOnly))
        .layer(middleware::map_response(sandbox_user_content));
    let direct = Router::new()
        .route("/remote.php/direct/{token}", get(direct::download))
        .layer(middleware::map_response(sandbox_user_content));
    let nextcloud = Router::new()
        .route("/status.php", get(nextcloud::status_php))
        .route("/index.php/204", get(nextcloud::connectivity))
        .route("/204", get(nextcloud::connectivity))
        .route("/ocs/v1.php/{*rest}", any(nextcloud::ocs))
        .route("/ocs/v2.php/{*rest}", any(nextcloud::ocs))
        .route("/index.php/ocs/v1.php/{*rest}", any(nextcloud::ocs))
        .route("/index.php/ocs/v2.php/{*rest}", any(nextcloud::ocs))
        .route("/index.php/login/v2", post(login_flow::start))
        .route("/login/v2", post(login_flow::start))
        .route("/index.php/login/v2/poll", post(login_flow::poll))
        .route("/login/v2/poll", post(login_flow::poll))
        .route(
            "/index.php/login/v2/flow/{token}",
            get(login_flow::page).post(login_flow::submit),
        )
        .route(
            "/login/v2/flow/{token}",
            get(login_flow::page).post(login_flow::submit),
        );
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .merge(nextcloud)
        .merge(dav)
        .merge(direct);
    if state.push.is_some() {
        router = router
            .route(WEBSOCKET_PATH, get(notify_push::websocket))
            .route(PRE_AUTH_PATH, post(notify_push::pre_auth))
            .route("/apps/notify_push/pre_auth", post(notify_push::pre_auth));
    }
    if let Some(admin) = &state.admin {
        router = router.merge(admin::routes(admin.prefix()));
    }
    router
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
    /// The credentials could not be checked: 503 with `Retry-After`. Never 401, which makes
    /// the Nextcloud apps forget the account (see [`crate::auth`]).
    Unavailable,
}

/// `Retry-After` of a [`Rejection::Unavailable`], in seconds.
const UNAVAILABLE_RETRY_AFTER: &str = "30";

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
            Self::Unavailable => {
                let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_static(UNAVAILABLE_RETRY_AFTER),
                );
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
        AuthOutcome::Unavailable => Err(Rejection::Unavailable),
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

/// The rest of `/remote.php/dav`: the root itself and paths without a handler of their own
/// (`files/` without a user, `principals/`, ...). Nextcloud authenticates every request below
/// `/remote.php/dav` before it routes it, and the Android app depends on that: it detects the
/// authentication method with an anonymous `HEAD /remote.php/dav` and refuses the server unless
/// the answer is 401 with a Basic challenge. Authenticated requests get 404, since nothing is
/// served here.
async fn dav_namespace(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    match authenticate(&state, peer, request.headers()).await {
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(rejection) => rejection.into_response(),
    }
}

/// Hands an authenticated WebDAV request to dav-server, except `REPORT`, which dav-server does
/// not implement (see [`gono_server_dav::report`]).
async fn serve_dav(state: &AppState, identity: Arc<Identity>, request: Request) -> Response {
    let request = match check_xml_body(request).await {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };
    if request.method().as_str() == "REPORT" {
        return report::handle(&state.dav, identity, request)
            .await
            .map(Body::new);
    }
    state.dav.handle(identity, request).await.map(Body::new)
}

/// `/remote.php/dav/uploads/<user>/...`: chunked upload v2 ([`ChunkedUploads`]) in the
/// authenticated user's own namespace, for app passwords that can write somewhere.
async fn uploads(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let identity = match authenticate(&state, peer, request.headers()).await {
        Ok(identity) => identity,
        Err(rejection) => return rejection.into_response(),
    };
    let own =
        url_user(request.uri().path(), UPLOADS_ROOT).as_deref() == Some(identity.username.as_str());
    if !own || !identity.can_write_somewhere() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let request = match check_xml_body(request).await {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };
    state.uploads.handle(identity, request).await.map(Body::new)
}

/// Reads the XML body of an authenticated WebDAV request (methods in
/// [`xml_limits::parses_body`]) and refuses it with 400 when its elements nest deeper than
/// [`xml_limits::MAX_DEPTH`], before any parser builds a tree from it. Bodies larger than
/// [`xml_limits::MAX_BODY`] are refused with 413, as the handlers behind this would. Requests
/// with other methods pass through untouched, so `PUT` bodies keep streaming.
async fn check_xml_body(request: Request) -> Result<Request, StatusCode> {
    if !xml_limits::parses_body(request.method()) {
        return Ok(request);
    }
    let (parts, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, xml_limits::MAX_BODY).await else {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    };
    if xml_limits::exceeds_depth(&bytes, xml_limits::MAX_DEPTH) {
        tracing::debug!(
            method = %parts.method,
            "refused an XML body nested deeper than {} levels",
            xml_limits::MAX_DEPTH
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::http::Request;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use gono_server_core::{
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

    struct Fixture {
        dir: tempfile::TempDir,
        router: Router,
        state: AppState,
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
        let dav = crate::commands::serve::dav_service(
            Duration::from_secs(600),
            layout,
            gono_server_core::meta::MetaStore::new(pool.clone()),
        )
        .await
        .unwrap();
        let uploads = ChunkedUploads::new(
            dav.fs().clone(),
            gono_server_core::locks::LockStore::new(pool.clone()),
        );
        let base_url = Url::parse("http://localhost:8080").unwrap();
        let state = AppState {
            db: pool.clone(),
            auth: Arc::new(Authenticator::new(
                pool.clone(),
                Arc::new(RateLimiter::new()),
            )),
            dav,
            uploads,
            web: Arc::new(Web::new(pool, Arc::new(RateLimiter::new()), &base_url)),
            base_url: Arc::new(base_url),
            flow_starts: Arc::new(RateLimiter::new()),
            trusted_proxies: Arc::new(Vec::new()),
            push: None,
            admin: None,
        };
        Fixture {
            dir,
            router: router(state.clone()),
            state,
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
    async fn dav_xml_is_compressed_on_request_but_file_contents_never() {
        let f = fixture().await;
        let xml_file = r#"<?xml version="1.0"?><x>a file that happens to be XML</x>"#;
        let put = f
            .send(
                "PUT",
                &format!("{FILES}/doc.xml"),
                Some(&f.full),
                &[("Content-Type", "application/xml")],
                xml_file,
            )
            .await;
        assert_eq!(put.status, StatusCode::CREATED);
        let gzip = ("Accept-Encoding", "gzip");

        let listing = f
            .send(
                "PROPFIND",
                FILES,
                Some(&f.full),
                &[("Depth", "1"), gzip],
                "",
            )
            .await;
        assert_eq!(listing.status, StatusCode::MULTI_STATUS);
        assert_eq!(listing.header("content-encoding"), "gzip");
        let plain = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "1")], "")
            .await;
        assert!(!plain.headers.contains_key("content-encoding"));
        assert!(plain.body.contains("/doc.xml</d:href>"), "{}", plain.body);

        for headers in [vec![gzip], vec![gzip, ("Range", "bytes=0-4")]] {
            let get = f
                .send(
                    "GET",
                    &format!("{FILES}/doc.xml"),
                    Some(&f.full),
                    &headers,
                    "",
                )
                .await;
            assert!(get.status.is_success(), "{}", get.status);
            assert!(!get.headers.contains_key("content-encoding"), "{headers:?}");
            assert!(xml_file.starts_with(&get.body), "{headers:?}: {}", get.body);
        }
    }

    #[tokio::test]
    async fn a_failing_database_answers_503_not_401() {
        // After a 401 on `cloud/user` the Nextcloud iOS app deletes the account from the
        // device, so credentials that cannot be checked must not look wrong.
        let f = fixture().await;
        f.state.db.close().await;
        for (method, uri) in [
            ("PROPFIND", FILES),
            ("GET", "/ocs/v2.php/cloud/user?format=json"),
            ("GET", "/ocs/v1.php/cloud/user"),
        ] {
            let reply = f.send(method, uri, Some(&f.full), &[], "").await;
            assert_eq!(
                reply.status,
                StatusCode::SERVICE_UNAVAILABLE,
                "{method} {uri}"
            );
            assert_eq!(reply.header("retry-after"), "30");
            assert!(!reply.headers.contains_key(header::WWW_AUTHENTICATE));
        }
    }

    #[tokio::test]
    async fn the_rest_of_the_dav_namespace_asks_for_credentials_first() {
        // Nextcloud Android detects the authentication method with an anonymous
        // `HEAD /remote.php/dav` and gives up on anything but a Basic challenge.
        let f = fixture().await;
        for (method, uri) in [
            ("HEAD", "/remote.php/dav"),
            ("HEAD", "/remote.php/dav/"),
            ("PROPFIND", "/remote.php/dav/"),
            ("PROPFIND", "/remote.php/dav/files"),
            ("GET", "/remote.php/dav/files/"),
            ("PROPFIND", "/remote.php/dav/uploads/"),
            ("GET", "/remote.php/dav/principals/users/alice"),
        ] {
            let anonymous = f.send(method, uri, None, &[], "").await;
            assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
            assert!(
                anonymous.header("www-authenticate").starts_with("Basic"),
                "{method} {uri}"
            );
            let wrong = f.send(method, uri, Some("nope"), &[], "").await;
            assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
            let known = f.send(method, uri, Some(&f.full), &[], "").await;
            assert_eq!(known.status, StatusCode::NOT_FOUND, "{method} {uri}");
        }
        // The routes with handlers of their own are not shadowed.
        let files = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "0")], "")
            .await;
        assert_eq!(files.status, StatusCode::MULTI_STATUS, "{}", files.body);
        let uploads = f
            .send(
                "PROPFIND",
                "/remote.php/dav/uploads/alice",
                Some(&f.full),
                &[("Depth", "0")],
                "",
            )
            .await;
        assert_eq!(uploads.status, StatusCode::MULTI_STATUS, "{}", uploads.body);
    }

    #[tokio::test]
    async fn dav_xml_uses_the_d_prefix_but_file_contents_stay_unchanged() {
        // NextcloudKit (iOS) looks up `d:multistatus`, `d:response`, ... by their literal names.
        let f = fixture().await;
        let xml_file = r#"<D:x xmlns:D="DAV:"><D:y/></D:x>"#;
        let put = f
            .send(
                "PUT",
                &format!("{FILES}/doc.xml"),
                Some(&f.full),
                &[("Content-Type", "application/xml")],
                xml_file,
            )
            .await;
        assert_eq!(put.status, StatusCode::CREATED);

        let propfind = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "1")], "")
            .await;
        assert_eq!(propfind.status, StatusCode::MULTI_STATUS);
        let report = f
            .send(
                "REPORT",
                FILES,
                Some(&f.full),
                &[],
                r#"<oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><oc:filter-rules><oc:favorite>1</oc:favorite></oc:filter-rules></oc:filter-files>"#,
            )
            .await;
        assert_eq!(report.status, StatusCode::MULTI_STATUS);
        let infinity = f
            .send(
                "PROPFIND",
                FILES,
                Some(&f.full),
                &[("Depth", "infinity")],
                "",
            )
            .await;
        assert_eq!(infinity.status, StatusCode::MULTI_STATUS);
        for reply in [&propfind, &report, &infinity] {
            assert!(reply.body.contains(r#"xmlns:d="DAV:""#), "{}", reply.body);
            assert!(!reply.body.contains("<D:"), "{}", reply.body);
            assert!(!reply.body.contains("xmlns:D="), "{}", reply.body);
        }
        assert!(
            propfind.body.contains("<d:multistatus"),
            "{}",
            propfind.body
        );
        assert!(
            propfind.body.contains("/doc.xml</d:href>"),
            "{}",
            propfind.body
        );
        assert!(report.body.contains("<d:multistatus"), "{}", report.body);
        if let Some(length) = propfind.headers.get("content-length") {
            assert_eq!(length.to_str().unwrap(), propfind.body.len().to_string());
        }

        let get = f
            .send("GET", &format!("{FILES}/doc.xml"), Some(&f.full), &[], "")
            .await;
        assert_eq!(get.status, StatusCode::OK);
        assert_eq!(get.body, xml_file, "a file's content is never rewritten");
    }

    #[tokio::test]
    async fn fractional_oc_times_are_truncated_like_nextcloud() {
        // NextcloudKit (iOS) sends `X-OC-MTime: 1700000000.123456`; dav-server alone refuses
        // that with 400, Nextcloud truncates it.
        let f = fixture().await;
        let put = f
            .send(
                "PUT",
                &format!("{FILES}/photo.jpg"),
                Some(&f.full),
                &[
                    ("X-OC-MTime", "1700000000.123456"),
                    ("X-OC-CTime", "1699999999.5"),
                ],
                "jpeg",
            )
            .await;
        assert_eq!(put.status, StatusCode::CREATED, "{}", put.body);
        assert_eq!(put.header("x-oc-mtime"), "accepted");
        let get = f
            .send("GET", &format!("{FILES}/photo.jpg"), Some(&f.full), &[], "")
            .await;
        assert_eq!(get.header("last-modified"), "Tue, 14 Nov 2023 22:13:20 GMT");

        let malformed = f
            .send(
                "PUT",
                &format!("{FILES}/other.jpg"),
                Some(&f.full),
                &[("X-OC-MTime", "yesterday")],
                "jpeg",
            )
            .await;
        assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn repeated_failures_are_rate_limited_but_valid_devices_are_not() {
        let f = fixture().await;
        for _ in 0..crate::ratelimit::BURST {
            let reply = f.send("GET", FILES, Some("wrong"), &[], "").await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }
        let limited = f.send("GET", FILES, Some("wrong"), &[], "").await;
        assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.header("retry-after").parse::<u64>().unwrap() >= 1);
        // Another device behind the same address keeps working.
        let valid = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "0")], "")
            .await;
        assert_eq!(valid.status, StatusCode::MULTI_STATUS);
    }

    /// An XML body whose elements nest `depth` levels: a DAV root with `depth - 1` unclosed
    /// elements, the shape that made xmltree overflow the stack.
    fn deeply_nested(root: &str, depth: usize) -> String {
        format!(
            r#"<?xml version="1.0"?><D:{root} xmlns:D="DAV:">{}"#,
            "<a>".repeat(depth - 1)
        )
    }

    #[tokio::test]
    async fn deeply_nested_xml_bodies_are_refused_before_they_are_parsed() {
        let f = fixture().await;
        let file = format!("{FILES}/x.txt");
        let put = f.send("PUT", &file, Some(&f.full), &[], "x").await;
        assert_eq!(put.status, StatusCode::CREATED);

        // 3000 levels overflow a 2 MiB stack even in release builds; without the check the
        // first of these requests would abort the test process.
        let cases = [
            ("PROPFIND", FILES, "propfind"),
            ("PROPFIND", "/remote.php/webdav/", "propfind"),
            ("PROPPATCH", file.as_str(), "propertyupdate"),
            ("LOCK", file.as_str(), "lockinfo"),
            ("REPORT", FILES, "filter-files"),
            ("PROPFIND", "/remote.php/dav/uploads/alice", "propfind"),
        ];
        for (method, uri, root) in cases {
            let body = deeply_nested(root, 3000);
            let refused = f
                .send(method, uri, Some(&f.full), &[("Depth", "0")], &body)
                .await;
            assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{method} {uri}");
        }
        let read_only = f
            .send(
                "PROPFIND",
                FILES,
                Some(&f.view),
                &[("Depth", "0")],
                &deeply_nested("propfind", 3000),
            )
            .await;
        assert_eq!(read_only.status, StatusCode::BAD_REQUEST);
        // Authentication comes first: anonymous requests learn nothing about the body check.
        let anonymous = f
            .send(
                "PROPFIND",
                FILES,
                None,
                &[("Depth", "0")],
                &deeply_nested("propfind", 3000),
            )
            .await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

        // Exactly the limit still reaches dav-server: propfind, prop and a dead property whose
        // value nests the remaining levels.
        let inner = xml_limits::MAX_DEPTH - 2;
        let at_limit = format!(
            r#"<D:propfind xmlns:D="DAV:"><D:prop>{}{}</D:prop></D:propfind>"#,
            r#"<x:a xmlns:x="urn:x">"#.repeat(inner),
            "</x:a>".repeat(inner)
        );
        let accepted = f
            .send(
                "PROPFIND",
                &file,
                Some(&f.full),
                &[("Depth", "0")],
                &at_limit,
            )
            .await;
        assert_eq!(
            accepted.status,
            StatusCode::MULTI_STATUS,
            "{}",
            accepted.body
        );

        // The size limit is unchanged, and PUT bodies are not read by the check.
        let oversized = format!(
            r#"<D:propertyupdate xmlns:D="DAV:"><!--{}--></D:propertyupdate>"#,
            "x".repeat(xml_limits::MAX_BODY)
        );
        let too_large = f
            .send("PROPPATCH", &file, Some(&f.full), &[], &oversized)
            .await;
        assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
        let big = "y".repeat(4 * xml_limits::MAX_BODY);
        let stored = f
            .send("PUT", &format!("{FILES}/big.txt"), Some(&f.full), &[], &big)
            .await;
        assert_eq!(stored.status, StatusCode::CREATED);

        let still_serving = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "1")], "")
            .await;
        assert_eq!(still_serving.status, StatusCode::MULTI_STATUS);
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
                .contains(&format!("<d:getetag>{etag}</d:getetag>")),
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
                .contains("/remote.php/dav/files/alice/dir/</d:href>"),
            "{}",
            reply.body
        );
        assert!(
            reply.body.contains("/dir/fav.txt</d:href>"),
            "{}",
            reply.body
        );
        assert!(!reply.body.contains("plain.txt"), "{}", reply.body);
        assert!(
            reply
                .body
                .contains(&format!("<d:getetag>{}</d:getetag>", put.header("etag"))),
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
            !below.body.contains("dir/</d:href>"),
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
        xml.matches("<d:response>").count() == xml.matches("</d:response>").count()
            && xml.trim_end().ends_with("</d:multistatus>")
    }

    #[tokio::test]
    async fn protocol_preflight_checks() {
        let f = fixture().await;
        // Depth infinity lists the direct children only, like Depth 1 (and Nextcloud).
        for (method, path, body) in [
            ("MKCOL", "/a", ""),
            ("MKCOL", "/a/b", ""),
            ("PUT", "/a/b/c.txt", "c"),
        ] {
            let reply = f
                .send(method, &format!("{FILES}{path}"), Some(&f.full), &[], body)
                .await;
            assert_eq!(reply.status, StatusCode::CREATED, "{method} {path}");
        }
        let infinity = f
            .send(
                "PROPFIND",
                FILES,
                Some(&f.full),
                &[("Depth", "infinity")],
                "",
            )
            .await;
        assert_eq!(infinity.status, StatusCode::MULTI_STATUS);
        assert!(
            infinity.body.contains("/alice/a/</d:href>"),
            "{}",
            infinity.body
        );
        assert!(!infinity.body.contains("/alice/a/b/"), "{}", infinity.body);

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

    /// A user's HTML must never run as part of the site, where the admin UI and the web login
    /// keep their sessions: file contents are attachments, and every response of the WebDAV
    /// routes and of direct links (which need no credentials) is sandboxed.
    #[tokio::test]
    async fn user_files_are_sandboxed_attachments() {
        let f = fixture().await;
        let page = "<html><script>document.title = 'x'</script></html>";
        let file = format!("{FILES}/%C3%9Cber%20page.html");
        let put = f.send("PUT", &file, Some(&f.full), &[], page).await;
        assert_eq!(put.status, StatusCode::CREATED);
        let sandboxed = |reply: &Reply, what: &str| {
            assert_eq!(
                reply.header("content-security-policy"),
                "default-src 'none'; sandbox",
                "{what}"
            );
            assert_eq!(reply.header("x-content-type-options"), "nosniff", "{what}");
        };
        let attachment = "attachment; filename*=UTF-8''%C3%9Cber%20page.html";

        for method in ["GET", "HEAD"] {
            let reply = f.send(method, &file, Some(&f.full), &[], "").await;
            assert_eq!(reply.status, StatusCode::OK, "{method}");
            sandboxed(&reply, method);
            assert_eq!(reply.header("content-disposition"), attachment, "{method}");
        }
        let ranged = f
            .send("GET", &file, Some(&f.full), &[("Range", "bytes=0-5")], "")
            .await;
        assert_eq!(ranged.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(ranged.header("content-disposition"), attachment);

        // Folders, listings and refusals are no downloads, but sandboxed all the same.
        let folder = f
            .send("GET", &format!("{FILES}/"), Some(&f.full), &[], "")
            .await;
        assert_eq!(folder.status, StatusCode::OK);
        sandboxed(&folder, "folder");
        assert!(folder.headers.get("content-disposition").is_none());
        let listing = f
            .send("PROPFIND", FILES, Some(&f.full), &[("Depth", "1")], "")
            .await;
        assert_eq!(listing.status, StatusCode::MULTI_STATUS);
        sandboxed(&listing, "PROPFIND");
        assert!(listing.headers.get("content-disposition").is_none());
        let anonymous = f.send("GET", &file, None, &[], "").await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        sandboxed(&anonymous, "401");

        // A direct link names the file, not its token.
        let id: i64 =
            sqlx::query_scalar("SELECT id FROM files WHERE rel_path LIKE '%ber page.html'")
                .fetch_one(&f.state.db)
                .await
                .unwrap();
        let link = link_path(&direct_link(&f, &f.full, &format!("fileId={id}")).await);
        let direct = f.send("GET", &link, None, &[], "").await;
        assert_eq!(direct.status, StatusCode::OK);
        assert_eq!(direct.body, page);
        sandboxed(&direct, "direct link");
        assert_eq!(direct.header("content-disposition"), attachment);
        let unknown = f
            .send("GET", "/remote.php/direct/not-a-token", None, &[], "")
            .await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
        sandboxed(&unknown, "unknown link");

        // Other routes keep their own headers: the status document is not sandboxed.
        let status = f.send("GET", "/status.php", None, &[], "").await;
        assert!(status.headers.get("content-security-policy").is_none());
    }

    async fn direct_link(f: &Fixture, password: &str, form: &str) -> Reply {
        f.send(
            "POST",
            "/ocs/v2.php/apps/dav/api/v1/direct?format=json",
            Some(password),
            &[("Content-Type", "application/x-www-form-urlencoded")],
            form,
        )
        .await
    }

    /// The path of the link in a successful answer of [`direct_link`].
    fn link_path(reply: &Reply) -> String {
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
        let url = body["ocs"]["data"]["url"].as_str().unwrap();
        let path = url.strip_prefix("http://localhost:8080").unwrap();
        assert!(path.starts_with("/remote.php/direct/"), "{url}");
        path.to_owned()
    }

    #[tokio::test]
    async fn direct_links_serve_files_without_credentials() {
        let f = fixture().await;
        let put = f
            .send(
                "PUT",
                &format!("{FILES}/movie.mp4"),
                Some(&f.full),
                &[],
                "0123456789",
            )
            .await;
        assert_eq!(put.status, StatusCode::CREATED);
        let mkcol = f
            .send("MKCOL", &format!("{FILES}/dir"), Some(&f.full), &[], "")
            .await;
        assert_eq!(mkcol.status, StatusCode::CREATED);
        let id_of = |path: &'static str| {
            let db = f.state.db.clone();
            async move {
                sqlx::query_scalar::<_, i64>("SELECT id FROM files WHERE rel_path = ?1")
                    .bind(path)
                    .fetch_one(&db)
                    .await
                    .unwrap()
            }
        };
        let movie = id_of("movie.mp4").await;

        // A read-only app password may stream; the link needs no credentials.
        let link = link_path(&direct_link(&f, &f.view, &format!("fileId={movie}")).await);
        let ranged = f
            .send("GET", &link, None, &[("Range", "bytes=2-5")], "")
            .await;
        assert_eq!(ranged.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(ranged.body, "2345");
        assert_eq!(ranged.header("content-range"), "bytes 2-5/10");
        assert_eq!(ranged.header("content-type"), "video/mp4");
        let head = f.send("HEAD", &link, None, &[], "").await;
        assert_eq!(head.status, StatusCode::OK);
        assert_eq!(head.header("content-length"), "10");

        // The link follows the file when it moves.
        let moved = f
            .send(
                "MOVE",
                &format!("{FILES}/movie.mp4"),
                Some(&f.full),
                &[(
                    "Destination",
                    "http://localhost/remote.php/dav/files/alice/dir/m.mp4",
                )],
                "",
            )
            .await;
        assert_eq!(moved.status, StatusCode::CREATED);
        assert_eq!(f.send("GET", &link, None, &[], "").await.body, "0123456789");

        // Refused requests.
        for (form, status) in [
            (
                format!("fileId={}", id_of("dir").await),
                StatusCode::BAD_REQUEST,
            ),
            ("fileId=999999".to_owned(), StatusCode::NOT_FOUND),
            (String::new(), StatusCode::BAD_REQUEST),
            (
                format!("fileId={movie}&expirationTime=0"),
                StatusCode::BAD_REQUEST,
            ),
            (
                format!("fileId={movie}&expirationTime=86401"),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let reply = direct_link(&f, &f.full, &form).await;
            assert_eq!(reply.status, status, "{form}: {}", reply.body);
        }
        let anonymous = f
            .send(
                "POST",
                "/ocs/v2.php/apps/dav/api/v1/direct",
                None,
                &[],
                "fileId=1",
            )
            .await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        let unknown = f
            .send("GET", "/remote.php/direct/not-a-token", None, &[], "")
            .await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);

        // Revoking the app password ends its links; other links stay until the file goes.
        let other = link_path(
            &direct_link(&f, &f.full, &format!("fileId={movie}&expirationTime=60")).await,
        );
        let revoke = f
            .send(
                "DELETE",
                "/ocs/v2.php/core/apppassword",
                Some(&f.view),
                &[],
                "",
            )
            .await;
        assert_eq!(revoke.status, StatusCode::OK);
        assert_eq!(
            f.send("GET", &link, None, &[], "").await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            f.send("GET", &other, None, &[], "").await.status,
            StatusCode::OK
        );
        let delete = f
            .send(
                "DELETE",
                &format!("{FILES}/dir/m.mp4"),
                Some(&f.full),
                &[],
                "",
            )
            .await;
        assert_eq!(delete.status, StatusCode::NO_CONTENT);
        assert_eq!(
            f.send("GET", &other, None, &[], "").await.status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn status_capabilities_and_ocs_user() {
        let f = fixture().await;
        let status = f.send("GET", "/status.php", None, &[], "").await;
        assert_eq!(status.status, StatusCode::OK);
        let status: serde_json::Value = serde_json::from_str(&status.body).unwrap();
        assert_eq!(status["productname"], gono_server_core::PRODUCT_NAME);
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

    /// The `name=value` part of the `Set-Cookie` header for cookie `name`.
    fn set_cookie(reply: &Reply, name: &str) -> Option<String> {
        reply
            .headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(&format!("{name}=")))
            .map(|value| value.split(';').next().unwrap().to_owned())
    }

    /// The value of the hidden `csrf` input of a page.
    fn csrf_field(body: &str) -> String {
        let pattern = "name=\"csrf\" value=\"";
        let start = body.find(pattern).expect("csrf field") + pattern.len();
        body[start..start + body[start..].find('"').unwrap()].to_owned()
    }

    const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

    #[tokio::test]
    async fn login_flow_needs_the_web_password_and_explicit_consent() {
        let f = fixture().await;
        let hash = gono_server_core::password::hash(&secrecy::SecretString::from(
            "correct horse".to_owned(),
        ))
        .unwrap();
        users::set_password_hash(&f.state.db, &Username::new("alice").unwrap(), &hash)
            .await
            .unwrap();

        let desktop = "Mozilla/5.0 (Macintosh) mirall/3.13.0 (Nextcloud, osx-23.5.0)";
        let start = f
            .send(
                "POST",
                "/index.php/login/v2",
                None,
                &[("User-Agent", desktop)],
                "",
            )
            .await;
        assert_eq!(start.status, StatusCode::OK, "{}", start.body);
        let start: serde_json::Value = serde_json::from_str(&start.body).unwrap();
        let poll_token = start["poll"]["token"].as_str().unwrap().to_owned();
        let poll_body = format!("token={poll_token}");
        let login = start["login"].as_str().unwrap();
        assert!(login.starts_with("http://localhost:8080/index.php/login/v2/flow/"));
        let page = login.trim_start_matches("http://localhost:8080").to_owned();
        let poll = || {
            f.send(
                "POST",
                "/index.php/login/v2/poll",
                None,
                &[FORM],
                &poll_body,
            )
        };
        assert_eq!(poll().await.status, StatusCode::NOT_FOUND);

        // The sign-in page: security headers and a double-submit CSRF cookie.
        let form = f.send("GET", &page, None, &[], "").await;
        assert_eq!(form.status, StatusCode::OK);
        assert!(
            form.body.contains("Nextcloud desktop 3.13.0 (macOS)"),
            "{}",
            form.body
        );
        assert!(
            form.header("content-security-policy")
                .contains("frame-ancestors 'none'")
        );
        assert_eq!(form.header("x-frame-options"), "DENY");
        assert_eq!(form.header("referrer-policy"), "same-origin");
        let csrf_cookie = set_cookie(&form, "gono_csrf").expect("csrf cookie");
        let csrf = csrf_field(&form.body);
        let login_body = |csrf: &str, password: &str| {
            format!("action=login&csrf={csrf}&user=alice&password={password}")
        };

        let forged = f
            .send(
                "POST",
                &page,
                None,
                &[FORM, ("Cookie", &csrf_cookie)],
                &login_body("forged", "correct+horse"),
            )
            .await;
        assert_eq!(forged.status, StatusCode::FORBIDDEN, "wrong CSRF token");
        assert!(set_cookie(&forged, "gono_session").is_none());
        let foreign = f
            .send(
                "POST",
                &page,
                None,
                &[
                    FORM,
                    ("Cookie", &csrf_cookie),
                    ("Origin", "https://evil.example"),
                ],
                &login_body(&csrf, "correct+horse"),
            )
            .await;
        assert_eq!(foreign.status, StatusCode::FORBIDDEN, "foreign origin");
        let wrong = f
            .send(
                "POST",
                &page,
                None,
                &[FORM, ("Cookie", &csrf_cookie)],
                &login_body(&csrf, "wrong"),
            )
            .await;
        assert_eq!(wrong.status, StatusCode::FORBIDDEN);
        assert!(
            wrong.body.contains("Wrong username or password"),
            "{}",
            wrong.body
        );
        // An app password is not a web password.
        let app = f
            .send(
                "POST",
                &page,
                None,
                &[FORM, ("Cookie", &csrf_cookie)],
                &login_body(&csrf, &f.full),
            )
            .await;
        assert_eq!(app.status, StatusCode::FORBIDDEN);

        let signed_in = f
            .send(
                "POST",
                &page,
                None,
                &[FORM, ("Cookie", &csrf_cookie)],
                &login_body(&csrf, "correct+horse"),
            )
            .await;
        assert_eq!(
            signed_in.status,
            StatusCode::SEE_OTHER,
            "{}",
            signed_in.body
        );
        assert_eq!(signed_in.header("location"), page);
        let session = set_cookie(&signed_in, "gono_session").expect("session cookie");
        assert!(
            signed_in
                .headers
                .get_all("set-cookie")
                .iter()
                .any(|v| v.to_str().unwrap().contains("HttpOnly")),
        );
        assert_eq!(poll().await.status, StatusCode::NOT_FOUND, "no consent yet");

        let consent = f
            .send("GET", &page, None, &[("Cookie", &session)], "")
            .await;
        assert!(consent.body.contains("Grant access"), "{}", consent.body);
        assert!(consent.body.contains("Nextcloud desktop 3.13.0 (macOS)"));
        let csrf = csrf_field(&consent.body);
        let stolen = f
            .send(
                "POST",
                &page,
                None,
                &[FORM, ("Cookie", &session)],
                "action=grant&csrf=nope",
            )
            .await;
        assert_eq!(stolen.status, StatusCode::FORBIDDEN);
        assert_eq!(poll().await.status, StatusCode::NOT_FOUND);
        let granted = f
            .send(
                "POST",
                &page,
                None,
                &[FORM, ("Cookie", &session)],
                &format!("action=grant&csrf={csrf}"),
            )
            .await;
        assert_eq!(granted.status, StatusCode::SEE_OTHER);
        let done = f
            .send("GET", &page, None, &[("Cookie", &session)], "")
            .await;
        assert!(done.body.contains("Access granted"), "{}", done.body);
        assert!(!done.body.contains("<form"), "nothing left to submit");

        let completed = poll().await;
        assert_eq!(completed.status, StatusCode::OK, "{}", completed.body);
        let completed: serde_json::Value = serde_json::from_str(&completed.body).unwrap();
        assert_eq!(completed["loginName"], "alice");
        assert_eq!(completed["server"], "http://localhost:8080");
        let minted = completed["appPassword"].as_str().unwrap().to_owned();
        assert_ne!(minted, "correct horse");
        assert_eq!(poll().await.status, StatusCode::NOT_FOUND, "single use");
        assert_eq!(
            f.send("PROPFIND", FILES, Some(&minted), &[("Depth", "0")], "")
                .await
                .status,
            StatusCode::MULTI_STATUS
        );
        let labels: Vec<String> = app_passwords::list(&f.state.db, 1)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.label)
            .collect();
        assert!(
            labels.contains(&"Nextcloud desktop 3.13.0 (macOS)".to_owned()),
            "{labels:?}"
        );
        assert_eq!(
            f.send("GET", &page, None, &[("Cookie", &session)], "")
                .await
                .status,
            StatusCode::NOT_FOUND,
            "the flow is gone"
        );
    }

    #[tokio::test]
    async fn login_flow_poll_takes_the_token_from_the_query_too() {
        // Nextcloud iOS polls with `POST .../poll?token=...` and no body or content type.
        let f = fixture().await;
        let ios = "Mozilla/5.0 (iOS) Nextcloud-iOS/35.2.2";
        let start = f
            .send(
                "POST",
                "/index.php/login/v2",
                None,
                &[("User-Agent", ios)],
                "",
            )
            .await;
        let start: serde_json::Value = serde_json::from_str(&start.body).unwrap();
        let poll_token = start["poll"]["token"].as_str().unwrap().to_owned();
        let login_token = start["login"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let query_poll = format!("/index.php/login/v2/poll?token={poll_token}");

        let pending = f.send("POST", &query_poll, None, &[], "").await;
        assert_eq!(pending.status, StatusCode::NOT_FOUND, "{}", pending.body);
        assert_eq!(
            f.send("POST", "/index.php/login/v2/poll", None, &[], "")
                .await
                .status,
            StatusCode::NOT_FOUND,
            "no token at all"
        );

        let now = db::unix_now();
        let flow = gono_server_core::login_flows::find(&f.state.db, &login_token, now)
            .await
            .unwrap()
            .expect("pending flow");
        assert!(
            gono_server_core::login_flows::grant(&f.state.db, flow.id, 1, now)
                .await
                .unwrap()
        );
        // With a token in both places, the one in the body counts.
        let wrong_query = f
            .send(
                "POST",
                "/index.php/login/v2/poll?token=wrong",
                None,
                &[FORM],
                &format!("token={poll_token}"),
            )
            .await;
        assert_eq!(wrong_query.status, StatusCode::OK, "{}", wrong_query.body);
        let completed: serde_json::Value = serde_json::from_str(&wrong_query.body).unwrap();
        assert_eq!(completed["loginName"], "alice");
        assert!(
            completed["appPassword"]
                .as_str()
                .is_some_and(|p| !p.is_empty())
        );
        assert_eq!(
            f.send("POST", &query_poll, None, &[], "").await.status,
            StatusCode::NOT_FOUND,
            "single use"
        );

        // The query alone completes a flow as well.
        let start = f
            .send("POST", "/login/v2", None, &[("User-Agent", ios)], "")
            .await;
        let start: serde_json::Value = serde_json::from_str(&start.body).unwrap();
        let poll_token = start["poll"]["token"].as_str().unwrap().to_owned();
        let login_token = start["login"].as_str().unwrap().rsplit('/').next().unwrap();
        let flow = gono_server_core::login_flows::find(&f.state.db, login_token, now)
            .await
            .unwrap()
            .expect("pending flow");
        gono_server_core::login_flows::grant(&f.state.db, flow.id, 1, now)
            .await
            .unwrap();
        let completed = f
            .send(
                "POST",
                &format!("/login/v2/poll?token={poll_token}"),
                None,
                &[],
                "",
            )
            .await;
        assert_eq!(completed.status, StatusCode::OK, "{}", completed.body);
        let labels: Vec<String> = app_passwords::list(&f.state.db, 1)
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.label)
            .collect();
        assert!(
            labels.iter().filter(|l| l.contains("iOS")).count() == 2,
            "{labels:?}"
        );
    }

    #[tokio::test]
    async fn failed_web_sign_ins_are_rate_limited_apart_from_devices() {
        let f = fixture().await;
        let start = f.send("POST", "/login/v2", None, &[], "").await;
        let start: serde_json::Value = serde_json::from_str(&start.body).unwrap();
        assert!(
            start["poll"]["endpoint"]
                .as_str()
                .unwrap()
                .ends_with("/login/v2/poll")
        );
        let page = start["login"]
            .as_str()
            .unwrap()
            .trim_start_matches("http://localhost:8080")
            .to_owned();
        let form = f.send("GET", &page, None, &[], "").await;
        let cookie = set_cookie(&form, "gono_csrf").unwrap();
        let body = format!(
            "action=login&csrf={}&user=alice&password=wrong",
            csrf_field(&form.body)
        );
        for _ in 0..crate::ratelimit::BURST {
            let reply = f
                .send("POST", &page, None, &[FORM, ("Cookie", &cookie)], &body)
                .await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN);
        }
        let limited = f
            .send("POST", &page, None, &[FORM, ("Cookie", &cookie)], &body)
            .await;
        assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.header("retry-after").parse::<u64>().unwrap() >= 1);
        // Devices have a limiter of their own.
        let dav = f.send("PROPFIND", FILES, Some("wrong"), &[], "").await;
        assert_eq!(dav.status, StatusCode::UNAUTHORIZED, "separate limiters");
    }

    const UPLOADS: &str = "/remote.php/dav/uploads/alice";

    #[tokio::test]
    async fn chunked_uploads_assemble_resume_and_respect_scopes() {
        let f = fixture().await;
        let full = Some(f.full.as_str());
        let destination = "http://localhost/remote.php/dav/files/alice/big.bin";
        let session = format!("{UPLOADS}/s1");
        let created = f
            .send(
                "MKCOL",
                &session,
                full,
                &[("Destination", destination), ("OC-Total-Length", "11")],
                "",
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
        assert_eq!(
            f.send("MKCOL", &session, full, &[], "").await.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "the session exists"
        );
        for (name, body) in [("00002", "world"), ("00001", "hello ")] {
            let chunk = f
                .send("PUT", &format!("{session}/{name}"), full, &[], body)
                .await;
            assert_eq!(chunk.status, StatusCode::CREATED, "{}", chunk.body);
        }
        // A resuming client lists what arrived.
        let listing = f
            .send("PROPFIND", &session, full, &[("Depth", "1")], "")
            .await;
        assert_eq!(listing.status, StatusCode::MULTI_STATUS);
        assert!(
            listing
                .body
                .contains("/remote.php/dav/uploads/alice/s1/00001</d:href>")
        );
        assert!(
            listing
                .body
                .contains("<d:getcontentlength>6</d:getcontentlength>"),
            "{}",
            listing.body
        );

        let short = f
            .send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[("Destination", destination), ("OC-Total-Length", "12")],
                "",
            )
            .await;
        assert_eq!(short.status, StatusCode::BAD_REQUEST, "differs from MKCOL");
        let moved = f
            .send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[
                    ("Destination", destination),
                    ("OC-Total-Length", "11"),
                    // NextcloudKit sends fractions of a second.
                    ("X-OC-MTime", "1700000000.75"),
                ],
                "",
            )
            .await;
        assert_eq!(moved.status, StatusCode::CREATED, "{}", moved.body);
        assert_eq!(moved.header("x-oc-mtime"), "accepted");
        assert_eq!(moved.header("etag"), moved.header("oc-etag"));
        assert!(moved.header("oc-fileid").len() > 8);
        let get = f
            .send("GET", &format!("{FILES}/big.bin"), full, &[], "")
            .await;
        assert_eq!(get.body, "hello world");
        assert_eq!(get.header("last-modified"), "Tue, 14 Nov 2023 22:13:20 GMT");
        assert_eq!(get.header("etag"), moved.header("etag"));
        assert_eq!(
            f.send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[("Destination", destination)],
                ""
            )
            .await
            .status,
            StatusCode::NOT_FOUND,
            "the session is consumed"
        );

        // Overwrite with a stale If-Match is refused; with the current ETag it replaces (204).
        let session = format!("{UPLOADS}/s2");
        f.send("MKCOL", &session, full, &[], "").await;
        f.send("PUT", &format!("{session}/1"), full, &[], "new")
            .await;
        let stale = f
            .send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[("Destination", destination), ("If-Match", "\"stale\"")],
                "",
            )
            .await;
        assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
        let current = get.header("etag");
        let replaced = f
            .send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[("Destination", destination), ("If-Match", current.as_str())],
                "",
            )
            .await;
        assert_eq!(replaced.status, StatusCode::NO_CONTENT, "{}", replaced.body);
        assert_eq!(replaced.header("oc-fileid"), moved.header("oc-fileid"));

        // Scopes: read-only app passwords and other users' namespaces are refused.
        assert_eq!(
            f.send("MKCOL", &format!("{UPLOADS}/s3"), Some(&f.view), &[], "")
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            f.send("MKCOL", "/remote.php/dav/uploads/bob/s3", full, &[], "")
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        let foreign = f
            .send(
                "MKCOL",
                &format!("{UPLOADS}/s3"),
                full,
                &[("Destination", "http://localhost/remote.php/dav/files/bob/x")],
                "",
            )
            .await;
        assert_eq!(foreign.status, StatusCode::FORBIDDEN);
        assert_eq!(
            f.send("PUT", &format!("{UPLOADS}/missing/1"), full, &[], "x")
                .await
                .status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn chunked_uploads_accept_rclone_byte_ranges() {
        let f = fixture().await;
        let full = Some(f.full.as_str());
        // rclone's Nextcloud backend: MKCOL without Destination, chunks named by their byte
        // range (15 digits, end inclusive), MOVE with Destination and X-OC-Mtime but without
        // OC-Total-Length.
        let session = format!("{UPLOADS}/rclone-chunked-upload-0123456789abcdef");
        let mkcol = f.send("MKCOL", &format!("{session}/"), full, &[], "").await;
        assert_eq!(mkcol.status, StatusCode::CREATED, "{}", mkcol.body);
        let form = [("Content-Type", "application/x-www-form-urlencoded")];
        for (name, body) in [
            ("000000000000006-000000000000010", "world"),
            ("000000000000000-000000000000005", "hello "),
        ] {
            let chunk = f
                .send("PUT", &format!("{session}/{name}"), full, &form, body)
                .await;
            assert_eq!(chunk.status, StatusCode::CREATED, "{name}: {}", chunk.body);
        }
        // A chunk shorter than its range, and a numbered chunk in a session of byte ranges.
        for (name, body) in [("000000000000011-000000000000020", "short"), ("00003", "!")] {
            let refused = f
                .send("PUT", &format!("{session}/{name}"), full, &form, body)
                .await;
            assert_eq!(
                refused.status,
                StatusCode::BAD_REQUEST,
                "{name}: {}",
                refused.body
            );
        }
        let moved = f
            .send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[
                    (
                        "Destination",
                        "http://localhost/remote.php/dav/files/alice/rc.bin",
                    ),
                    ("X-OC-Mtime", "1700000000"),
                ],
                "",
            )
            .await;
        assert_eq!(moved.status, StatusCode::CREATED, "{}", moved.body);
        assert_eq!(moved.header("x-oc-mtime"), "accepted");
        let get = f
            .send("GET", &format!("{FILES}/rc.bin"), full, &[], "")
            .await;
        assert_eq!(get.body, "hello world");
        assert_eq!(get.header("last-modified"), "Tue, 14 Nov 2023 22:13:20 GMT");

        // Without OC-Total-Length the ranges still have to cover the file without a gap.
        let gap = format!("{UPLOADS}/rclone-gap");
        let gap_destination = "http://localhost/remote.php/dav/files/alice/gap.bin";
        f.send("MKCOL", &gap, full, &[], "").await;
        for (name, body) in [("0-1", "ab"), ("4-5", "ef")] {
            let chunk = f
                .send("PUT", &format!("{gap}/{name}"), full, &[], body)
                .await;
            assert_eq!(chunk.status, StatusCode::CREATED, "{name}: {}", chunk.body);
        }
        let refused = f
            .send(
                "MOVE",
                &format!("{gap}/.file"),
                full,
                &[("Destination", gap_destination)],
                "",
            )
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert!(
            refused
                .body
                .contains("Chunk 4-5 starts at byte 4, expected 2"),
            "{}",
            refused.body
        );
        assert_eq!(
            f.send("GET", &format!("{FILES}/gap.bin"), full, &[], "")
                .await
                .status,
            StatusCode::NOT_FOUND
        );
        // The client can still repair the session: drop a chunk, send the missing bytes.
        let deleted = f.send("DELETE", &format!("{gap}/4-5"), full, &[], "").await;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);
        let filled = f
            .send("PUT", &format!("{gap}/2-5"), full, &[], "cdef")
            .await;
        assert_eq!(filled.status, StatusCode::CREATED, "{}", filled.body);
        let moved = f
            .send(
                "MOVE",
                &format!("{gap}/.file"),
                full,
                &[("Destination", gap_destination)],
                "",
            )
            .await;
        assert_eq!(moved.status, StatusCode::CREATED, "{}", moved.body);
        let get = f
            .send("GET", &format!("{FILES}/gap.bin"), full, &[], "")
            .await;
        assert_eq!(get.body, "abcdef");
    }

    #[tokio::test]
    async fn the_janitor_removes_expired_and_orphaned_uploads() {
        let f = fixture().await;
        let full = Some(f.full.as_str());
        let session = format!("{UPLOADS}/expiring");
        f.send("MKCOL", &session, full, &[], "").await;
        f.send("PUT", &format!("{session}/1"), full, &[], "x").await;
        f.send("MKCOL", &format!("{UPLOADS}/live"), full, &[], "")
            .await;
        sqlx::query("UPDATE upload_sessions SET expires_at = 0 WHERE upload_id = 'expiring'")
            .execute(&f.state.db)
            .await
            .unwrap();
        let uploads = f.dir.path().join("data/uploads/1");
        let old_orphan = uploads.join("0123456789abcdef0123456789abcdef");
        let new_orphan = uploads.join("fedcba9876543210fedcba9876543210");
        for dir in [&old_orphan, &new_orphan] {
            std::fs::create_dir(dir).unwrap();
        }
        let two_hours_ago = std::time::SystemTime::now() - Duration::from_secs(7200);
        std::fs::File::open(&old_orphan)
            .unwrap()
            .set_modified(two_hours_ago)
            .unwrap();
        let session_dir =
            |id: &str| uploads.join(gono_server_core::storage::upload_session_dir_name(id));
        assert!(session_dir("expiring").join("1").exists());

        crate::janitor::Janitor {
            db: f.state.db.clone(),
            uploads: f.state.uploads.clone(),
        }
        .run_once()
        .await;
        assert!(!session_dir("expiring").exists());
        assert!(!old_orphan.exists());
        assert!(new_orphan.exists(), "a MKCOL may be creating it right now");
        assert!(session_dir("live").exists());
        assert_eq!(
            f.send("PROPFIND", &session, full, &[], "").await.status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn chunked_uploads_respect_locks_and_can_be_cancelled() {
        let f = fixture().await;
        let full = Some(f.full.as_str());
        f.send("PUT", &format!("{FILES}/locked.txt"), full, &[], "old")
            .await;
        let lock = f
            .send(
                "LOCK",
                &format!("{FILES}/locked.txt"),
                full,
                &[],
                r#"<?xml version="1.0"?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>"#,
            )
            .await;
        assert_eq!(lock.status, StatusCode::OK, "{}", lock.body);
        let token = lock.header("lock-token");
        let destination = "/remote.php/dav/files/alice/locked.txt";
        let session = format!("{UPLOADS}/locked");
        f.send("MKCOL", &session, full, &[], "").await;
        f.send("PUT", &format!("{session}/1"), full, &[], "new")
            .await;
        let refused = f
            .send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[("Destination", destination)],
                "",
            )
            .await;
        assert_eq!(refused.status, StatusCode::LOCKED, "{}", refused.body);
        let held = format!("({token})");
        let moved = f
            .send(
                "MOVE",
                &format!("{session}/.file"),
                full,
                &[("Destination", destination), ("If", held.as_str())],
                "",
            )
            .await;
        assert_eq!(moved.status, StatusCode::NO_CONTENT, "{}", moved.body);

        let cancelled = format!("{UPLOADS}/cancelled");
        f.send("MKCOL", &cancelled, full, &[], "").await;
        f.send("PUT", &format!("{cancelled}/1"), full, &[], "x")
            .await;
        assert_eq!(
            f.send("PUT", &format!("{cancelled}/one"), full, &[], "x")
                .await
                .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            f.send("DELETE", &cancelled, full, &[], "").await.status,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            f.send("PROPFIND", &cancelled, full, &[], "").await.status,
            StatusCode::NOT_FOUND
        );
    }
}
