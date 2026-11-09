//! notify_push endpoints (see [`gono_nextcloud::notify_push`] for the protocol and the hub).
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /push/ws` (WebSocket upgrade) | The push connection. |
//! | `POST /index.php/apps/notify_push/pre_auth` (also without `/index.php`) | A single-use token for the WebSocket, for a request authenticated with an app password. |
//!
//! A connection goes through these stages:
//!
//! 1. **Handshake.** At most
//!    [`MAX_HANDSHAKES`](gono_nextcloud::notify_push::MAX_HANDSHAKES) connections may wait for credentials at once;
//!    each has `notify_push.auth_timeout_secs` to send them. Frames are limited to
//!    [`MAX_FRAME_BYTES`], so nobody can make the server buffer large messages.
//! 2. **Authentication.** Username and app password go through the shared
//!    [`Authenticator`](crate::auth::Authenticator) and its failed-attempt limiter; a pre-auth
//!    token (empty username) is checked against the same limiter. Failures are answered with
//!    `err: ...` and a close frame.
//! 3. **Subscription.** The hub refuses users at `notify_push.max_connections_per_user`.
//! 4. **Streaming.** Changes are filtered and debounced by an [`Outbox`]. Every
//!    `notify_push.ping_interval_secs` the server checks that the app password is still valid
//!    (revoked, expired or disabled ends the connection) and sends a ping; a client that has
//!    not sent anything (a pong or any other frame) by the next ping is disconnected, and so
//!    is one that does not take a frame within one ping interval.
//! 5. **Shutdown.** When the server stops, every connection gets a `1001 Going Away` close.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Bytes,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket, close_code},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use gono_core::{app_passwords, db};
use gono_dav::Identity;
use gono_nextcloud::notify_push::{
    Handshake, Hub, Outbox, SubscribeError, Subscription,
    message::{self, AUTHENTICATED},
};
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::broadcast::error::RecvError;

use crate::{
    app::{AppState, authenticate},
    auth::AuthOutcome,
    client_ip::client_ip,
};

/// Largest frame or message a client may send. The protocol only needs a username, an app
/// password or token, and `listen notify_file_id`.
pub const MAX_FRAME_BYTES: usize = 4096;

/// Why a connection was not authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailure {
    /// The client closed the socket or the connection broke; nobody to answer.
    Gone,
    /// The client sent something other than two text frames.
    Protocol,
    /// Wrong credentials or an unknown, used or expired pre-auth token.
    Invalid,
    /// Too many failed attempts from this client address.
    RateLimited,
}

/// `GET /push/ws`.
pub async fn websocket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Some(hub) = state.push.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(handshake) = hub.begin_handshake() else {
        tracing::warn!("too many notify_push connections are waiting for credentials");
        let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("10"));
        return response;
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    upgrade
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| serve(socket, state, hub, client, handshake))
}

/// `POST /index.php/apps/notify_push/pre_auth` and `POST /apps/notify_push/pre_auth`.
pub async fn pre_auth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(hub) = state.push.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let identity = match authenticate(&state, peer, &headers).await {
        Ok(identity) => identity,
        Err(rejection) => return rejection.into_response(),
    };
    let Some(token) = hub.issue_pre_auth(identity) else {
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        let wait = hub.settings().pre_auth_ttl.as_secs().max(1).to_string();
        if let Ok(value) = HeaderValue::from_str(&wait) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    };
    let mut response = token.expose_secret().to_owned().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// One push connection, from the first frame to the close.
async fn serve(
    mut socket: WebSocket,
    state: AppState,
    hub: Arc<Hub>,
    client: IpAddr,
    handshake: Handshake,
) {
    let settings = *hub.settings();
    let identity = match tokio::time::timeout(
        settings.auth_timeout,
        authenticate_socket(&mut socket, &state, &hub, client),
    )
    .await
    {
        Ok(Ok(identity)) => identity,
        Ok(Err(failure)) => {
            tracing::info!(%client, ?failure, "notify_push authentication failed");
            let reason = match failure {
                AuthFailure::Gone => return,
                AuthFailure::Protocol => "Invalid auth message",
                AuthFailure::Invalid => "Invalid credentials",
                AuthFailure::RateLimited => "Too many failed attempts, try again later",
            };
            reject(&mut socket, reason, close_code::POLICY).await;
            return;
        }
        Err(_) => {
            tracing::info!(%client, "notify_push authentication timed out");
            reject(&mut socket, "Authentication timeout", close_code::POLICY).await;
            return;
        }
    };
    drop(handshake);

    let subscription = match hub.subscribe(identity.user_id) {
        Ok(subscription) => subscription,
        Err(SubscribeError::TooManyConnections) => {
            tracing::warn!(
                %client,
                user = %identity.username,
                "notify_push connection limit reached"
            );
            reject(&mut socket, "Too many connections", close_code::AGAIN).await;
            return;
        }
    };
    if socket.send(Message::text(AUTHENTICATED)).await.is_err() {
        return;
    }
    tracing::info!(
        %client,
        user = %identity.username,
        app_password = identity.app_password_id,
        "notify_push connected"
    );
    let ended = stream(&mut socket, &state, &hub, subscription, identity.clone()).await;
    tracing::info!(
        %client,
        user = %identity.username,
        reason = ended,
        "notify_push disconnected"
    );
}

/// Reads the two credential frames and checks them.
async fn authenticate_socket(
    socket: &mut WebSocket,
    state: &AppState,
    hub: &Hub,
    client: IpAddr,
) -> Result<Arc<Identity>, AuthFailure> {
    let username = read_text(socket).await?;
    let password = SecretString::from(read_text(socket).await?);
    if username.is_empty() {
        let limiter = state.auth.limiter();
        if limiter.check(client).is_some() {
            return Err(AuthFailure::RateLimited);
        }
        return hub
            .redeem_pre_auth(password.expose_secret())
            .ok_or_else(|| {
                limiter.record_failure(client);
                AuthFailure::Invalid
            });
    }
    match state
        .auth
        .authenticate_credentials(client, &username, &password)
        .await
    {
        AuthOutcome::Authenticated(identity) => Ok(identity),
        AuthOutcome::Missing | AuthOutcome::Invalid => Err(AuthFailure::Invalid),
        AuthOutcome::RateLimited(_) => Err(AuthFailure::RateLimited),
    }
}

/// The next text frame; pings and pongs are skipped.
async fn read_text(socket: &mut WebSocket) -> Result<String, AuthFailure> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => return Ok(text.as_str().to_owned()),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(Message::Binary(_))) => return Err(AuthFailure::Protocol),
            // Too large frames end up here as errors, like broken connections.
            Some(Ok(Message::Close(_)) | Err(_)) | None => return Err(AuthFailure::Gone),
        }
    }
}

/// Sends `err: <reason>` and closes the socket.
async fn reject(socket: &mut WebSocket, reason: &'static str, code: u16) {
    if socket
        .send(Message::text(message::error(reason)))
        .await
        .is_ok()
    {
        close(socket, code, reason).await;
    }
}

/// Sends a close frame (best effort: a client that does not read gets a few seconds).
async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    send_within(socket, Message::Close(Some(frame)), CLOSE_TIMEOUT).await;
}

/// How long a close frame may take to send.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends a frame, giving up after `limit`: a client that stopped reading must not hold the
/// connection task (and its heartbeat) up forever.
async fn send_within(socket: &mut WebSocket, message: Message, limit: Duration) -> bool {
    matches!(
        tokio::time::timeout(limit, socket.send(message)).await,
        Ok(Ok(()))
    )
}

/// One heartbeat: checks the pong of the previous ping and the app password, then pings.
async fn heartbeat(
    socket: &mut WebSocket,
    state: &AppState,
    identity: &Identity,
    awaiting_pong: &mut bool,
    limit: Duration,
) -> Result<(), &'static str> {
    if *awaiting_pong {
        close(socket, close_code::AWAY, "Ping timeout").await;
        return Err("no answer to ping");
    }
    match app_passwords::is_active(&state.db, identity.app_password_id, db::unix_now()).await {
        Ok(true) => {}
        Ok(false) => {
            close(socket, close_code::POLICY, "Credentials revoked").await;
            return Err("app password revoked, expired or account disabled");
        }
        // Keep the connection; the next heartbeat checks again.
        Err(err) => tracing::warn!(error = %err, "cannot check a push connection's app password"),
    }
    if !send_within(socket, Message::Ping(Bytes::new()), limit).await {
        return Err("send failed or timed out");
    }
    *awaiting_pong = true;
    Ok(())
}

/// Streams notifications until the connection ends; returns why it ended.
async fn stream(
    socket: &mut WebSocket,
    state: &AppState,
    hub: &Hub,
    mut subscription: Subscription,
    identity: Arc<Identity>,
) -> &'static str {
    let settings = *hub.settings();
    let mut outbox = Outbox::new(Arc::clone(&identity), settings.debounce);
    let start = tokio::time::Instant::now() + settings.ping_interval;
    let mut ping = tokio::time::interval_at(start, settings.ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut awaiting_pong = false;
    let stopped = hub.stopped();
    tokio::pin!(stopped);

    loop {
        let due = outbox.next_due().map(tokio::time::Instant::from_std);
        let wake = async move {
            match due {
                Some(due) => tokio::time::sleep_until(due).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = &mut stopped => {
                close(socket, close_code::AWAY, "Server shutting down").await;
                return "server shutting down";
            }
            event = subscription.recv() => match event {
                Ok(event) => outbox.push(&event, Instant::now()),
                Err(RecvError::Lagged(_)) => outbox.missed(Instant::now()),
                Err(RecvError::Closed) => return "hub closed",
            },
            () = wake => {
                for text in outbox.take_due(Instant::now()) {
                    if !send_within(socket, Message::text(text), settings.ping_interval).await {
                        return "send failed or timed out";
                    }
                }
            }
            _ = ping.tick() => {
                let limit = settings.ping_interval;
                if let Err(ended) =
                    heartbeat(socket, state, &identity, &mut awaiting_pong, limit).await
                {
                    return ended;
                }
            }
            frame = socket.recv() => match frame {
                Some(Ok(Message::Text(text))) => {
                    awaiting_pong = false;
                    outbox.client_text(text.as_str());
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => awaiting_pong = false,
                Some(Ok(Message::Binary(_))) => {
                    close(socket, close_code::UNSUPPORTED, "Binary frames are unsupported").await;
                    return "binary frame";
                }
                Some(Ok(Message::Close(_))) | None => return "closed by the client",
                Some(Err(_)) => return "connection error",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    //! The WebSocket over a real TCP connection, with a tungstenite client.

    use axum::{body::Body, http::Request};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use futures_util::{SinkExt as _, StreamExt as _};
    use gono_core::{
        Permission, RelPath, Username,
        app_passwords::{self, Scope},
        config::DbConfig,
        db::OpenMode,
        meta::{DiskStat, MetaStore},
        storage::DataLayout,
        users::{self, NewUser},
    };
    use gono_nextcloud::{
        chunking::ChunkedUploads,
        notify_push::{Hub, PushSettings},
    };
    use http_body_util::BodyExt as _;
    use tokio::net::TcpStream;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite};
    use tower::ServiceExt as _;
    use url::Url;

    use super::*;
    use crate::{auth::Authenticator, ratelimit::RateLimiter, web::Web};

    type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

    struct Fixture {
        _dir: tempfile::TempDir,
        state: AppState,
        meta: MetaStore,
        url: String,
        alice: i64,
        /// Full access.
        full: String,
        full_id: i64,
        /// Only `Inbox` (mounted at `/in`).
        scoped: String,
    }

    fn settings() -> PushSettings {
        PushSettings {
            ping_interval: Duration::from_secs(1),
            auth_timeout: Duration::from_secs(1),
            pre_auth_ttl: Duration::from_secs(15),
            debounce: Duration::from_secs(1),
            max_connections_per_user: 2,
        }
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
        let username = Username::new("alice").unwrap();
        let alice = users::create(
            &pool,
            &NewUser {
                username: &username,
                display_name: "Alice",
                password_hash: "x",
                is_admin: false,
            },
            |id| layout.create_user(id),
        )
        .await
        .unwrap();
        let (full_id, full) = app_passwords::create(&pool, alice, "full", Vec::new(), None)
            .await
            .unwrap();
        let inbox = Scope {
            mount_path: RelPath::parse("in").unwrap(),
            storage_path: RelPath::parse("Inbox").unwrap(),
            permission: Permission::View,
        };
        let (_, scoped) = app_passwords::create(&pool, alice, "scoped", vec![inbox], None)
            .await
            .unwrap();

        let hub = Hub::new(settings(), 0);
        let meta = MetaStore::new(pool.clone()).with_sink(hub.clone());
        let dav =
            crate::commands::serve::dav_service(Duration::from_secs(600), layout, meta.clone())
                .await
                .unwrap();
        let uploads = ChunkedUploads::new(
            dav.fs().clone(),
            gono_core::locks::LockStore::new(pool.clone()),
        );
        let limiter = Arc::new(RateLimiter::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = Url::parse(&format!("http://{address}")).unwrap();
        let state = AppState {
            db: pool.clone(),
            auth: Arc::new(Authenticator::new(pool.clone(), limiter.clone())),
            dav,
            uploads,
            web: Arc::new(Web::new(pool, limiter, &base_url)),
            base_url: Arc::new(base_url),
            flow_starts: Arc::new(RateLimiter::new()),
            trusted_proxies: Arc::new(Vec::new()),
            push: Some(hub),
        };
        let app = crate::app::router(state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Fixture {
            _dir: dir,
            state,
            meta,
            url: format!("ws://{address}/push/ws"),
            alice,
            full: full.expose_secret().to_owned(),
            full_id,
            scoped: scoped.expose_secret().to_owned(),
        }
    }

    impl Fixture {
        async fn connect(&self) -> Client {
            tokio_tungstenite::connect_async(&self.url).await.unwrap().0
        }

        /// Connects and sends two credential frames; returns the socket and the reply.
        async fn login(&self, user: &str, password: &str) -> (Client, Option<String>) {
            let mut client = self.connect().await;
            client.send(text(user)).await.unwrap();
            client.send(text(password)).await.unwrap();
            let reply = next_text(&mut client, Duration::from_secs(5)).await;
            (client, reply)
        }

        async fn authenticated(&self, password: &str) -> Client {
            let (client, reply) = self.login("alice", password).await;
            assert_eq!(reply.as_deref(), Some("authenticated"));
            client
        }

        async fn write(&self, path: &str) {
            let stat = DiskStat {
                is_dir: false,
                mtime_ns: 1,
                size: 1,
            };
            self.meta
                .record_write(self.alice, &RelPath::parse(path).unwrap(), stat)
                .await
                .unwrap();
        }

        async fn pre_auth(&self, password: Option<&str>) -> (StatusCode, String) {
            let mut request = Request::post(PRE_AUTH).body(Body::empty()).unwrap();
            if let Some(password) = password {
                let value = format!("Basic {}", STANDARD.encode(format!("alice:{password}")));
                request
                    .headers_mut()
                    .insert(header::AUTHORIZATION, value.parse().unwrap());
            }
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 4000))));
            let response = crate::app::router(self.state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&body).into_owned())
        }
    }

    const PRE_AUTH: &str = "/index.php/apps/notify_push/pre_auth";

    fn text(value: &str) -> tungstenite::Message {
        tungstenite::Message::text(value.to_owned())
    }

    /// The next text frame within `timeout`; `None` on timeout, close or error. Pings are
    /// answered by tungstenite while reading.
    async fn next_text(client: &mut Client, timeout: Duration) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, client.next()).await {
                Ok(Some(Ok(tungstenite::Message::Text(text)))) => return Some(text.to_string()),
                Ok(Some(Ok(tungstenite::Message::Close(_)) | Err(_)) | None) | Err(_) => {
                    return None;
                }
                Ok(Some(Ok(_))) => {}
            }
        }
    }

    /// Reads until the server closes the connection; returns the close code.
    async fn close_code(client: &mut Client, timeout: Duration) -> Option<u16> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, client.next()).await {
                Ok(Some(Ok(tungstenite::Message::Close(frame)))) => {
                    return frame.map(|frame| u16::from(frame.code));
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(_)) | None) | Err(_) => return None,
            }
        }
    }

    #[tokio::test]
    async fn app_password_authentication_and_file_notifications() {
        let fixture = fixture().await;
        let mut client = fixture.authenticated(&fixture.full).await;
        fixture.write("a.txt").await;
        assert_eq!(
            next_text(&mut client, Duration::from_secs(5))
                .await
                .as_deref(),
            Some("notify_file")
        );

        client.send(text("listen notify_file_id")).await.unwrap();
        // Let the server read the request before the change.
        tokio::time::sleep(Duration::from_millis(100)).await;
        fixture.write("b.txt").await;
        let id = fixture
            .meta
            .get(fixture.alice, &RelPath::parse("b.txt").unwrap())
            .await
            .unwrap()
            .unwrap()
            .id;
        assert_eq!(
            next_text(&mut client, Duration::from_secs(5)).await,
            Some(format!("notify_file_id [{id}]"))
        );
    }

    #[tokio::test]
    async fn bad_credentials_are_refused() {
        let fixture = fixture().await;
        let (mut client, reply) = fixture.login("alice", "wrong").await;
        assert_eq!(reply.as_deref(), Some("err: Invalid credentials"));
        assert_eq!(
            close_code(&mut client, Duration::from_secs(5)).await,
            Some(close_code::POLICY)
        );
        let (_, reply) = fixture.login("bob", &fixture.full).await;
        assert_eq!(reply.as_deref(), Some("err: Invalid credentials"));
    }

    #[tokio::test]
    async fn failed_attempts_are_rate_limited() {
        let fixture = fixture().await;
        for _ in 0..crate::ratelimit::BURST {
            let (_, reply) = fixture.login("", "not-a-token").await;
            assert_eq!(reply.as_deref(), Some("err: Invalid credentials"));
        }
        let (_, reply) = fixture.login("alice", &fixture.full).await;
        assert_eq!(
            reply.as_deref(),
            Some("err: Too many failed attempts, try again later")
        );
    }

    #[tokio::test]
    async fn pre_auth_tokens_need_credentials_and_work_once() {
        let fixture = fixture().await;
        assert_eq!(fixture.pre_auth(None).await.0, StatusCode::UNAUTHORIZED);
        let (status, token) = fixture.pre_auth(Some(&fixture.full)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(token.len() >= 32, "{token}");

        let (_first, reply) = fixture.login("", &token).await;
        assert_eq!(reply.as_deref(), Some("authenticated"));
        let (_second, reply) = fixture.login("", &token).await;
        assert_eq!(reply.as_deref(), Some("err: Invalid credentials"));
    }

    #[tokio::test]
    async fn connections_per_user_are_limited() {
        let fixture = fixture().await;
        let _first = fixture.authenticated(&fixture.full).await;
        let second = fixture.authenticated(&fixture.full).await;
        let (_, reply) = fixture.login("alice", &fixture.full).await;
        assert_eq!(reply.as_deref(), Some("err: Too many connections"));
        drop(second);
        // The server notices the closed socket and frees the slot.
        let mut reply = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let (_client, answer) = fixture.login("alice", &fixture.full).await;
            reply = answer;
            if reply.as_deref() == Some("authenticated") {
                break;
            }
        }
        assert_eq!(reply.as_deref(), Some("authenticated"));
    }

    #[tokio::test]
    async fn silent_and_oversized_clients_are_disconnected() {
        let fixture = fixture().await;
        let mut silent = fixture.connect().await;
        assert_eq!(
            next_text(&mut silent, Duration::from_secs(5))
                .await
                .as_deref(),
            Some("err: Authentication timeout")
        );

        let mut large = fixture.connect().await;
        large
            .send(text(&"x".repeat(MAX_FRAME_BYTES + 1)))
            .await
            .unwrap();
        assert_eq!(next_text(&mut large, Duration::from_secs(5)).await, None);
    }

    #[tokio::test]
    async fn clients_that_do_not_answer_pings_are_disconnected() {
        let fixture = fixture().await;
        let mut client = fixture.authenticated(&fixture.full).await;
        // Not reading means not answering pings: after one unanswered ping the next tick
        // closes the connection.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(
            close_code(&mut client, Duration::from_secs(5)).await,
            Some(close_code::AWAY)
        );

        // A client that reads (and so answers pings) stays connected.
        let mut client = fixture.authenticated(&fixture.full).await;
        assert_eq!(
            next_text(&mut client, Duration::from_millis(3500)).await,
            None
        );
        fixture.write("still-here.txt").await;
        assert!(
            next_text(&mut client, Duration::from_secs(5))
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn revoking_the_app_password_ends_the_connection() {
        let fixture = fixture().await;
        let mut client = fixture.authenticated(&fixture.full).await;
        app_passwords::delete(&fixture.state.db, fixture.alice, fixture.full_id)
            .await
            .unwrap();
        assert_eq!(
            close_code(&mut client, Duration::from_secs(5)).await,
            Some(close_code::POLICY)
        );
    }

    #[tokio::test]
    async fn scoped_connections_only_see_their_mounts() {
        let fixture = fixture().await;
        let mut scoped = fixture.authenticated(&fixture.scoped).await;
        fixture.write("outside.txt").await;
        assert_eq!(
            next_text(&mut scoped, Duration::from_millis(1500)).await,
            None
        );
        fixture.write("Inbox/inside.txt").await;
        assert_eq!(
            next_text(&mut scoped, Duration::from_secs(5))
                .await
                .as_deref(),
            Some("notify_file")
        );
    }

    #[tokio::test]
    async fn deletes_are_announced_with_the_deleted_id() {
        let fixture = fixture().await;
        fixture.write("doomed.txt").await;
        let mut client = fixture.authenticated(&fixture.full).await;
        client.send(text("listen notify_file_id")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let removed = fixture
            .meta
            .record_delete(fixture.alice, &RelPath::parse("doomed.txt").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            next_text(&mut client, Duration::from_secs(5)).await,
            Some(format!("notify_file_id [{}]", removed.id))
        );
    }

    #[tokio::test]
    async fn shutdown_closes_connections() {
        let fixture = fixture().await;
        let mut client = fixture.authenticated(&fixture.full).await;
        fixture.state.push.as_ref().unwrap().shut_down();
        assert_eq!(
            close_code(&mut client, Duration::from_secs(5)).await,
            Some(close_code::AWAY)
        );
    }
}
