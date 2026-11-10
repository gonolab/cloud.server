//! Authentication of device requests (HTTP Basic with an app password).
//!
//! 1. Requests without credentials get a Basic challenge and cost nothing.
//! 2. The password is hashed with SHA-256 and the single matching `app_passwords` row is
//!    loaded; it must belong to the given username, the account must be enabled, and the app
//!    password must not have expired. Web login passwords are never accepted here.
//!
//!    When the lookup itself fails (the database is unreachable or broken), the outcome is
//!    [`AuthOutcome::Unavailable`], answered with `503`, never `401`: after a `401` on
//!    `cloud/user` the Nextcloud iOS app deletes the account from the device, and Nextcloud
//!    Android discards the stored password, so a short database problem must not look like
//!    revoked credentials.
//! 3. Failures go to the [`RateLimiter`] **after** verification. App passwords are random
//!    tokens that cannot be guessed, so the limiter is not there to stop guessing; it slows
//!    down clients that keep failing: once a client address has used up its failed attempts,
//!    further wrong credentials get `429 Too Many Requests` instead of `401`. Valid
//!    credentials are always accepted. Behind one NAT address (a household, an office), a
//!    single misconfigured client, such as an old device with a revoked app password or a
//!    WebDAV app set up with the web login password, must not lock out every other device.
//!    The web login, whose passwords can be guessed, has a limiter of its own that it consults
//!    before verifying ([`crate::web`]).
//! 4. `last_used_at` is written at most once every [`LAST_USED_GRANULARITY`] per app password,
//!    in the background, so ordinary requests do not write to the database.
//!
//! The password is held in a `SecretString` and never logged.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gono_server_core::{PRODUCT_NAME, app_passwords, db};
use gono_server_dav::Identity;
use secrecy::SecretString;

use crate::ratelimit::RateLimiter;

/// Minimum time between two `last_used_at` updates of one app password, in seconds.
pub const LAST_USED_GRANULARITY: i64 = 300;

/// Outcome of [`Authenticator::authenticate`].
#[derive(Debug)]
pub enum AuthOutcome {
    /// Valid credentials.
    Authenticated(Arc<Identity>),
    /// No (Basic) credentials were sent.
    Missing,
    /// The credentials are wrong, expired or belong to a disabled account.
    Invalid,
    /// Too many failed attempts from this client; retry after the given time.
    RateLimited(Duration),
    /// The credentials could not be checked because the database failed; retry later.
    Unavailable,
}

/// Verifies app passwords. Shared by all request handlers.
#[derive(Debug)]
pub struct Authenticator {
    pool: db::Pool,
    limiter: Arc<RateLimiter>,
    /// App password id -> last `last_used_at` value written (or being written) by us.
    last_used: Mutex<HashMap<i64, i64>>,
}

impl Authenticator {
    /// Creates an authenticator that records failures in `limiter`.
    pub fn new(pool: db::Pool, limiter: Arc<RateLimiter>) -> Self {
        Self {
            pool,
            limiter,
            last_used: Mutex::new(HashMap::new()),
        }
    }

    /// The failed-attempt limiter of device authentication, also used for notify_push pre-auth
    /// tokens.
    pub fn limiter(&self) -> &Arc<RateLimiter> {
        &self.limiter
    }

    /// Authenticates a request from `client` by its `Authorization: Basic` header.
    pub async fn authenticate(&self, client: IpAddr, headers: &HeaderMap) -> AuthOutcome {
        let Some((username, password)) = basic_credentials(headers) else {
            return AuthOutcome::Missing;
        };
        self.authenticate_credentials(client, &username, &password)
            .await
    }

    /// Authenticates a username and app password sent by `client` some other way than a
    /// Basic header (the notify_push WebSocket), with the same rate limiting.
    pub async fn authenticate_credentials(
        &self,
        client: IpAddr,
        username: &str,
        password: &SecretString,
    ) -> AuthOutcome {
        // Verified first: the limiter never refuses valid credentials (see the module
        // documentation).
        let blocked = self.limiter.check(client);
        let now = db::unix_now();
        match app_passwords::authenticate(&self.pool, username, password, now).await {
            Ok(Some(device)) => {
                self.record_use(device.app_password_id, device.last_used_at, now);
                AuthOutcome::Authenticated(Identity::from_device(device))
            }
            Ok(None) => {
                self.limiter.record_failure(client);
                match blocked {
                    // Logged once per request by the request log already.
                    Some(wait) => AuthOutcome::RateLimited(wait),
                    None => {
                        tracing::info!(%client, user = %username, "rejected device credentials");
                        AuthOutcome::Invalid
                    }
                }
            }
            Err(err) => {
                // Neither let the request through nor call the credentials wrong (see the
                // module documentation); the error is logged once here.
                tracing::error!(error = %err, "authentication lookup failed");
                AuthOutcome::Unavailable
            }
        }
    }

    /// Writes `last_used_at` in the background unless it was written recently.
    fn record_use(&self, id: i64, stored: Option<i64>, now: i64) {
        if stored.is_some_and(|at| now - at < LAST_USED_GRANULARITY) {
            return;
        }
        {
            let mut last_used = self.last_used.lock().unwrap_or_else(|e| e.into_inner());
            if last_used
                .get(&id)
                .is_some_and(|&at| now - at < LAST_USED_GRANULARITY)
            {
                return;
            }
            last_used.insert(id, now);
        }
        let pool = self.pool.clone();
        tokio::spawn(async move {
            if let Err(err) = app_passwords::record_use(&pool, id, now).await {
                tracing::warn!(error = %err, app_password = id, "cannot record app password use");
            }
        });
    }
}

/// Extracts `(username, password)` from an `Authorization: Basic` header.
pub fn basic_credentials(headers: &HeaderMap) -> Option<(String, SecretString)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_owned(), SecretString::from(password.to_owned())))
}

/// The `WWW-Authenticate` value of a 401 response.
pub fn basic_challenge() -> HeaderValue {
    HeaderValue::from_str(&format!(
        "Basic realm=\"{PRODUCT_NAME}\", charset=\"UTF-8\""
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("Basic"))
}

#[cfg(test)]
mod tests {
    use gono_server_core::{
        Username,
        config::DbConfig,
        db::OpenMode,
        users::{self, NewUser},
    };
    use secrecy::ExposeSecret;

    use super::*;

    fn basic(user: &str, password: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = format!("Basic {}", STANDARD.encode(format!("{user}:{password}")));
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[test]
    fn parses_basic_credentials() {
        let (user, password) = basic_credentials(&basic("alice", "a:b:c")).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(password.expose_secret(), "a:b:c");

        let mut bearer = HeaderMap::new();
        bearer.insert(header::AUTHORIZATION, "Bearer xyz".parse().unwrap());
        assert!(basic_credentials(&bearer).is_none());
        let mut broken = HeaderMap::new();
        broken.insert(header::AUTHORIZATION, "Basic !!!".parse().unwrap());
        assert!(basic_credentials(&broken).is_none());
        assert!(basic_credentials(&HeaderMap::new()).is_none());
        assert!(
            basic_challenge()
                .to_str()
                .unwrap()
                .starts_with("Basic realm=")
        );
    }

    async fn setup() -> (tempfile::TempDir, db::Pool, String) {
        let dir = tempfile::tempdir().unwrap();
        let config = DbConfig {
            path: dir.path().join("db.sqlite"),
            max_connections: 2,
            busy_timeout_secs: 5,
        };
        let pool = db::connect(&config, OpenMode::CreateIfMissing)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let username = Username::new("alice").unwrap();
        let id = users::create(
            &pool,
            &NewUser {
                username: &username,
                display_name: "Alice",
                password_hash: "x",
                is_admin: false,
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        let (_, token) = app_passwords::create(&pool, id, "test", Vec::new(), None)
            .await
            .unwrap();
        (dir, pool, token.expose_secret().to_owned())
    }

    #[tokio::test]
    async fn authenticates_and_rate_limits_failures() {
        let (_dir, pool, token) = setup().await;
        let auth = Authenticator::new(pool, Arc::new(RateLimiter::new()));
        let client: IpAddr = "192.0.2.10".parse().unwrap();

        assert!(matches!(
            auth.authenticate(client, &HeaderMap::new()).await,
            AuthOutcome::Missing
        ));
        match auth.authenticate(client, &basic("alice", &token)).await {
            AuthOutcome::Authenticated(identity) => {
                assert_eq!(identity.username.as_str(), "alice");
                assert!(identity.mounts[0].writable);
            }
            other => panic!("expected success, got {other:?}"),
        }

        for _ in 0..crate::ratelimit::BURST {
            assert!(matches!(
                auth.authenticate(client, &basic("alice", "wrong")).await,
                AuthOutcome::Invalid
            ));
        }
        // Further failures are refused with 429, but the right app password still works
        // from the same address.
        match auth.authenticate(client, &basic("alice", "wrong")).await {
            AuthOutcome::RateLimited(wait) => assert!(wait <= crate::ratelimit::REFILL_INTERVAL),
            other => panic!("expected 429, got {other:?}"),
        }
        assert!(matches!(
            auth.authenticate(client, &basic("alice", &token)).await,
            AuthOutcome::Authenticated(_)
        ));
        let other: IpAddr = "192.0.2.11".parse().unwrap();
        assert!(matches!(
            auth.authenticate(other, &basic("alice", "wrong")).await,
            AuthOutcome::Invalid
        ));
    }

    #[tokio::test]
    async fn a_failing_database_is_unavailable_not_invalid() {
        let (_dir, pool, token) = setup().await;
        let limiter = Arc::new(RateLimiter::new());
        let auth = Authenticator::new(pool.clone(), Arc::clone(&limiter));
        let client: IpAddr = "192.0.2.10".parse().unwrap();
        pool.close().await;

        for _ in 0..=crate::ratelimit::BURST {
            assert!(matches!(
                auth.authenticate(client, &basic("alice", &token)).await,
                AuthOutcome::Unavailable
            ));
        }
        // Not counted as failures.
        assert!(limiter.check(client).is_none());
    }
}
