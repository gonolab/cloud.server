//! Building blocks of the server's HTML pages: the Login Flow v2 pages now, the web admin UI
//! later.
//!
//! - **Sign-in** ([`Web::sign_in`]) with the web login password (Argon2), behind the same
//!   per-client [`RateLimiter`] as device authentication: checked before anything is
//!   verified, one token per failure. Unknown accounts cost the same Argon2 work as known
//!   ones, so response times do not reveal which accounts exist.
//! - **Sessions**: a successful sign-in creates a `web_sessions` row
//!   ([`gono_core::web_sessions`]) and sets the [`SESSION_COOKIE`] (`HttpOnly`,
//!   `SameSite=Lax`, `Secure` when the public origin is HTTPS). App passwords never create a
//!   session.
//! - **CSRF**: every form carries a token. Before sign-in it is a double-submit token: a random
//!   value in the [`CSRF_COOKIE`] (`SameSite=Strict`) repeated in the form. After sign-in it
//!   is derived from the session token, which the page cannot read. POSTs with an `Origin` or
//!   `Sec-Fetch-Site` header that names another site are refused as well.
//! - **Headers** ([`page`]): a strict Content Security Policy (no scripts, only the page's own
//!   stylesheet by hash, forms only to this origin, no framing), `X-Frame-Options: DENY`,
//!   `Referrer-Policy: no-referrer` (page URLs can carry tokens), `Cache-Control: no-store`.

use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gono_core::{
    PRODUCT_NAME, Username, db, password, secret, users,
    web_sessions::{self, SessionUser},
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::ratelimit::RateLimiter;

/// Cookie holding the session token.
pub const SESSION_COOKIE: &str = "gono_session";

/// Cookie holding the double-submit CSRF token of forms shown before sign-in.
pub const CSRF_COOKIE: &str = "gono_csrf";

/// Length of the pre-sign-in CSRF token.
const CSRF_CHARS: usize = 43;

/// Outcome of [`Web::sign_in`].
#[derive(Debug)]
pub enum SignIn {
    /// The password is right: the cookie token of a new session.
    Ok(SecretString),
    /// Unknown account, wrong password or disabled account.
    Invalid,
    /// Too many failures from this client; retry after the given time.
    RateLimited(Duration),
}

/// Sessions, sign-in and CSRF checks of the HTML pages. Shared by all handlers.
#[derive(Debug)]
pub struct Web {
    pool: db::Pool,
    limiter: Arc<RateLimiter>,
    /// `scheme://host[:port]` of the public origin.
    origin: String,
    /// Mark cookies `Secure` (the public origin is HTTPS).
    secure: bool,
}

/// A PHC string to verify against when the account does not exist.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        password::hash(&SecretString::from(
            "gono-cloud-timing-equalizer".to_owned(),
        ))
        .unwrap_or_default()
    })
}

/// The value of cookie `name` in the request.
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then(|| value.trim_matches('"').to_owned())
        })
}

/// The CSRF token of forms shown to the holder of session `token`.
fn session_csrf(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gono-csrf-v1\0");
    hasher.update(token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

impl Web {
    /// Creates the page support for the public origin `base_url`, recording failed sign-ins
    /// in `limiter`.
    pub fn new(pool: db::Pool, limiter: Arc<RateLimiter>, base_url: &Url) -> Self {
        Self {
            pool,
            limiter,
            origin: base_url.origin().ascii_serialization(),
            secure: base_url.scheme() == "https",
        }
    }

    fn cookie_header(
        &self,
        name: &str,
        value: &str,
        same_site: &str,
        max_age: Option<u32>,
    ) -> HeaderValue {
        let mut cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite={same_site}");
        if self.secure {
            cookie.push_str("; Secure");
        }
        if let Some(max_age) = max_age {
            cookie.push_str(&format!("; Max-Age={max_age}"));
        }
        HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    /// The `Set-Cookie` value that stores a session token.
    pub fn session_cookie(&self, token: &SecretString) -> HeaderValue {
        self.cookie_header(SESSION_COOKIE, token.expose_secret(), "Lax", None)
    }

    /// The `Set-Cookie` value that deletes cookie `name`.
    pub fn removal_cookie(&self, name: &str) -> HeaderValue {
        self.cookie_header(
            name,
            "",
            if name == CSRF_COOKIE { "Strict" } else { "Lax" },
            Some(0),
        )
    }

    /// The signed-in account of the request and its session token, if it has a live session.
    pub async fn session(&self, headers: &HeaderMap) -> Option<(SessionUser, String)> {
        let token = cookie(headers, SESSION_COOKIE)?;
        match web_sessions::lookup(&self.pool, &token, db::unix_now()).await {
            Ok(user) => user.map(|user| (user, token)),
            Err(err) => {
                tracing::error!(error = %err, "session lookup failed");
                None
            }
        }
    }

    /// Ends the session with `token`.
    pub async fn sign_out(&self, token: &str) {
        if let Err(err) = web_sessions::delete(&self.pool, token).await {
            tracing::error!(error = %err, "cannot end a session");
        }
    }

    /// Checks a web login password and opens a session (see the module documentation).
    pub async fn sign_in(&self, client: IpAddr, username: &str, password: SecretString) -> SignIn {
        if let Some(wait) = self.limiter.check(client) {
            return SignIn::RateLimited(wait);
        }
        let account = match Username::new(username.trim()) {
            Ok(name) => match users::credentials(&self.pool, &name).await {
                Ok(account) => account,
                Err(err) => {
                    tracing::error!(error = %err, "sign-in lookup failed");
                    return SignIn::Invalid;
                }
            },
            Err(_) => None,
        };
        let phc = account
            .as_ref()
            .map_or_else(|| dummy_hash().to_owned(), |(_, hash)| hash.clone());
        let verified = tokio::task::spawn_blocking(move || password::verify(&password, &phc))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        match account {
            Some((user, _)) if verified && user.enabled => {
                match web_sessions::create(&self.pool, user.id, db::unix_now()).await {
                    Ok(token) => {
                        tracing::info!(%client, user = %user.username, "web sign-in");
                        SignIn::Ok(token)
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "cannot create a session");
                        SignIn::Invalid
                    }
                }
            }
            _ => {
                self.limiter.record_failure(client);
                tracing::info!(%client, user = %username.trim(), "rejected web sign-in");
                SignIn::Invalid
            }
        }
    }

    /// The CSRF token for a form shown before sign-in, and the `Set-Cookie` value to send
    /// with the page. An existing token is kept, so that several open pages stay valid.
    pub fn login_csrf(&self, headers: &HeaderMap) -> (String, HeaderValue) {
        let token = cookie(headers, CSRF_COOKIE)
            .filter(|token| {
                token.len() == CSRF_CHARS && token.bytes().all(|b| b.is_ascii_alphanumeric())
            })
            .unwrap_or_else(|| secret::random_token(CSRF_CHARS).expose_secret().to_owned());
        let cookie = self.cookie_header(CSRF_COOKIE, &token, "Strict", None);
        (token, cookie)
    }

    /// Whether a form submitted before sign-in carries the token of its CSRF cookie.
    pub fn check_login_csrf(&self, headers: &HeaderMap, submitted: &str) -> bool {
        cookie(headers, CSRF_COOKIE).is_some_and(|expected| {
            !expected.is_empty()
                && secret::constant_time_eq(expected.as_bytes(), submitted.as_bytes())
        })
    }

    /// The CSRF token for forms shown to the holder of session `token`.
    pub fn session_csrf(&self, token: &str) -> String {
        session_csrf(token)
    }

    /// Whether a form submitted with session `token` carries that session's CSRF token.
    pub fn check_session_csrf(&self, token: &str, submitted: &str) -> bool {
        secret::constant_time_eq(session_csrf(token).as_bytes(), submitted.as_bytes())
    }

    /// Whether a form submission comes from this origin as far as the browser says: an
    /// `Origin` header must name the public origin, and `Sec-Fetch-Site` must not be
    /// `cross-site` or `same-site`. Requests without these headers (non-browser clients)
    /// rely on the CSRF token alone.
    pub fn same_origin(&self, headers: &HeaderMap) -> bool {
        same_origin(&self.origin, headers)
    }
}

/// See [`Web::same_origin`]; `origin` is `scheme://host[:port]`.
fn same_origin(origin: &str, headers: &HeaderMap) -> bool {
    let origin_ok = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value == origin);
    let fetch_ok = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|site| matches!(site, "same-origin" | "none"));
    origin_ok && fetch_ok
}

/// Escapes text for HTML element content and attribute values.
pub fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// The stylesheet of every page. The CSP allows exactly this text (by hash).
const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#f4f5f7;--card:#fff;--text:#1d2125;--muted:#5c6670;\
--line:#d5d9de;--accent:#2457c5;--accent-text:#fff;--error:#b42318}\
@media (prefers-color-scheme:dark){:root{--bg:#16181b;--card:#202327;--text:#e8eaed;\
--muted:#a3aab2;--line:#3a3f45;--accent:#7aa2ff;--accent-text:#0d1117;--error:#ff8a80}}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
padding:16px;background:var(--bg);color:var(--text);\
font:16px/1.5 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif}\
main{width:100%;max-width:26rem;background:var(--card);border:1px solid var(--line);\
border-radius:12px;padding:28px}\
.product{margin:0 0 4px;color:var(--muted);font-size:.875rem;letter-spacing:.02em}\
h1{margin:0 0 16px;font-size:1.375rem;line-height:1.3}\
p{margin:0 0 12px}.muted{color:var(--muted);font-size:.9375rem}\
.error{color:var(--error);font-weight:600}\
label{display:block;margin:0 0 12px;font-weight:600;font-size:.9375rem}\
input[type=text],input[type=password]{display:block;width:100%;margin-top:4px;padding:10px 12px;\
border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit}\
form{margin:0}.actions{display:flex;gap:8px;margin-top:20px;flex-wrap:wrap}\
button{flex:1;min-width:8rem;padding:10px 16px;border-radius:8px;border:1px solid var(--accent);\
background:var(--accent);color:var(--accent-text);font:inherit;font-weight:600;cursor:pointer}\
button.secondary{background:transparent;color:var(--text);border-color:var(--line)}\
button.link{flex:none;min-width:0;padding:0;border:0;background:none;color:var(--accent);\
font-weight:400;text-decoration:underline}\
.client{font-weight:700;overflow-wrap:anywhere}";

/// The `Content-Security-Policy` of every page.
fn content_security_policy() -> &'static str {
    static POLICY: OnceLock<String> = OnceLock::new();
    POLICY.get_or_init(|| {
        let hash = STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
        format!(
            "default-src 'none'; style-src 'sha256-{hash}'; img-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
    })
}

/// Adds the security headers of an HTML page (see the module documentation).
pub fn secure_headers(headers: &mut HeaderMap) {
    let set = |headers: &mut HeaderMap, name: &'static str, value: &str| {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    };
    set(
        headers,
        "content-security-policy",
        content_security_policy(),
    );
    set(headers, "x-frame-options", "DENY");
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "cache-control", "no-store");
}

/// An HTML page: `body` (trusted HTML) inside the common layout, with the security headers.
pub fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n<title>{title} – {product}</title>\n\
         <style>{STYLE}</style>\n</head>\n<body>\n<main>\n<p class=\"product\">{product}</p>\n\
         {body}\n</main>\n</body>\n</html>\n",
        title = escape(title),
        product = escape(PRODUCT_NAME),
    );
    let mut response = (status, html).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    secure_headers(response.headers_mut());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_are_parsed_by_name() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, "a=1; gono_session=abc".parse().unwrap());
        headers.append(header::COOKIE, "gono_csrf=\"xyz\"".parse().unwrap());
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("abc"));
        assert_eq!(cookie(&headers, CSRF_COOKIE).as_deref(), Some("xyz"));
        assert_eq!(cookie(&headers, "b"), None);
    }

    #[test]
    fn session_csrf_tokens_are_bound_to_the_session() {
        assert_eq!(session_csrf("a"), session_csrf("a"));
        assert_ne!(session_csrf("a"), session_csrf("b"));
        assert_eq!(
            session_csrf("a").len(),
            43,
            "SHA-256, base64url without padding"
        );
    }

    #[test]
    fn pages_carry_the_security_headers() {
        let response = page(StatusCode::OK, "T<", "<p>x</p>");
        let headers = response.headers();
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(
            headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert_eq!(escape("<a href='x'>&"), "&lt;a href=&#39;x&#39;&gt;&amp;");
    }

    #[test]
    fn origin_checks() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.insert(*name, HeaderValue::from_static(value));
            }
            map
        };
        let origin = "https://cloud.example.com";
        assert!(same_origin(origin, &headers(&[])));
        assert!(same_origin(
            origin,
            &headers(&[("origin", origin), ("sec-fetch-site", "same-origin")])
        ));
        assert!(!same_origin(
            origin,
            &headers(&[("origin", "https://evil.example")])
        ));
        assert!(!same_origin(
            origin,
            &headers(&[("sec-fetch-site", "cross-site")])
        ));
        assert!(!same_origin(
            origin,
            &headers(&[("sec-fetch-site", "same-site")])
        ));
    }
}
