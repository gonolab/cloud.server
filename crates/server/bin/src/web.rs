//! Building blocks of the server's HTML pages: the web file UI, the sign-in and account pages,
//! the Login Flow v2 pages and the web admin UI.
//!
//! - **Pages** are askama templates (`crates/server/bin/templates/`) with a [`Chrome`] (the
//!   masthead, the language of [`crate::i18n`] and the theme), rendered with [`render`]. Every
//!   value is HTML-escaped by the template engine. Every page loads the same stylesheet
//!   (`assets/web.css`) and script (`assets/app.js`) from [`ASSETS_PATH`] under
//!   content-hashed names. The script only enhances: every page works without it.
//! - **Theme**: system, light or dark, kept in the [`THEME_COOKIE`] and switched by a form, so
//!   that it needs no script either.
//! - **Sign-in** ([`Web::sign_in`]) with the web login password (Argon2), behind a per-client
//!   [`RateLimiter`] of its own: checked before anything is verified, one token per failure.
//!   It is not shared with device authentication, so failing devices behind the same address
//!   do not keep a user from signing a new device in. Unknown accounts cost the same Argon2
//!   work as known ones, so response times do not reveal which accounts exist.
//! - **Sessions**: a successful sign-in creates a `web_sessions` row
//!   ([`gono_server_core::web_sessions`]) and sets the [`SESSION_COOKIE`] (`HttpOnly`,
//!   `SameSite=Lax`, `Secure` when the public origin is HTTPS). App passwords never create a
//!   session, and sessions never authenticate WebDAV requests.
//! - **CSRF**: every form carries a token. Before sign-in it is a double-submit token: a random
//!   value in the [`CSRF_COOKIE`] (`SameSite=Strict`) repeated in the form. After sign-in it
//!   is derived from the session token, which the page cannot read; the script sends it in a
//!   header. POSTs with an `Origin` or `Sec-Fetch-Site` header that names another site are
//!   refused as well.
//! - **Headers** ([`render`]): a strict Content Security Policy (the one script only, by a
//!   nonce of this response; stylesheets, images and media from this origin; no inline styles;
//!   requests and forms only to this origin; no framing), `X-Frame-Options: DENY`,
//!   `Referrer-Policy: same-origin` (page URLs can carry tokens, so no other site ever sees
//!   them; `no-referrer` would also make browsers send `Origin: null` with our own forms),
//!   `Cache-Control: no-store`.

use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use askama::Template;
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use gono_server_core::{
    Username, db, password, secret,
    users::{self, User},
    web_sessions::{self, SessionUser},
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    i18n::{Lang, Text, fill},
    ratelimit::RateLimiter,
};

/// Cookie holding the session token.
pub const SESSION_COOKIE: &str = "gono_session";

/// Cookie holding the double-submit CSRF token of forms shown before sign-in.
pub const CSRF_COOKIE: &str = "gono_csrf";

/// Length of the pre-sign-in CSRF token.
const CSRF_CHARS: usize = 43;

/// Outcome of [`Web::verify_password`].
#[derive(Debug)]
pub enum Verified {
    /// The password is right and the account is enabled.
    Ok(User),
    /// Unknown account, wrong password or disabled account.
    Invalid,
    /// Too many failures from this client; retry after the given time.
    RateLimited(Duration),
    /// The password could not be checked because the database failed.
    Unavailable,
}

/// Outcome of [`Web::sign_in`].
#[derive(Debug)]
pub enum SignIn {
    /// The password is right: the cookie token of a new session.
    Ok(SecretString),
    /// Unknown account, wrong password or disabled account.
    Invalid,
    /// Too many failures from this client; retry after the given time.
    RateLimited(Duration),
    /// The password could not be checked or the session not stored: the database failed.
    Unavailable,
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

    /// The `Set-Cookie` value that stores `theme` for a year (or forgets the choice).
    pub fn theme_cookie(&self, theme: Theme) -> HeaderValue {
        match theme.attr() {
            Some(name) => self.cookie_header(THEME_COOKIE, name, "Lax", Some(365 * 86_400)),
            None => self.cookie_header(THEME_COOKIE, "", "Lax", Some(0)),
        }
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

    /// Checks a web login password (see the module documentation) without opening a session.
    pub async fn verify_password(
        &self,
        client: IpAddr,
        username: &str,
        password: SecretString,
    ) -> Verified {
        if let Some(wait) = self.limiter.check(client) {
            return Verified::RateLimited(wait);
        }
        let account = match Username::new(username.trim()) {
            Ok(name) => match users::credentials(&self.pool, &name).await {
                Ok(account) => account,
                Err(err) => {
                    tracing::error!(error = %err, "sign-in lookup failed");
                    return Verified::Unavailable;
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
            Some((user, _)) if verified && user.enabled => Verified::Ok(user),
            _ => {
                self.limiter.record_failure(client);
                tracing::info!(%client, user = %username.trim(), "rejected web sign-in");
                Verified::Invalid
            }
        }
    }

    /// Opens a session for an account whose password was verified; returns the cookie token.
    pub async fn open_session(&self, client: IpAddr, user: &User) -> Option<SecretString> {
        match web_sessions::create(&self.pool, user.id, db::unix_now()).await {
            Ok(token) => {
                tracing::info!(%client, user = %user.username, "web sign-in");
                Some(token)
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot create a session");
                None
            }
        }
    }

    /// Checks a web login password and opens a session (see the module documentation).
    pub async fn sign_in(&self, client: IpAddr, username: &str, password: SecretString) -> SignIn {
        match self.verify_password(client, username, password).await {
            Verified::Ok(user) => match self.open_session(client, &user).await {
                Some(token) => SignIn::Ok(token),
                None => SignIn::Unavailable,
            },
            Verified::Invalid => SignIn::Invalid,
            Verified::RateLimited(wait) => SignIn::RateLimited(wait),
            Verified::Unavailable => SignIn::Unavailable,
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
///
/// Browsers send `Origin: null` instead of the origin when the page's referrer policy or a
/// privacy setting hides it; that is accepted only together with `Sec-Fetch-Site:
/// same-origin`, which pages cannot forge.
fn same_origin(origin: &str, headers: &HeaderMap) -> bool {
    let fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok());
    let origin_ok = match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        None => true,
        Some("null") => fetch_site == Some("same-origin"),
        Some(value) => value == origin,
    };
    let fetch_ok = fetch_site.is_none_or(|site| matches!(site, "same-origin" | "none"));
    origin_ok && fetch_ok
}

/// The stylesheet of every page.
pub const STYLE: &str = include_str!("../assets/web.css");

/// The script of every page. It only enhances them (theme switch without a reload, drag and
/// drop, resumable uploads): every page works without it.
pub const SCRIPT: &str = include_str!("../assets/app.js");

/// The icon of every page (SVG).
pub const ICON: &str = include_str!("../assets/icon.svg");

/// Path prefix of the static assets. Their names carry a hash of their content, so they can
/// be cached forever.
pub const ASSETS_PATH: &str = "/apps/assets/";

/// The cookie holding the chosen theme (`light` or `dark`; absent: follow the system).
pub const THEME_COOKIE: &str = "gono_theme";

/// Where the theme switch posts to.
pub const THEME_PATH: &str = "/apps/theme";

/// The URLs of the stylesheet and the script.
struct AssetUrls {
    style: String,
    script: String,
    icon: String,
}

fn asset_urls() -> &'static AssetUrls {
    static URLS: OnceLock<AssetUrls> = OnceLock::new();
    URLS.get_or_init(|| {
        let short = |text: &str| {
            let digest = Sha256::digest(text.as_bytes());
            digest[..6]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        AssetUrls {
            style: format!("{ASSETS_PATH}web.{}.css", short(STYLE)),
            script: format!("{ASSETS_PATH}app.{}.js", short(SCRIPT)),
            icon: format!("{ASSETS_PATH}icon.{}.svg", short(ICON)),
        }
    })
}

/// The URL of the stylesheet.
pub fn style_url() -> &'static str {
    &asset_urls().style
}

/// The URL of the script.
pub fn script_url() -> &'static str {
    &asset_urls().script
}

/// The URL of the page icon.
pub fn icon_url() -> &'static str {
    &asset_urls().icon
}

/// The asset at `path` with its content type, if there is one.
pub fn asset(path: &str) -> Option<(&'static str, &'static str)> {
    let urls = asset_urls();
    if path == urls.style {
        Some(("text/css; charset=utf-8", STYLE))
    } else if path == urls.script {
        Some(("text/javascript; charset=utf-8", SCRIPT))
    } else if path == urls.icon || path == format!("{ASSETS_PATH}icon.svg") {
        Some(("image/svg+xml", ICON))
    } else {
        None
    }
}

/// The colour theme a page is shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    /// Follow the system setting (`prefers-color-scheme`).
    #[default]
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl Theme {
    /// The theme chosen in this browser ([`THEME_COOKIE`]).
    pub fn from_headers(headers: &HeaderMap) -> Self {
        match cookie(headers, THEME_COOKIE).as_deref() {
            Some("light") => Self::Light,
            Some("dark") => Self::Dark,
            _ => Self::System,
        }
    }

    /// The `data-theme` attribute of the page; none follows the system.
    pub fn attr(self) -> Option<&'static str> {
        match self {
            Self::System => None,
            Self::Light => Some("light"),
            Self::Dark => Some("dark"),
        }
    }

    /// The theme after this one in the switch's cycle: system, light, dark.
    pub fn next(self) -> Self {
        match self {
            Self::System => Self::Light,
            Self::Light => Self::Dark,
            Self::Dark => Self::System,
        }
    }

    /// The name stored in the cookie and reported to the script.
    pub fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

/// The signed-in account as the masthead shows it.
#[derive(Debug, Clone)]
pub struct ChromeUser {
    /// Login name.
    pub username: String,
    /// Display name.
    pub display_name: String,
    /// One or two letters for the avatar.
    pub initials: String,
}

impl ChromeUser {
    /// The masthead's view of a session.
    pub fn new(user: &SessionUser) -> Self {
        let initials: String = user
            .display_name
            .split_whitespace()
            .filter_map(|word| word.chars().next())
            .take(2)
            .collect();
        Self {
            username: user.username.to_string(),
            display_name: user.display_name.clone(),
            initials: if initials.is_empty() {
                user.username.as_str().chars().take(1).collect()
            } else {
                initials
            },
        }
    }
}

/// The masthead entry of the current page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nav {
    /// None of them.
    #[default]
    None,
    /// The file browser.
    Files,
    /// The favorites.
    Favorites,
    /// The account page.
    Account,
    /// The admin UI.
    Admin,
}

/// What every page shows around its content (the masthead), and what it needs for the
/// response: the language, the theme and the CSP nonce of the response.
#[derive(Debug, Clone)]
pub struct Chrome {
    /// Language of the page.
    pub lang: Lang,
    /// The strings in that language.
    pub t: &'static Text,
    /// The `data-theme` attribute, if the browser chose a theme.
    pub theme: Option<&'static str>,
    /// The theme switch's label for the current theme.
    pub theme_label: &'static str,
    /// Nonce of this response's `script-src`.
    pub nonce: String,
    /// URL of the stylesheet.
    pub style: &'static str,
    /// URL of the script.
    pub script: &'static str,
    /// URL of the page icon.
    pub icon: &'static str,
    /// The signed-in account, if any.
    pub user: Option<ChromeUser>,
    /// CSRF token of the session (empty without one), for the forms in the masthead and for
    /// the script's requests.
    pub csrf: String,
    /// The current masthead entry.
    pub nav: Nav,
    /// The web file UI is enabled.
    pub files: bool,
    /// The admin UI's path, when it is enabled and the user is an admin.
    pub admin: Option<String>,
    /// Where the sign-out form posts.
    pub logout: String,
    /// Path and query of the page, where the theme switch returns to.
    pub here: String,
    /// The text in the search box.
    pub query: String,
    /// Strings for the script (JSON, safe inside a `<script type="application/json">`).
    pub script_text: String,
}

impl Chrome {
    /// The frame of a page for an anonymous visitor in `lang`, with the theme of `headers`.
    pub fn new(headers: &HeaderMap, lang: Lang) -> Self {
        let theme = Theme::from_headers(headers);
        let t = lang.t();
        Self {
            lang,
            t,
            theme: theme.attr(),
            theme_label: match theme {
                Theme::System => t.theme_system,
                Theme::Light => t.theme_light,
                Theme::Dark => t.theme_dark,
            },
            nonce: secret::random_token(22).expose_secret().to_owned(),
            style: style_url(),
            script: script_url(),
            icon: icon_url(),
            user: None,
            csrf: String::new(),
            nav: Nav::None,
            files: false,
            admin: None,
            logout: String::new(),
            here: "/".to_owned(),
            query: String::new(),
            script_text: script_text(t),
        }
    }

    /// The frame of a page for an anonymous visitor, in the browser's language.
    pub fn for_request(headers: &HeaderMap) -> Self {
        Self::new(headers, Lang::from_headers(headers))
    }

    /// The same frame for the signed-in `user`, whose session has the CSRF token `csrf`.
    #[must_use]
    pub fn signed_in(mut self, user: &SessionUser, csrf: &str) -> Self {
        self.user = Some(ChromeUser::new(user));
        self.csrf = csrf.to_owned();
        self
    }

    /// Whether masthead entry `index` is the current one (for the templates, which cannot
    /// name [`Nav`]): 1 files, 2 favorites, 3 account, 4 admin.
    pub fn on(&self, index: u8) -> bool {
        let nav = match index {
            1 => Nav::Files,
            2 => Nav::Favorites,
            3 => Nav::Account,
            4 => Nav::Admin,
            _ => return false,
        };
        self.nav == nav
    }

    /// Where the brand links to.
    pub fn home(&self) -> &str {
        if self.files {
            "/apps/files/"
        } else if let Some(admin) = &self.admin {
            admin
        } else {
            "/"
        }
    }
}

/// The strings the script shows, as JSON that can be embedded in a page.
fn script_text(t: &Text) -> String {
    let value = serde_json::json!({
        "uploads": t.js_uploads,
        "waiting": t.js_waiting,
        "uploading": t.js_uploading,
        "finishing": t.js_finishing,
        "done": t.js_done,
        "replaced": t.js_replaced,
        "skipped": t.js_skipped,
        "failed": t.js_failed,
        "retrying": t.js_retrying,
        "cancelled": t.js_cancelled,
        "retry": t.js_retry,
        "cancelAll": t.js_cancel_all,
        "close": t.js_close,
        "conflict": t.js_conflict,
        "leave": t.js_leave,
        "left": t.js_left,
        "dropHere": t.drop_here,
        "selected": t.selected,
        "today": t.today,
        "yesterday": t.yesterday,
        "themeSystem": t.theme_system,
        "themeLight": t.theme_light,
        "themeDark": t.theme_dark,
    });
    embed_json(&value)
}

/// `value` as JSON text that cannot end a `<script>` element or open a comment.
pub fn embed_json(value: &serde_json::Value) -> String {
    value
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// A page template with its frame.
pub trait Page: Template {
    /// The frame of the page.
    fn chrome(&self) -> &Chrome;
}

/// Implements [`Page`] for templates with a `chrome` field.
macro_rules! page {
    ($($ty:ty),+ $(,)?) => {
        $(impl $crate::web::Page for $ty {
            fn chrome(&self) -> &$crate::web::Chrome {
                &self.chrome
            }
        })+
    };
}
pub(crate) use page;

/// The `Content-Security-Policy` of a page whose script carries `nonce`: the page's own
/// stylesheet and script, images and media from this origin (previews), requests and forms
/// to this origin only, and no framing.
fn page_policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'self'; img-src 'self'; \
         media-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; \
         base-uri 'none'; object-src 'none'"
    )
}

/// The `Content-Security-Policy` of responses without a page (redirects).
const BARE_POLICY: &str =
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Adds the security headers of a response without a page body (see the module
/// documentation).
pub fn secure_headers(headers: &mut HeaderMap) {
    add_security_headers(headers, BARE_POLICY);
}

fn add_security_headers(headers: &mut HeaderMap, policy: &str) {
    let set = |headers: &mut HeaderMap, name: &'static str, value: &str| {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    };
    set(headers, "content-security-policy", policy);
    set(headers, "x-frame-options", "DENY");
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "referrer-policy", "same-origin");
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cache-control", "no-store");
}

/// Renders a page with the security headers and its nonce in the CSP.
pub fn render(status: StatusCode, page: &impl Page) -> Response {
    let html = match page.render() {
        Ok(html) => html,
        Err(err) => {
            tracing::error!(error = %err, "cannot render a page");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut response = (status, html).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    add_security_headers(response.headers_mut(), &page_policy(&page.chrome().nonce));
    response
}

/// `303 See Other` to `location` (a path on this server), with the security headers and
/// extra `Set-Cookie` values.
pub fn see_other(location: &str, cookies: &[HeaderValue]) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    for cookie in cookies {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    secure_headers(response.headers_mut());
    response
}

/// The page shown while a client is blocked by the failed-attempt limiter, with
/// `Retry-After`.
pub fn too_many_attempts(chrome: Chrome, wait: Duration) -> Response {
    let t = chrome.t;
    let seconds = wait.as_secs().max(1).to_string();
    let mut response = Message::new(
        chrome,
        t.too_many_attempts,
        t.too_many_attempts,
        &fill(t.too_many_attempts_lead, &[&seconds]),
    )
    .respond(StatusCode::TOO_MANY_REQUESTS);
    if let Ok(value) = HeaderValue::from_str(&seconds) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The page shown when a password could not be checked because the database failed: `503`
/// with `Retry-After`, so that it does not read as a wrong password.
pub fn unavailable(chrome: Chrome) -> Response {
    let t = chrome.t;
    let mut response = Message::new(chrome, t.unavailable, t.unavailable, t.unavailable_lead)
        .respond(StatusCode::SERVICE_UNAVAILABLE);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

/// A page with a heading and a short text (`templates/message.html`).
#[derive(Debug, Clone, Template)]
#[template(path = "message.html")]
pub struct Message {
    /// The frame.
    pub chrome: Chrome,
    /// Window title.
    pub title: String,
    /// Heading.
    pub heading: String,
    /// A client (device) name shown before `lead`.
    pub client: Option<String>,
    /// The text.
    pub lead: String,
    /// A second, smaller text.
    pub note: Option<String>,
    /// A button: link target and label.
    pub link: Option<(String, String)>,
}

page!(Message);

impl Message {
    /// A message page with a heading and a text.
    pub fn new(chrome: Chrome, title: &str, heading: &str, lead: &str) -> Self {
        Self {
            chrome,
            title: title.to_owned(),
            heading: heading.to_owned(),
            client: None,
            lead: lead.to_owned(),
            note: None,
            link: None,
        }
    }

    /// Renders the page with `status`.
    pub fn respond(&self, status: StatusCode) -> Response {
        render(status, self)
    }
}

/// The ids of every `id="..."` attribute in `html`, for tests that check uniqueness.
#[cfg(test)]
pub fn element_ids(html: &str) -> Vec<String> {
    html.match_indices(" id=\"")
        .filter_map(|(index, needle)| {
            let rest = &html[index + needle.len()..];
            rest.find('"').map(|end| rest[..end].to_owned())
        })
        .collect()
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

    fn plain() -> Chrome {
        Chrome::new(&HeaderMap::new(), Lang::En)
    }

    #[test]
    fn pages_carry_the_security_headers() {
        let message = Message::new(plain(), "T<", "<b>", "x");
        let nonce = message.chrome.nonce.clone();
        let response = message.respond(StatusCode::OK);
        let headers = response.headers();
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(
            csp.contains(&format!("script-src 'nonce-{nonce}'")),
            "{csp}"
        );
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "same-origin");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(
            headers["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        // Every response gets a nonce of its own.
        assert_ne!(plain().nonce, plain().nonce);
    }

    #[tokio::test]
    async fn templates_escape_values_and_link_the_hashed_assets() {
        let mut message = Message::new(plain(), "T", "<script>alert(1)</script>", "a & b");
        message.client = Some("\"evil\" <img>".into());
        let html = message.render().unwrap();
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(html.contains("&#60;script&#62;"), "{html}");
        assert!(!html.contains("\"evil\""), "{html}");
        assert!(!html.contains("<img>"), "{html}");
        assert!(
            html.contains(&format!("href=\"{}\"", style_url())),
            "{html}"
        );
        assert!(
            html.contains(&format!(
                "src=\"{}\" nonce=\"{}\"",
                script_url(),
                message.chrome.nonce
            )),
            "{html}"
        );
        assert!(
            !html.contains(" style=\""),
            "no inline styles: the CSP refuses them"
        );
        assert_eq!(asset(style_url()), Some(("text/css; charset=utf-8", STYLE)));
        assert!(asset(script_url()).is_some());
        assert!(
            asset("/apps/assets/web.css").is_none(),
            "only the hashed names"
        );
    }

    #[test]
    fn the_script_text_cannot_end_its_element() {
        let json = embed_json(&serde_json::json!({ "x": "</script><!--&" }));
        assert!(
            !json.contains('<') && !json.contains('>') && !json.contains('&'),
            "{json}"
        );
        assert!(
            !SCRIPT.contains("innerHTML"),
            "the script builds DOM nodes only"
        );
        assert!(!SCRIPT.contains("eval("), "the script never evaluates text");
    }

    #[test]
    fn themes_cycle_through_system_light_and_dark() {
        let mut headers = HeaderMap::new();
        assert_eq!(Theme::from_headers(&headers), Theme::System);
        headers.insert(header::COOKIE, HeaderValue::from_static("gono_theme=dark"));
        assert_eq!(Theme::from_headers(&headers), Theme::Dark);
        assert_eq!(Theme::Dark.next(), Theme::System);
        assert_eq!(Theme::System.next().next(), Theme::Dark);
        headers.insert(header::COOKIE, HeaderValue::from_static("gono_theme=\"><x"));
        assert_eq!(
            Theme::from_headers(&headers),
            Theme::System,
            "unknown values: system"
        );
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
        // A hidden origin counts only with the browser's own same-origin statement.
        assert!(same_origin(
            origin,
            &headers(&[("origin", "null"), ("sec-fetch-site", "same-origin")])
        ));
        assert!(!same_origin(origin, &headers(&[("origin", "null")])));
        assert!(!same_origin(
            origin,
            &headers(&[("origin", "null"), ("sec-fetch-site", "cross-site")])
        ));
    }
}
