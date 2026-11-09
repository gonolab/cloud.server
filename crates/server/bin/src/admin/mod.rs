//! The web admin UI, served under `admin.path` (default `/gono-admin`) when `admin.enabled`.
//!
//! | Request | Page or action |
//! |---|---|
//! | `GET  <p>/login`, `POST <p>/login` | Sign in with the web login password (admins only). |
//! | `POST <p>/logout` | Sign out. |
//! | `GET  <p>/` | Overview of this server. |
//! | `GET  <p>/users` | All accounts. |
//! | `GET  <p>/new-user`, `POST <p>/users` | Create an account. |
//! | `GET  <p>/users/<name>` | One account with its app passwords. |
//! | `POST <p>/users/<name>/enable`, `.../disable` | Enable or disable the account. |
//! | `POST <p>/users/<name>/promote`, `.../demote` | Grant or withdraw admin access. |
//! | `POST <p>/users/<name>/display-name` | Change the display name. |
//! | `POST <p>/users/<name>/password` | Set the web login password. |
//! | `GET  <p>/users/<name>/delete`, `POST` the same | Confirm and delete the account. |
//! | `POST <p>/users/<name>/app-passwords` | Create an app password, then show it once at `<p>/created`. |
//! | `POST <p>/users/<name>/app-passwords/<id>/delete` | Revoke an app password. |
//!
//! # Security
//!
//! - **Sign-in** uses the web login password through [`Web::verify_password`] (Argon2, the
//!   shared failed-attempt limiter) and only accounts with the admin flag get a session. App
//!   passwords are never looked at, whether sent as Basic credentials or typed into the form.
//! - **Every page** needs a live session of an enabled admin (checked on each request, so a
//!   demoted or disabled admin is locked out at once). Pages carry the headers of
//!   [`crate::web`]: a strict CSP without scripts, `X-Frame-Options: DENY`, `no-store`.
//! - **Every change** is a POST with the session's CSRF token and a same-origin check, and is
//!   answered with a redirect (Post/Redirect/Get), so reloading a page never repeats it. Errors
//!   show the form again without changing anything.
//! - **New app passwords** are kept in memory, bound to the session that created them, and
//!   shown exactly once at `<p>/created` (`Cache-Control: no-store`); the URL carries no
//!   secret, so nothing sensitive reaches logs or history.
//! - **The last enabled admin** cannot be disabled, demoted or deleted
//!   ([`users::set_enabled`], [`users::set_admin`] and [`users::delete`] check it in the same
//!   transaction), and an admin cannot disable, demote or delete the account they are signed in
//!   with.

mod pages;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Form, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gono_server_core::{
    Error as CoreError, Permission, RelPath, Username,
    app_passwords::{self, Scope},
    db, password, stats,
    users::{self, NewUser, User},
    web_sessions::{self, SessionUser},
};
use gono_server_nextcloud::{
    notify_push::{Endpoints, PushSettings},
    status,
};
use ipnet::IpNet;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use self::pages::{
    AppPasswordForm, AppPasswordRow, CreatedPage, DeletePage, Fact, Feature, Frame, LoginPage,
    MOUNT_ROWS, MessagePage, MountInput, NewUserPage, NotAdminPage, OverviewPage, ScopeChip,
    UserPage, UserRow, UserView, UsersPage,
};
use crate::{
    app::AppState,
    client_ip::client_ip,
    web::{self, CSRF_COOKIE, SESSION_COOKIE, Verified},
};

/// How long a new app password waits to be shown.
const CREATED_TTL: Duration = Duration::from_secs(10 * 60);

/// New app passwords waiting to be shown, at most.
const MAX_CREATED: usize = 1000;

/// Facts about the running server shown on the overview, collected at startup.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// Start of the process, UNIX seconds.
    pub started_at: i64,
    /// The instance id (`oc:id` suffix).
    pub instance_id: String,
    /// `server.bind`.
    pub bind: SocketAddr,
    /// `server.trusted_proxies`.
    pub trusted_proxies: Vec<IpNet>,
    /// The configuration file.
    pub config_path: PathBuf,
    /// Log level and destination.
    pub log: String,
    /// `storage.data_dir`.
    pub data_dir: PathBuf,
    /// `db.path`.
    pub db_path: PathBuf,
    /// Whether the data directory ignores case (`None`: could not be determined).
    pub case_insensitive: Option<bool>,
    /// `webdav.max_lock_timeout_secs`.
    pub lock_timeout_secs: u64,
    /// The notify_push settings, when enabled.
    pub push: Option<PushSettings>,
    /// Configuration warnings to show.
    pub warnings: Vec<String>,
}

/// A new app password waiting to be shown once.
#[derive(Debug)]
struct Created {
    username: String,
    label: String,
    token: SecretString,
    scopes: Vec<Scope>,
    expires_at: Option<i64>,
    until: Instant,
}

/// The admin UI's state.
#[derive(Debug)]
pub struct Admin {
    /// `admin.path`.
    prefix: String,
    info: ServerInfo,
    /// New app passwords by the id of the session that created them.
    created: Mutex<HashMap<i64, Created>>,
}

impl Admin {
    /// The admin UI under `prefix`.
    pub fn new(prefix: &str, info: ServerInfo) -> Self {
        Self {
            prefix: prefix.trim_end_matches('/').to_owned(),
            info,
            created: Mutex::new(HashMap::new()),
        }
    }

    /// The admin path.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.prefix)
    }

    fn user_url(&self, username: &str) -> String {
        format!("{}/users/{username}", self.prefix)
    }

    fn frame(&self, session: &Session, on_overview: bool, on_users: bool) -> Frame {
        Frame {
            prefix: self.prefix.clone(),
            on_overview,
            on_users,
            username: session.user.username.to_string(),
            csrf: session.csrf.clone(),
            version: env!("CARGO_PKG_VERSION"),
            nextcloud: status::version_string(),
            instance_id: self.info.instance_id.clone(),
        }
    }

    fn remember(&self, session_id: i64, created: Created) {
        let now = Instant::now();
        let mut waiting = self
            .created
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        waiting.retain(|_, entry| entry.until > now);
        if waiting.len() >= MAX_CREATED {
            waiting.clear();
        }
        waiting.insert(session_id, created);
    }

    fn take(&self, session_id: i64) -> Option<Created> {
        self.created
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session_id)
            .filter(|entry| entry.until > Instant::now())
    }
}

/// The routes of the admin UI under its prefix.
pub fn routes(prefix: &str) -> Router<AppState> {
    let p = prefix.trim_end_matches('/');
    Router::new()
        .route(p, get(to_root))
        .route(&format!("{p}/"), get(overview))
        .route(&format!("{p}/login"), get(login_page).post(login))
        .route(&format!("{p}/logout"), post(logout))
        .route(&format!("{p}/users"), get(users_page).post(create_user))
        .route(&format!("{p}/new-user"), get(new_user_page))
        .route(&format!("{p}/users/{{name}}"), get(user_page))
        .route(&format!("{p}/users/{{name}}/enable"), post(enable))
        .route(&format!("{p}/users/{{name}}/disable"), post(disable))
        .route(&format!("{p}/users/{{name}}/promote"), post(promote))
        .route(&format!("{p}/users/{{name}}/demote"), post(demote))
        .route(
            &format!("{p}/users/{{name}}/display-name"),
            post(set_display_name),
        )
        .route(&format!("{p}/users/{{name}}/password"), post(set_password))
        .route(
            &format!("{p}/users/{{name}}/delete"),
            get(delete_page).post(delete_user),
        )
        .route(
            &format!("{p}/users/{{name}}/app-passwords"),
            post(create_app_password),
        )
        .route(
            &format!("{p}/users/{{name}}/app-passwords/{{id}}/delete"),
            post(revoke_app_password),
        )
        .route(&format!("{p}/created"), get(created_page))
}

// ---------------------------------------------------------------------------------------------
// Sessions, CSRF and responses
// ---------------------------------------------------------------------------------------------

/// A signed-in admin.
struct Session {
    user: SessionUser,
    token: String,
    csrf: String,
}

/// The response a guard sends instead of the page (boxed: a `Response` is large).
type Halt = Box<Response>;

fn admin(state: &AppState) -> Result<Arc<Admin>, Halt> {
    state
        .admin
        .clone()
        .ok_or_else(|| Box::new(StatusCode::NOT_FOUND.into_response()))
}

/// `303 See Other` to `location`, with the page headers.
fn see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    web::secure_headers(response.headers_mut());
    response
}

/// The signed-in admin of the request, or the response to send instead: the sign-in page
/// for anonymous requests, a refusal for accounts without the admin flag.
async fn session(state: &AppState, admin: &Admin, headers: &HeaderMap) -> Result<Session, Halt> {
    let Some((user, token)) = state.web.session(headers).await else {
        return Err(Box::new(see_other(&admin.url("/login"))));
    };
    let csrf = state.web.session_csrf(&token);
    if !user.is_admin {
        let page = NotAdminPage {
            prefix: admin.prefix(),
            csrf: &csrf,
            username: user.username.as_str(),
        };
        return Err(Box::new(web::render(StatusCode::FORBIDDEN, &page)));
    }
    Ok(Session { user, token, csrf })
}

/// Like [`session`], for form submissions: also checks the origin and the CSRF token.
async fn form_session(
    state: &AppState,
    admin: &Admin,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<Session, Halt> {
    if !state.web.same_origin(headers) {
        return Err(Box::new(blocked("This form was sent from another site.")));
    }
    let session = session(state, admin, headers).await?;
    if !state.web.check_session_csrf(&session.token, csrf) {
        return Err(Box::new(blocked(
            "The form has expired. Go back, reload the page and try again.",
        )));
    }
    Ok(session)
}

fn blocked(lead: &str) -> Response {
    web::Message::new("Request blocked", "Request blocked", lead).respond(StatusCode::FORBIDDEN)
}

fn internal_error(err: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %err, "admin request failed");
    web::Message::new(
        "Error",
        "Something went wrong",
        "The server could not complete the request. The details are in the server log.",
    )
    .respond(StatusCode::INTERNAL_SERVER_ERROR)
}

/// The account named in the URL, or a "not found" page.
async fn find_user(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    name: &str,
) -> Result<User, Halt> {
    let found = match Username::new(name) {
        Ok(username) => users::find(&state.db, &username)
            .await
            .map_err(|err| Box::new(internal_error(&err)))?,
        Err(_) => None,
    };
    found.ok_or_else(|| {
        let page = MessagePage {
            frame: admin.frame(session, false, true),
            heading: "No such user".to_owned(),
            lead: format!("There is no account named {name}."),
            link_href: admin.url("/users"),
            link_label: "All users".to_owned(),
        };
        Box::new(web::render(StatusCode::NOT_FOUND, &page))
    })
}

/// The form field every POST carries.
#[derive(Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `?done=<what>` after a redirect.
#[derive(Deserialize)]
struct Done {
    done: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------------------------

async fn to_root(State(state): State<AppState>) -> Response {
    match admin(&state) {
        Ok(admin) => see_other(&admin.url("/")),
        Err(halt) => *halt,
    }
}

fn login_form(
    state: &AppState,
    admin: &Admin,
    headers: &HeaderMap,
    status: StatusCode,
    user: &str,
    error: Option<&str>,
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let page = LoginPage {
        prefix: admin.prefix(),
        csrf: &csrf,
        user,
        error,
    };
    let mut response = web::render(status, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    if let Some((user, _)) = state.web.session(&headers).await
        && user.is_admin
    {
        return see_other(&admin.url("/"));
    }
    login_form(&state, &admin, &headers, StatusCode::OK, "", None)
}

#[derive(Deserialize)]
struct LoginForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    if !state.web.same_origin(&headers) {
        return blocked("This form was sent from another site.");
    }
    let user = form.user.trim().to_owned();
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        let error = "The form has expired. Please sign in again.";
        return login_form(
            &state,
            &admin,
            &headers,
            StatusCode::FORBIDDEN,
            &user,
            Some(error),
        );
    }
    let client: IpAddr = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let password = SecretString::from(form.password);
    match state.web.verify_password(client, &user, password).await {
        Verified::Ok(account) if account.is_admin => {
            match state.web.open_session(client, &account).await {
                Some(token) => {
                    let mut response = see_other(&admin.url("/"));
                    let headers = response.headers_mut();
                    headers.append(header::SET_COOKIE, state.web.session_cookie(&token));
                    headers.append(header::SET_COOKIE, state.web.removal_cookie(CSRF_COOKIE));
                    response
                }
                None => internal_error(&"cannot create a session"),
            }
        }
        Verified::Ok(account) => {
            tracing::info!(%client, user = %account.username, "admin sign-in refused: not an admin");
            let error = "This account is not an administrator.";
            login_form(
                &state,
                &admin,
                &headers,
                StatusCode::FORBIDDEN,
                &user,
                Some(error),
            )
        }
        Verified::Invalid => {
            let error = "Wrong username or password.";
            login_form(
                &state,
                &admin,
                &headers,
                StatusCode::FORBIDDEN,
                &user,
                Some(error),
            )
        }
        Verified::RateLimited(wait) => {
            let mut response = web::too_many_attempts(wait);
            if let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
    }
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    if !state.web.same_origin(&headers) {
        return blocked("This form was sent from another site.");
    }
    // Non-admin sessions may sign out here as well (see `NotAdminPage`).
    if let Some((_, token)) = state.web.session(&headers).await {
        if !state.web.check_session_csrf(&token, &form.csrf) {
            return blocked("The form has expired. Go back, reload the page and try again.");
        }
        state.web.sign_out(&token).await;
    }
    let mut response = see_other(&admin.url("/login"));
    response
        .headers_mut()
        .append(header::SET_COOKIE, state.web.removal_cookie(SESSION_COOKIE));
    response
}

// ---------------------------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------------------------

async fn overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let now = pages::now();
    let stats = match stats::overview(&state.db, now).await {
        Ok(stats) => stats,
        Err(err) => return internal_error(&err),
    };
    let info = &admin.info;

    let data_dir = info.data_dir.clone();
    let db_path = info.db_path.clone();
    let (disk, db_bytes) = tokio::task::spawn_blocking(move || {
        let disk = gono_server_dav::fs::disk_space(&data_dir);
        let file_size = |path: PathBuf| std::fs::metadata(path).map_or(0, |meta| meta.len());
        let mut wal = db_path.clone().into_os_string();
        wal.push("-wal");
        (disk, file_size(db_path) + file_size(PathBuf::from(wal)))
    })
    .await
    .unwrap_or((None, 0));

    let (storage_number, storage_unit) = pages::split_bytes(stats.storage_used);
    let free_of_total = disk.map_or_else(
        || "unknown".to_owned(),
        |(free, total)| {
            format!(
                "{} of {}",
                pages::format_bytes(free),
                pages::format_bytes(total)
            )
        },
    );
    let disk_note = disk.map_or_else(
        || "Free space unknown".to_owned(),
        |(free, total)| {
            format!(
                "{} free of {}",
                pages::format_bytes(free),
                pages::format_bytes(total)
            )
        },
    );
    let push_live = state.push.as_ref().map(|hub| hub.connection_stats());
    let endpoints = state.push.as_ref().map(|_| Endpoints::new(&state.base_url));
    let origin = state.base_url.as_str().trim_end_matches('/').to_owned();
    let uptime = pages::duration(now - info.started_at);
    let proxies = if info.trusted_proxies.is_empty() {
        "none".to_owned()
    } else {
        info.trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let fact = |label: &'static str, value: String, mono: bool| Fact { label, value, mono };
    let server_facts = vec![
        fact("Version", env!("CARGO_PKG_VERSION").to_owned(), true),
        fact("Nextcloud protocol", status::version_string(), true),
        fact("Instance id", info.instance_id.clone(), true),
        fact("Started", pages::time(info.started_at), false),
        fact("Public URL", origin.clone(), true),
        fact("Listening on", info.bind.to_string(), true),
        fact("Trusted proxies", proxies, true),
        fact(
            "Configuration",
            info.config_path.display().to_string(),
            true,
        ),
        fact("Log", info.log.clone(), true),
    ];
    let mut features = Vec::new();
    match &info.push {
        Some(push) => features.push(Feature {
            name: "notify_push",
            detail: format!(
                "Ping {} s · debounce {} s · {} per user",
                push.ping_interval.as_secs(),
                push.debounce.as_secs(),
                push.max_connections_per_user
            ),
            on: true,
        }),
        None => features.push(Feature {
            name: "notify_push",
            detail: "Clients poll for changes".to_owned(),
            on: false,
        }),
    }
    features.push(Feature {
        name: "Login Flow v2",
        detail: format!(
            "{} {} waiting",
            stats.pending_login_flows,
            if stats.pending_login_flows == 1 {
                "sign-in"
            } else {
                "sign-ins"
            }
        ),
        on: true,
    });
    features.push(Feature {
        name: "Chunked upload v2",
        detail: format!(
            "Unfinished uploads expire after {} h",
            gono_server_core::uploads::SESSION_TTL_SECS / 3600
        ),
        on: true,
    });
    features.push(Feature {
        name: "WebDAV locks",
        detail: format!(
            "At most {} · {} held now",
            pages::duration(i64::try_from(info.lock_timeout_secs).unwrap_or(i64::MAX)),
            stats.locks
        ),
        on: true,
    });
    features.push(Feature {
        name: "Web admin",
        detail: format!(
            "{} browser {}",
            stats.web_sessions,
            if stats.web_sessions == 1 {
                "session"
            } else {
                "sessions"
            }
        ),
        on: true,
    });
    let mut warnings = info.warnings.clone();
    if info.case_insensitive == Some(true) {
        warnings.push(
            "the data directory is on a case-insensitive file system, so names that differ \
             only in case (Report.pdf, report.pdf) cannot coexist. A case-sensitive file system \
             (Linux with ext4, XFS or Btrfs) is recommended."
                .to_owned(),
        );
    }

    let page = OverviewPage {
        frame: admin.frame(&session, true, false),
        host: state.base_url.host_str().unwrap_or("Gono Cloud").to_owned(),
        uptime,
        warnings,
        users_note: format!(
            "{} {} · {} disabled",
            stats.admins,
            if stats.admins == 1 { "admin" } else { "admins" },
            stats.disabled
        ),
        storage_number,
        storage_unit: storage_unit.to_owned(),
        // The files' share of the file system they live on.
        disk: disk.map(|(_, total)| (stats.storage_used.min(total), total)),
        disk_note,
        push_live,
        server_facts,
        server_address: origin.clone(),
        webdav_url: format!("{origin}/remote.php/dav/files/<username>/"),
        websocket: endpoints.map(|endpoints| endpoints.websocket),
        data_dir: info.data_dir.display().to_string(),
        case_insensitive: info.case_insensitive,
        storage_used: pages::format_bytes(stats.storage_used),
        free_of_total,
        db_path: info.db_path.display().to_string(),
        db_size: pages::format_bytes(db_bytes),
        features,
        stats,
    };
    web::render(StatusCode::OK, &page)
}

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

async fn users_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(done): Query<Done>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let (accounts, counts) =
        match tokio::try_join!(users::list(&state.db), stats::per_user(&state.db)) {
            Ok(result) => result,
            Err(err) => return internal_error(&err),
        };
    let admins = accounts
        .iter()
        .filter(|user| user.is_admin && user.enabled)
        .count();
    let disabled = accounts.iter().filter(|user| !user.enabled).count();
    let summary = format!(
        "{} {} · {} {} · {} disabled",
        accounts.len(),
        if accounts.len() == 1 {
            "account"
        } else {
            "accounts"
        },
        admins,
        if admins == 1 { "admin" } else { "admins" },
        disabled
    );
    let rows = accounts
        .into_iter()
        .map(|user| {
            let counts = counts.get(&user.id).copied().unwrap_or_default();
            UserRow {
                username: user.username.to_string(),
                display_name: user.display_name,
                is_admin: user.is_admin,
                enabled: user.enabled,
                app_passwords: counts.app_passwords,
                storage: pages::format_bytes(counts.storage_used),
                created: pages::date(user.created_at),
            }
        })
        .collect();
    let notice = match done.done.as_deref() {
        Some("deleted") => {
            Some("The user was deleted. Their files were moved to deleted/.".to_owned())
        }
        _ => None,
    };
    let page = UsersPage {
        frame: admin.frame(&session, false, true),
        notice,
        summary,
        users: rows,
    };
    web::render(StatusCode::OK, &page)
}

async fn new_user_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let page = NewUserPage {
        frame: admin.frame(&session, false, true),
        error: None,
        username: String::new(),
        display_name: String::new(),
        admin: false,
    };
    web::render(StatusCode::OK, &page)
}

#[derive(Deserialize)]
struct NewUserForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
    #[serde(default)]
    admin: Option<String>,
}

/// Checks a new web login password and its repetition, then hashes it off the runtime.
async fn new_password_hash(password: String, repeat: &str) -> Result<String, String> {
    if password != repeat {
        return Err("The passwords do not match.".to_owned());
    }
    let password = SecretString::from(password);
    password::check_policy(&password).map_err(|err| format!("The password {err}."))?;
    tokio::task::spawn_blocking(move || password::hash(&password))
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.to_string())
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NewUserForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let is_admin = form.admin.is_some();
    let show_error = |error: String| {
        let page = NewUserPage {
            frame: admin.frame(&session, false, true),
            error: Some(error),
            username: form.username.trim().to_owned(),
            display_name: form.display_name.trim().to_owned(),
            admin: is_admin,
        };
        web::render(StatusCode::UNPROCESSABLE_ENTITY, &page)
    };
    let username = match Username::new(form.username.trim()) {
        Ok(username) => username,
        Err(err) => return show_error(err.to_string()),
    };
    let display_name = match users::display_name_or_default(
        Some(form.display_name.trim()).filter(|name| !name.is_empty()),
        &username,
    ) {
        Ok(name) => name,
        Err(err) => return show_error(err.to_string()),
    };
    match users::find(&state.db, &username).await {
        Ok(Some(_)) => return show_error(format!("A user named {username} already exists.")),
        Ok(None) => {}
        Err(err) => return internal_error(&err),
    }
    let hash = match new_password_hash(form.password.clone(), &form.password_repeat).await {
        Ok(hash) => hash,
        Err(error) => return show_error(error),
    };
    let layout = state.dav.fs().layout().clone();
    let created = users::create(
        &state.db,
        &NewUser {
            username: &username,
            display_name: &display_name,
            password_hash: &hash,
            is_admin,
        },
        |id| layout.create_user(id),
    )
    .await;
    match created {
        Ok(id) => {
            tracing::info!(by = %session.user.username, user = %username, id, is_admin, "admin created a user");
            see_other(&format!(
                "{}?done=created",
                admin.user_url(username.as_str())
            ))
        }
        Err(err @ (CoreError::UserExists(_) | CoreError::UserDirNotEmpty { .. })) => {
            show_error(err.to_string())
        }
        Err(err) => internal_error(&err),
    }
}

/// What the user detail page shows besides the account itself.
struct UserPageOptions {
    notice: Option<String>,
    error: Option<String>,
    form: AppPasswordForm,
    status: StatusCode,
}

impl Default for UserPageOptions {
    fn default() -> Self {
        Self {
            notice: None,
            error: None,
            form: AppPasswordForm::default(),
            status: StatusCode::OK,
        }
    }
}

/// The user detail page.
async fn user_page_response(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    user: &User,
    options: UserPageOptions,
) -> Response {
    let UserPageOptions {
        notice,
        error,
        form,
        status,
    } = options;
    let passwords = match app_passwords::list(&state.db, user.id).await {
        Ok(passwords) => passwords,
        Err(err) => return internal_error(&err),
    };
    let storage = match stats::per_user(&state.db).await {
        Ok(counts) => {
            counts
                .get(&user.id)
                .copied()
                .unwrap_or_default()
                .storage_used
        }
        Err(err) => return internal_error(&err),
    };
    let now = pages::now();
    let app_passwords = passwords
        .into_iter()
        .map(|password| AppPasswordRow {
            id: password.id,
            label: password.label,
            created: pages::date(password.created_at),
            scopes: password.scopes.iter().map(ScopeChip::new).collect(),
            last_used: password
                .last_used_at
                .map_or_else(|| "Never".to_owned(), |at| pages::ago(now, at)),
            expiry: pages::expiry(password.expires_at, now),
        })
        .collect();
    let page = UserPage {
        frame: admin.frame(session, false, true),
        base: admin.user_url(user.username.as_str()),
        notice,
        error,
        user: UserView {
            id: user.id,
            username: user.username.to_string(),
            display_name: user.display_name.clone(),
            is_admin: user.is_admin,
            enabled: user.enabled,
            created: pages::time(user.created_at),
            updated: pages::time(user.updated_at),
            storage: pages::format_bytes(storage),
        },
        is_self: user.id == session.user.user_id,
        app_passwords,
        form,
    };
    web::render(status, &page)
}

async fn user_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(done): Query<Done>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let notice = match done.done.as_deref() {
        Some("created") => Some(format!("User {} was created.", user.username)),
        Some("enabled") => Some("The account was enabled.".to_owned()),
        Some("disabled") => Some(
            "The account was disabled. Its devices and browser sessions are signed out.".to_owned(),
        ),
        Some("promoted") => Some(format!(
            "{} is now an admin and can sign in to this admin UI.",
            user.username
        )),
        Some("demoted") => Some(format!(
            "{} is no longer an admin. Their files and devices are not affected.",
            user.username
        )),
        Some("renamed") => Some("The display name was changed.".to_owned()),
        Some("password") => Some("The web login password was set.".to_owned()),
        Some("revoked") => Some("The app password was revoked.".to_owned()),
        _ => None,
    };
    let options = UserPageOptions {
        notice,
        ..UserPageOptions::default()
    };
    user_page_response(&state, &admin, &session, &user, options).await
}

/// Shows the user page again with an error, without changing anything.
async fn user_error(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    user: &User,
    status: StatusCode,
    error: String,
) -> Response {
    let options = UserPageOptions {
        error: Some(error),
        status,
        ..UserPageOptions::default()
    };
    user_page_response(state, admin, session, user, options).await
}

async fn enable(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_enabled(state, headers, name, form, true).await
}

async fn disable(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_enabled(state, headers, name, form, false).await
}

async fn set_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
    enabled: bool,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    if !enabled && user.id == session.user.user_id {
        let error = "You cannot disable the account you are signed in with.".to_owned();
        return user_error(&state, &admin, &session, &user, StatusCode::CONFLICT, error).await;
    }
    match users::set_enabled(&state.db, &user.username, enabled).await {
        Ok(()) => {}
        Err(err @ CoreError::LastAdmin(_)) => {
            return user_error(
                &state,
                &admin,
                &session,
                &user,
                StatusCode::CONFLICT,
                err.to_string(),
            )
            .await;
        }
        Err(err) => return internal_error(&err),
    }
    if !enabled && let Err(err) = web_sessions::delete_for_user(&state.db, user.id, None).await {
        tracing::warn!(error = %err, "cannot end the browser sessions of a disabled account");
    }
    tracing::info!(by = %session.user.username, user = %user.username, enabled, "admin changed an account");
    let done = if enabled { "enabled" } else { "disabled" };
    see_other(&format!(
        "{}?done={done}",
        admin.user_url(user.username.as_str())
    ))
}

async fn promote(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_admin(state, headers, name, form, true).await
}

async fn demote(
    state: State<AppState>,
    headers: HeaderMap,
    name: Path<String>,
    form: Form<CsrfForm>,
) -> Response {
    set_admin(state, headers, name, form, false).await
}

async fn set_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
    is_admin: bool,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    // Another admin has to do it, so that nobody locks themself out by accident.
    if !is_admin && user.id == session.user.user_id {
        let error = "You cannot demote the account you are signed in with.".to_owned();
        return user_error(&state, &admin, &session, &user, StatusCode::CONFLICT, error).await;
    }
    match users::set_admin(&state.db, &user.username, is_admin).await {
        Ok(()) => {}
        Err(err @ CoreError::LastAdmin(_)) => {
            return user_error(
                &state,
                &admin,
                &session,
                &user,
                StatusCode::CONFLICT,
                err.to_string(),
            )
            .await;
        }
        Err(err) => return internal_error(&err),
    }
    tracing::info!(by = %session.user.username, user = %user.username, is_admin, "admin changed an account's role");
    let done = if is_admin { "promoted" } else { "demoted" };
    see_other(&format!(
        "{}?done={done}",
        admin.user_url(user.username.as_str())
    ))
}

#[derive(Deserialize)]
struct DisplayNameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    display_name: String,
}

async fn set_display_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<DisplayNameForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    match users::set_display_name(&state.db, &user.username, &form.display_name).await {
        Ok(_) => {}
        Err(err @ CoreError::InvalidDisplayName(_)) => {
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            return user_error(&state, &admin, &session, &user, status, err.to_string()).await;
        }
        Err(err) => return internal_error(&err),
    }
    tracing::info!(by = %session.user.username, user = %user.username, "admin changed a display name");
    see_other(&format!(
        "{}?done=renamed",
        admin.user_url(user.username.as_str())
    ))
}

#[derive(Deserialize)]
struct PasswordForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
}

async fn set_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<PasswordForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let hash = match new_password_hash(form.password, &form.password_repeat).await {
        Ok(hash) => hash,
        Err(error) => {
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            return user_error(&state, &admin, &session, &user, status, error).await;
        }
    };
    if let Err(err) = users::set_password_hash(&state.db, &user.username, &hash).await {
        return internal_error(&err);
    }
    // Sign the user out everywhere else; an admin changing their own password stays in.
    let keep = (user.id == session.user.user_id).then_some(session.user.session_id);
    if let Err(err) = web_sessions::delete_for_user(&state.db, user.id, keep).await {
        tracing::warn!(error = %err, "cannot end the browser sessions after a password change");
    }
    tracing::info!(by = %session.user.username, user = %user.username, "admin set a web login password");
    see_other(&format!(
        "{}?done=password",
        admin.user_url(user.username.as_str())
    ))
}

async fn delete_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    delete_confirmation(&state, &admin, &session, &user, None, StatusCode::OK).await
}

async fn delete_confirmation(
    state: &AppState,
    admin: &Admin,
    session: &Session,
    user: &User,
    error: Option<String>,
    status: StatusCode,
) -> Response {
    let app_passwords = match stats::per_user(&state.db).await {
        Ok(counts) => {
            counts
                .get(&user.id)
                .copied()
                .unwrap_or_default()
                .app_passwords
        }
        Err(err) => return internal_error(&err),
    };
    let error = error.or_else(|| {
        (user.id == session.user.user_id)
            .then(|| "You cannot delete the account you are signed in with.".to_owned())
    });
    let page = DeletePage {
        frame: admin.frame(session, false, true),
        base: admin.user_url(user.username.as_str()),
        username: user.username.to_string(),
        app_passwords,
        error,
    };
    web::render(status, &page)
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    if user.id == session.user.user_id {
        return delete_confirmation(&state, &admin, &session, &user, None, StatusCode::CONFLICT)
            .await;
    }
    let deleted = match users::delete(&state.db, &user.username).await {
        Ok(deleted) => deleted,
        Err(err @ CoreError::LastAdmin(_)) => {
            let error = Some(err.to_string());
            return delete_confirmation(
                &state,
                &admin,
                &session,
                &user,
                error,
                StatusCode::CONFLICT,
            )
            .await;
        }
        Err(err) => return internal_error(&err),
    };
    let layout = state.dav.fs().layout().clone();
    let retired = tokio::task::spawn_blocking(move || {
        layout.retire_user(deleted.id, deleted.username.as_str(), db::unix_now())
    })
    .await;
    match retired {
        Ok(Ok(target)) => tracing::info!(
            by = %session.user.username,
            user = %user.username,
            files = ?target,
            "admin deleted a user"
        ),
        Ok(Err(err)) => tracing::warn!(
            user = %user.username,
            error = %err,
            "user deleted, but their files could not be moved to deleted/"
        ),
        Err(err) => tracing::warn!(error = %err, "user deleted, moving their files failed"),
    }
    see_other(&format!("{}?done=deleted", admin.url("/users")))
}

// ---------------------------------------------------------------------------------------------
// App passwords
// ---------------------------------------------------------------------------------------------

/// The new app password form. Mount rows are numbered fields (`mount_1`, `storage_1`,
/// `perm_1`, ...), collected by [`AppPasswordFields::form`].
struct AppPasswordFields {
    fields: HashMap<String, String>,
}

impl AppPasswordFields {
    fn field(&self, name: &str) -> String {
        self.fields
            .get(name)
            .map_or_else(String::new, |value| value.trim().to_owned())
    }

    fn form(&self) -> AppPasswordForm {
        AppPasswordForm {
            label: self.field("label"),
            expires_in_days: self.field("expires_in_days"),
            access: match self.field("access").as_str() {
                access @ ("view" | "custom") => access.to_owned(),
                _ => "full".to_owned(),
            },
            mounts: (1..=MOUNT_ROWS)
                .map(|row| MountInput {
                    mount: self.field(&format!("mount_{row}")),
                    storage: self.field(&format!("storage_{row}")),
                    permission: self.field(&format!("perm_{row}")),
                })
                .collect(),
        }
    }
}

/// Validates the form: label, expiry and scopes.
fn parse_app_password(
    form: &AppPasswordForm,
    now: i64,
) -> Result<(String, Vec<Scope>, Option<i64>), String> {
    let label = app_passwords::check_label(&form.label).map_err(|err| err.to_string())?;
    let expires_at = if form.expires_in_days.is_empty() {
        None
    } else {
        let days: i64 = form
            .expires_in_days
            .parse()
            .ok()
            .filter(|days| (1..=3650).contains(days))
            .ok_or("The expiry must be a number of days between 1 and 3650.")?;
        Some(now + days * 86_400)
    };
    let path = |value: &str| {
        RelPath::parse(value).map_err(|err| format!("Invalid path {value:?}: {err}."))
    };
    let scopes = match form.access.as_str() {
        "view" => vec![Scope {
            permission: Permission::View,
            ..Scope::full_access()
        }],
        "custom" => {
            let mut scopes = Vec::new();
            for mount in &form.mounts {
                if mount.mount.is_empty() && mount.storage.is_empty() {
                    continue;
                }
                if mount.mount.is_empty() || mount.storage.is_empty() {
                    return Err("Every mount needs both paths.".to_owned());
                }
                scopes.push(Scope {
                    mount_path: path(&mount.mount)?,
                    storage_path: path(&mount.storage)?,
                    permission: if mount.permission == "full" {
                        Permission::Full
                    } else {
                        Permission::View
                    },
                });
            }
            if scopes.is_empty() {
                return Err("Enter at least one folder for \"Selected folders\".".to_owned());
            }
            app_passwords::check_scopes(scopes).map_err(|err| err.to_string())?
        }
        _ => vec![Scope::full_access()],
    };
    Ok((label, scopes, expires_at))
}

async fn create_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let fields = AppPasswordFields { fields };
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &fields.field("csrf")).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    let form = fields.form();
    let now = pages::now();
    let (label, scopes, expires_at) = match parse_app_password(&form, now) {
        Ok(parsed) => parsed,
        Err(error) => {
            let options = UserPageOptions {
                error: Some(error),
                form,
                status: StatusCode::UNPROCESSABLE_ENTITY,
                ..UserPageOptions::default()
            };
            return user_page_response(&state, &admin, &session, &user, options).await;
        }
    };
    let (id, token) =
        match app_passwords::create(&state.db, user.id, &label, scopes.clone(), expires_at).await {
            Ok(created) => created,
            Err(err) => return internal_error(&err),
        };
    tracing::info!(by = %session.user.username, user = %user.username, app_password = id, "admin created an app password");
    admin.remember(
        session.user.session_id,
        Created {
            username: user.username.to_string(),
            label,
            token,
            scopes,
            expires_at,
            until: Instant::now() + CREATED_TTL,
        },
    );
    see_other(&admin.url("/created"))
}

/// The one-time display of the app password this session just created.
async fn created_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match session(&state, &admin, &headers).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let Some(created) = admin.take(session.user.session_id) else {
        let page = MessagePage {
            frame: admin.frame(&session, false, true),
            heading: "Nothing to show".to_owned(),
            lead: "A new app password is shown only once, right after it was created. Create \
                   another one if it was not written down."
                .to_owned(),
            link_href: admin.url("/users"),
            link_label: "All users".to_owned(),
        };
        return web::render(StatusCode::GONE, &page);
    };
    let page = CreatedPage {
        frame: admin.frame(&session, false, true),
        username: created.username,
        label: created.label,
        token: created.token.expose_secret().to_owned(),
        scopes: created.scopes.iter().map(ScopeChip::new).collect(),
        expiry: created
            .expires_at
            .map_or_else(|| "Never".to_owned(), pages::time),
        server: state.base_url.as_str().trim_end_matches('/').to_owned(),
    };
    let mut response = web::render(StatusCode::OK, &page);
    // `web::render` already sends `no-store`; say it in every dialect for older proxies.
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn revoke_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = match admin(&state) {
        Ok(admin) => admin,
        Err(halt) => return *halt,
    };
    let session = match form_session(&state, &admin, &headers, &form.csrf).await {
        Ok(session) => session,
        Err(halt) => return *halt,
    };
    let user = match find_user(&state, &admin, &session, &name).await {
        Ok(user) => user,
        Err(halt) => return *halt,
    };
    match app_passwords::delete(&state.db, user.id, id).await {
        Ok(true) => {
            tracing::info!(by = %session.user.username, user = %user.username, app_password = id, "admin revoked an app password");
            see_other(&format!(
                "{}?done=revoked",
                admin.user_url(user.username.as_str())
            ))
        }
        // Already revoked (for example in another tab): nothing to report.
        Ok(false) => see_other(&admin.user_url(user.username.as_str())),
        Err(err) => internal_error(&err),
    }
}

#[cfg(test)]
mod tests;
