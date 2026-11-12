//! The account page of the signed-in user, part of the web file UI.
//!
//! | Request | Page or action |
//! |---|---|
//! | `GET /apps/account/` | Profile, web login password and the user's app passwords. |
//! | `POST /apps/account/display-name` | Change the display name. |
//! | `POST /apps/account/password` | Change the web login password (needs the current one). The other browser sessions end; this one stays. |
//! | `POST /apps/account/app-passwords` | Create an app password, then show it once at `/apps/account/created`. |
//! | `POST /apps/account/app-passwords/<id>/delete` | Revoke one of the user's app passwords. |
//!
//! Every change is a POST with the session's CSRF token from this origin, answered with a
//! redirect. A new app password is kept in memory for its session only and shown once; the
//! URL carries no secret. Changing the password checks the current one through the
//! failed-attempt limiter of the sign-in pages.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use gono_server_core::{
    app_passwords::{self, Scope},
    db, password, users, web_sessions,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use super::{Visitor, blocked, internal, view::when, visitor};
use crate::{
    admin::{AppPasswordFields, AppPasswordForm, ScopeChip, core_message, parse_app_password},
    app::AppState,
    client_ip::client_ip,
    i18n::{Text, fill},
    web::{self, Chrome, Nav, Verified, page},
};

/// Where the account page lives.
pub const ACCOUNT: &str = "/apps/account";

/// How long a new app password waits to be shown.
const CREATED_TTL: Duration = Duration::from_secs(10 * 60);

/// New app passwords waiting to be shown, at most.
const MAX_CREATED: usize = 1000;

/// A new app password waiting to be shown once.
#[derive(Debug)]
pub struct Created {
    label: String,
    token: SecretString,
    scopes: Vec<Scope>,
    expires_at: Option<i64>,
    until: Instant,
}

/// New app passwords by the id of the session that created them.
#[derive(Debug, Default)]
pub struct CreatedStore(Mutex<HashMap<i64, Created>>);

impl CreatedStore {
    fn put(&self, session_id: i64, created: Created) {
        let now = Instant::now();
        let mut waiting = self.0.lock().unwrap_or_else(|e| e.into_inner());
        waiting.retain(|_, entry| entry.until > now);
        if waiting.len() >= MAX_CREATED {
            waiting.clear();
        }
        waiting.insert(session_id, created);
    }

    fn take(&self, session_id: i64) -> Option<Created> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id)
            .filter(|entry| entry.until > Instant::now())
    }
}

/// One app password in the list.
#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: i64,
    pub label: String,
    pub created: String,
    pub scopes: Vec<ScopeChip>,
    pub last_used: String,
    pub expiry: String,
}

/// `account/page.html`.
#[derive(Template)]
#[template(path = "account/page.html")]
struct AccountPage {
    chrome: Chrome,
    username: String,
    display_name: String,
    devices: Vec<DeviceRow>,
    form: AppPasswordForm,
    notice: Option<String>,
    error: Option<String>,
}

/// `account/created.html`.
#[derive(Template)]
#[template(path = "account/created.html")]
struct CreatedPage {
    chrome: Chrome,
    username: String,
    label: String,
    token: String,
    scopes: Vec<ScopeChip>,
    expiry: String,
    server: String,
    webdav: String,
}

page!(AccountPage, CreatedPage);

/// The signed-in user, or a redirect to the sign-in page.
async fn account_visitor(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<Visitor, Box<Response>> {
    if state.files.is_none() {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    }
    match visitor(state, headers, uri).await {
        Some(visitor) => Ok(visitor),
        None => Err(Box::new(web::see_other(
            &format!(
                "/login?next={}",
                super::view::encode_query(&format!("{ACCOUNT}/"))
            ),
            &[],
        ))),
    }
}

/// Like [`account_visitor`] for a form post: also checks the origin and the token.
async fn form_visitor(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    csrf: &str,
) -> Result<Visitor, Box<Response>> {
    let visitor = account_visitor(state, headers, uri).await?;
    if !state.web.same_origin(headers) {
        return Err(Box::new(blocked(&visitor, |t| t.from_other_site)));
    }
    if !state.web.check_session_csrf(&visitor.token, csrf) {
        return Err(Box::new(blocked(&visitor, |t| t.form_expired)));
    }
    Ok(visitor)
}

/// The expiry of an app password in words.
fn expiry(t: &Text, visitor: &Visitor, now: i64, expires_at: Option<i64>) -> String {
    match expires_at {
        Some(at) => fill(t.expires, &[&when(visitor.lang(), now, at).0]),
        None => t.no_expiry.to_owned(),
    }
}

async fn render_page(
    state: &AppState,
    visitor: &Visitor,
    form: AppPasswordForm,
    notice: Option<String>,
    error: Option<String>,
) -> Response {
    let t = visitor.t();
    let passwords = match app_passwords::list(&state.db, visitor.user.user_id).await {
        Ok(passwords) => passwords,
        Err(err) => return internal(visitor, "app password list", &err),
    };
    let now = db::unix_now();
    let devices = passwords
        .into_iter()
        .map(|password| DeviceRow {
            id: password.id,
            label: password.label,
            created: fill(
                t.created,
                &[&when(visitor.lang(), now, password.created_at).0],
            ),
            scopes: password.scopes.iter().map(ScopeChip::new).collect(),
            last_used: password.last_used_at.map_or_else(
                || t.never_used.to_owned(),
                |at| when(visitor.lang(), now, at).0,
            ),
            expiry: expiry(t, visitor, now, password.expires_at),
        })
        .collect();
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    let page = AccountPage {
        chrome: visitor.chrome(Nav::Account),
        username: visitor.user.username.to_string(),
        display_name: visitor.user.display_name.clone(),
        devices,
        form,
        notice,
        error,
    };
    web::render(status, &page)
}

#[derive(Deserialize)]
pub struct DoneQuery {
    done: Option<String>,
}

/// `GET /apps/account/`.
pub async fn show(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<DoneQuery>,
) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let notice = match query.done.as_deref() {
        Some("display-name") => Some(t.notice_display_name.to_owned()),
        Some("password") => Some(t.notice_password_changed.to_owned()),
        Some("revoked") => Some(t.notice_revoked.to_owned()),
        _ => None,
    };
    render_page(&state, &visitor, AppPasswordForm::default(), notice, None).await
}

/// `GET /apps/account`.
pub async fn to_page() -> Response {
    web::see_other(&format!("{ACCOUNT}/"), &[])
}

#[derive(Deserialize)]
pub struct DisplayNameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    display_name: String,
}

/// `POST /apps/account/display-name`.
pub async fn set_display_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<DisplayNameForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    if users::validate_display_name(&form.display_name).is_err() {
        let error = Some(t.err_display_name.to_owned());
        return render_page(&state, &visitor, AppPasswordForm::default(), None, error).await;
    }
    match users::set_display_name(&state.db, &visitor.user.username, &form.display_name).await {
        Ok(_) => web::see_other(&format!("{ACCOUNT}/?done=display-name"), &[]),
        Err(err) => internal(&visitor, "display name", &err),
    }
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    current: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_repeat: String,
}

/// `POST /apps/account/password`.
pub async fn set_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Form(form): Form<PasswordForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let t = visitor.t();
    let fail = |message: String| {
        let state = state.clone();
        let visitor = &visitor;
        async move {
            render_page(
                &state,
                visitor,
                AppPasswordForm::default(),
                None,
                Some(message),
            )
            .await
        }
    };
    if form.password != form.password_repeat {
        return fail(t.err_passwords_differ.to_owned()).await;
    }
    let new = SecretString::from(form.password);
    if let Err(err) = password::check_policy(&new) {
        return fail(core_message(t, &err)).await;
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match state
        .web
        .verify_password(
            client,
            visitor.user.username.as_str(),
            SecretString::from(form.current),
        )
        .await
    {
        Verified::Ok(user) if user.id == visitor.user.user_id => {}
        Verified::Ok(_) | Verified::Invalid => {
            return fail(t.err_current_password.to_owned()).await;
        }
        Verified::RateLimited(wait) => {
            return web::too_many_attempts(visitor.chrome(Nav::Account), wait);
        }
        Verified::Unavailable => return web::unavailable(visitor.chrome(Nav::Account)),
    }
    let hash = match tokio::task::spawn_blocking(move || password::hash(&new)).await {
        Ok(Ok(hash)) => hash,
        Ok(Err(err)) => return internal(&visitor, "password hash", &err),
        Err(err) => return internal(&visitor, "password hash", &err),
    };
    if let Err(err) = users::set_password_hash(&state.db, &visitor.user.username, &hash).await {
        return internal(&visitor, "password change", &err);
    }
    // Every other browser signs out; this one stays signed in.
    if let Err(err) = web_sessions::delete_for_user(
        &state.db,
        visitor.user.user_id,
        Some(visitor.user.session_id),
    )
    .await
    {
        tracing::warn!(error = %err, "cannot end the browser sessions after a password change");
    }
    tracing::info!(user = %visitor.user.username, "web login password changed by its user");
    web::see_other(&format!("{ACCOUNT}/?done=password"), &[])
}

/// `POST /apps/account/app-passwords`.
pub async fn create_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let fields = AppPasswordFields { fields };
    let visitor = match form_visitor(&state, &headers, &uri, &fields.field("csrf")).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let form = fields.form();
    let (label, scopes, expires_at) = match parse_app_password(visitor.t(), &form, db::unix_now()) {
        Ok(parsed) => parsed,
        Err(error) => return render_page(&state, &visitor, form, None, Some(error)).await,
    };
    let (id, token) = match app_passwords::create(
        &state.db,
        visitor.user.user_id,
        &label,
        scopes.clone(),
        expires_at,
    )
    .await
    {
        Ok(created) => created,
        Err(err) => return internal(&visitor, "app password", &err),
    };
    tracing::info!(user = %visitor.user.username, app_password = id, "user created an app password");
    files.created.put(
        visitor.user.session_id,
        Created {
            label,
            token,
            scopes,
            expires_at,
            until: Instant::now() + CREATED_TTL,
        },
    );
    web::see_other(&format!("{ACCOUNT}/created"), &[])
}

/// `GET /apps/account/created`: the new app password, once.
pub async fn created(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let visitor = match account_visitor(&state, &headers, &uri).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(created) = files.created.take(visitor.user.session_id) else {
        return web::see_other(&format!("{ACCOUNT}/"), &[]);
    };
    let t = visitor.t();
    let origin = state.base_url.as_str().trim_end_matches('/').to_owned();
    let page = CreatedPage {
        chrome: visitor.chrome(Nav::Account),
        username: visitor.user.username.to_string(),
        label: created.label,
        token: created.token.expose_secret().to_owned(),
        scopes: created.scopes.iter().map(ScopeChip::new).collect(),
        expiry: expiry(t, &visitor, db::unix_now(), created.expires_at),
        webdav: format!(
            "{origin}/remote.php/dav/files/{}/",
            super::view::encode_segment(visitor.user.username.as_str())
        ),
        server: origin,
    };
    web::render(StatusCode::OK, &page)
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /apps/account/app-passwords/<id>/delete`.
pub async fn revoke_app_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let visitor = match form_visitor(&state, &headers, &uri, &form.csrf).await {
        Ok(visitor) => visitor,
        Err(response) => return *response,
    };
    // Only the user's own: the query names the owner.
    match app_passwords::delete(&state.db, visitor.user.user_id, id).await {
        Ok(_) => {
            tracing::info!(user = %visitor.user.username, app_password = id, "user revoked an app password");
            web::see_other(&format!("{ACCOUNT}/?done=revoked"), &[])
        }
        Err(err) => internal(&visitor, "revoke", &err),
    }
}
