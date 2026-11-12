//! Site-wide pages and endpoints of the browser UI.
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /` | Redirects to the file UI, or to the admin UI when the file UI is off. |
//! | `GET /login`, `POST /login` | Sign in with the web login password (file UI only). `?next=` names a local page to return to. |
//! | `POST /logout` | Sign out (file UI only). |
//! | `POST /apps/theme` | Switches the theme (system, light, dark) and returns to the page; a script asking for JSON gets the new theme instead. |
//! | `GET /apps/assets/<name>` | The stylesheet and the script, under content-hashed names, cached for a year. |
//!
//! Sign-in uses [`Web::verify_password`](crate::web::Web::verify_password): Argon2, the
//! failed-attempt limiter of the HTML pages, and app passwords never accepted. Forms carry
//! the CSRF token of [`crate::web`] and must come from this origin.

use std::net::SocketAddr;

use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    app::AppState,
    client_ip::client_ip,
    i18n::Text,
    web::{self, ASSETS_PATH, CSRF_COOKIE, Chrome, Message, SESSION_COOKIE, Theme, Verified, page},
};

/// Where the file UI lives.
pub const FILES_HOME: &str = "/apps/files/";

/// `GET /`.
pub async fn root(State(state): State<AppState>) -> Response {
    if state.files.is_some() {
        web::see_other(FILES_HOME, &[])
    } else if let Some(admin) = &state.admin {
        web::see_other(&format!("{}/", admin.prefix()), &[])
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// `GET /apps/assets/<name>`.
pub async fn asset(Path(name): Path<String>) -> Response {
    let Some((content_type, body)) = web::asset(&format!("{ASSETS_PATH}{name}")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// A local page to return to: a path on this server (not `//host`), else `None`.
pub fn local_path(value: &str) -> Option<&str> {
    let ok = value.starts_with('/')
        && !value.starts_with("//")
        && !value.starts_with("/\\")
        && !value.bytes().any(|b| b.is_ascii_control() || b == b'\\');
    ok.then_some(value)
}

/// The page a `Referer` header names, if it is on this server.
fn referer_path(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let referer = headers.get(header::REFERER)?.to_str().ok()?;
    let url = url::Url::parse(referer).ok()?;
    if url.origin() != state.base_url.origin() {
        return None;
    }
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    local_path(&path).map(str::to_owned)
}

#[derive(Deserialize)]
pub struct ThemeForm {
    #[serde(default)]
    back: String,
}

/// `POST /apps/theme`: the next theme of the cycle. Not worth a CSRF token (another site could
/// only change a colour), but browsers must say it comes from this origin.
pub async fn theme(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ThemeForm>,
) -> Response {
    if !state.web.same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let theme = Theme::from_headers(&headers).next();
    let cookie = state.web.theme_cookie(theme);
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/json"));
    if wants_json {
        let mut response = axum::Json(serde_json::json!({ "theme": theme.name() })).into_response();
        response.headers_mut().append(header::SET_COOKIE, cookie);
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    let back = referer_path(&state, &headers)
        .or_else(|| local_path(&form.back).map(str::to_owned))
        .unwrap_or_else(|| "/".to_owned());
    web::see_other(&back, &[cookie])
}

// ---------------------------------------------------------------------------------------------
// Sign-in (file UI)
// ---------------------------------------------------------------------------------------------

/// `templates/sign_in.html`.
#[derive(Template)]
#[template(path = "sign_in.html")]
struct SignInPage {
    chrome: Chrome,
    csrf: String,
    user: String,
    next: String,
    notice: Option<&'static str>,
    error: Option<&'static str>,
}

page!(SignInPage);

#[derive(Deserialize)]
pub struct LoginQuery {
    next: Option<String>,
    done: Option<String>,
}

/// Where to go after signing in.
fn after_sign_in(next: Option<&str>) -> String {
    next.and_then(local_path)
        .filter(|path| *path != "/login")
        .unwrap_or(FILES_HOME)
        .to_owned()
}

fn sign_in_form(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    user: &str,
    next: &str,
    message: (Option<&'static str>, Option<&'static str>),
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let mut chrome = Chrome::for_request(headers);
    chrome.files = true;
    chrome.here = "/login".to_owned();
    let page = SignInPage {
        chrome,
        csrf,
        user: user.to_owned(),
        next: next.to_owned(),
        notice: message.0,
        error: message.1,
    };
    let mut response = web::render(status, &page);
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn files_off() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// `GET /login`.
pub async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    if state.files.is_none() {
        return files_off();
    }
    if state.web.session(&headers).await.is_some() {
        return web::see_other(&after_sign_in(query.next.as_deref()), &[]);
    }
    let t = Chrome::for_request(&headers).t;
    let notice = (query.done.as_deref() == Some("signed-out")).then_some(t.signed_out);
    let next = after_sign_in(query.next.as_deref());
    sign_in_form(&state, &headers, StatusCode::OK, "", &next, (notice, None))
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    next: String,
}

/// The refusal of a form sent from another site.
pub fn blocked(headers: &HeaderMap, lead: fn(&Text) -> &'static str) -> Response {
    let chrome = Chrome::for_request(headers);
    let t = chrome.t;
    Message::new(chrome, t.request_blocked, t.request_blocked, lead(t))
        .respond(StatusCode::FORBIDDEN)
}

/// `POST /login`.
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if state.files.is_none() {
        return files_off();
    }
    if !state.web.same_origin(&headers) {
        return blocked(&headers, |t| t.from_other_site);
    }
    let t = Chrome::for_request(&headers).t;
    let user = form.user.trim().to_owned();
    let next = after_sign_in(Some(&form.next));
    if !state.web.check_login_csrf(&headers, &form.csrf) {
        return sign_in_form(
            &state,
            &headers,
            StatusCode::FORBIDDEN,
            &user,
            &next,
            (None, Some(t.form_expired_sign_in)),
        );
    }
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    match state
        .web
        .verify_password(client, &user, SecretString::from(form.password))
        .await
    {
        Verified::Ok(account) => match state.web.open_session(client, &account).await {
            Some(token) => web::see_other(
                &next,
                &[
                    state.web.session_cookie(&token),
                    state.web.removal_cookie(CSRF_COOKIE),
                ],
            ),
            None => web::unavailable(Chrome::for_request(&headers)),
        },
        Verified::Invalid => sign_in_form(
            &state,
            &headers,
            StatusCode::FORBIDDEN,
            &user,
            &next,
            (None, Some(t.wrong_password)),
        ),
        Verified::RateLimited(wait) => web::too_many_attempts(Chrome::for_request(&headers), wait),
        Verified::Unavailable => web::unavailable(Chrome::for_request(&headers)),
    }
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /logout`.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if state.files.is_none() {
        return files_off();
    }
    if !state.web.same_origin(&headers) {
        return blocked(&headers, |t| t.from_other_site);
    }
    if let Some((_, token)) = state.web.session(&headers).await {
        if !state.web.check_session_csrf(&token, &form.csrf) {
            return blocked(&headers, |t| t.form_expired);
        }
        state.web.sign_out(&token).await;
    }
    web::see_other(
        "/login?done=signed-out",
        &[state.web.removal_cookie(SESSION_COOKIE)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_paths_are_followed() {
        assert_eq!(local_path("/apps/files/a?x=1"), Some("/apps/files/a?x=1"));
        assert_eq!(local_path("//evil.example/"), None);
        assert_eq!(local_path("/\\evil.example"), None);
        assert_eq!(local_path("https://evil.example/"), None);
        assert_eq!(local_path("/a\nb"), None);
        assert_eq!(local_path(""), None);
        assert_eq!(after_sign_in(Some("//evil")), FILES_HOME);
        assert_eq!(after_sign_in(Some("/login")), FILES_HOME);
        assert_eq!(after_sign_in(None), FILES_HOME);
        assert_eq!(after_sign_in(Some("/apps/account/")), "/apps/account/");
    }
}
