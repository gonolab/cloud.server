//! Login Flow v2 endpoints and pages (see [`gono_nextcloud::login_flow`] for the protocol).
//!
//! | Request | Answer |
//! |---|---|
//! | `POST /index.php/login/v2` (or `/login/v2`) | Starts a flow. Anonymous; limited per client address and by [`login_flows::MAX_PENDING_FLOWS`]. |
//! | `POST .../login/v2/poll` with `token` | `404` until the user approved the device, then the new app password, once. |
//! | `GET .../login/v2/flow/<login token>` | The sign-in page, the consent page (when signed in), or the result. |
//! | `POST .../login/v2/flow/<login token>` | The forms of those pages: `action` = `login`, `grant`, `deny` or `logout`. |
//!
//! The pages need no JavaScript. Signing in uses the web login password, never an app
//! password, and only creates a browser session ([`crate::web`]); the device gets nothing
//! until the user presses "Grant access" on the consent page, which names the client. The
//! app password is minted when the client polls next. Login tokens appear in page URLs only,
//! which the request log redacts and the pages never leak as a referrer.

use std::net::SocketAddr;

use axum::{
    Form,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use gono_core::{db, login_flows};
use gono_nextcloud::login_flow;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::{
    app::AppState,
    client_ip::client_ip,
    web::{self, CSRF_COOKIE, SESSION_COOKIE, SignIn, escape},
};

fn json(status: StatusCode, value: &serde_json::Value) -> Response {
    let mut response = (status, serde_json::to_vec(value).unwrap_or_default()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn retry_after(response: &mut Response, seconds: u64) {
    if let Ok(value) = HeaderValue::from_str(&seconds.max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
}

/// `POST /index.php/login/v2` and `POST /login/v2`.
pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    if let Some(wait) = state.flow_starts.check(client) {
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        retry_after(&mut response, wait.as_secs());
        return response;
    }
    // Every start costs one token of this client's (separate) bucket.
    state.flow_starts.record_failure(client);

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let client_name = login_flow::client_name(user_agent);
    match login_flows::create(&state.db, &client_name, db::unix_now()).await {
        Ok(Some(flow)) => {
            tracing::info!(%client, client_name, "Login Flow v2 started");
            let prefix = if uri.path().starts_with("/index.php/") {
                "/index.php"
            } else {
                ""
            };
            json(
                StatusCode::OK,
                &login_flow::init_document(
                    &state.base_url,
                    prefix,
                    flow.poll_token.expose_secret(),
                    flow.login_token.expose_secret(),
                ),
            )
        }
        Ok(None) => {
            tracing::warn!("too many pending Login Flow v2 sign-ins");
            let mut response = StatusCode::SERVICE_UNAVAILABLE.into_response();
            retry_after(&mut response, 60);
            response
        }
        Err(err) => {
            tracing::error!(error = %err, "cannot start a Login Flow v2 sign-in");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The poll request body.
#[derive(Deserialize)]
pub struct PollForm {
    #[serde(default)]
    token: String,
}

/// `POST /index.php/login/v2/poll` and `POST /login/v2/poll`.
pub async fn poll(State(state): State<AppState>, Form(form): Form<PollForm>) -> Response {
    if form.token.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match login_flows::complete(&state.db, &form.token, db::unix_now()).await {
        Ok(Some(credentials)) => {
            tracing::info!(
                user = %credentials.username,
                app_password = credentials.app_password_id,
                label = credentials.label,
                "Login Flow v2 completed: app password minted"
            );
            json(
                StatusCode::OK,
                &login_flow::poll_document(
                    &state.base_url,
                    credentials.username.as_str(),
                    credentials.app_password.expose_secret(),
                ),
            )
        }
        // Pending, unknown, expired or already used: Nextcloud answers 404 for all of them.
        Ok(None) => json(StatusCode::NOT_FOUND, &serde_json::json!([])),
        Err(err) => {
            tracing::error!(error = %err, "Login Flow v2 poll failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The form fields of the flow pages.
#[derive(Deserialize)]
pub struct PageForm {
    #[serde(default)]
    action: String,
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
}

fn expired_page() -> Response {
    web::page(
        StatusCode::NOT_FOUND,
        "Link expired",
        "<h1>This link has expired</h1>\n<p>The sign-in request was already used, cancelled \
         or is too old. Start the sign-in again in your app.</p>",
    )
}

fn done_page(client: &str) -> Response {
    web::page(
        StatusCode::OK,
        "Access granted",
        &format!(
            "<h1>Access granted</h1>\n<p><span class=\"client\">{}</span> is now connected to \
             your account.</p>\n<p class=\"muted\">You can close this window and return to the \
             app.</p>",
            escape(client)
        ),
    )
}

fn login_page(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    client: &str,
    message: Option<&str>,
) -> Response {
    let (csrf, cookie) = state.web.login_csrf(headers);
    let message = message
        .map(|text| format!("<p class=\"error\" role=\"alert\">{}</p>\n", escape(text)))
        .unwrap_or_default();
    let mut response = web::page(
        status,
        "Connect a device",
        &format!(
            "<h1>Connect a device</h1>\n<p><span class=\"client\">{client}</span> wants to \
             access your account. Sign in to continue; you will be asked to confirm.</p>\n\
             {message}<form method=\"post\" action=\"\">\n\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\n\
             <input type=\"hidden\" name=\"action\" value=\"login\">\n\
             <label>Username<input type=\"text\" name=\"user\" autocomplete=\"username\" \
             autocapitalize=\"none\" spellcheck=\"false\" required autofocus></label>\n\
             <label>Password<input type=\"password\" name=\"password\" \
             autocomplete=\"current-password\" required></label>\n\
             <div class=\"actions\"><button type=\"submit\">Log in</button></div>\n</form>",
            client = escape(client),
            csrf = escape(&csrf),
        ),
    );
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

fn consent_page(
    state: &AppState,
    client: &str,
    session: &(gono_core::web_sessions::SessionUser, String),
) -> Response {
    let (user, token) = session;
    let csrf = escape(&state.web.session_csrf(token));
    let account = if user.display_name == user.username.as_str() {
        escape(&user.display_name)
    } else {
        format!(
            "{} ({})",
            escape(&user.display_name),
            escape(user.username.as_str())
        )
    };
    web::page(
        StatusCode::OK,
        "Grant access",
        &format!(
            "<h1>Grant access?</h1>\n<p><span class=\"client\">{client}</span> asks for access \
             to your account <strong>{account}</strong>.</p>\n<p class=\"muted\">If you grant \
             access, this device gets its own app password with access to all your files. You \
             can revoke it at any time. Only continue if you just started this sign-in in the \
             app.</p>\n<div class=\"actions\">\n\
             <form method=\"post\" action=\"\"><input type=\"hidden\" name=\"csrf\" \
             value=\"{csrf}\"><button type=\"submit\" name=\"action\" value=\"grant\">Grant \
             access</button></form>\n\
             <form method=\"post\" action=\"\"><input type=\"hidden\" name=\"csrf\" \
             value=\"{csrf}\"><button type=\"submit\" name=\"action\" value=\"deny\" \
             class=\"secondary\">Cancel</button></form>\n</div>\n\
             <form method=\"post\" action=\"\" class=\"actions\"><input type=\"hidden\" \
             name=\"csrf\" value=\"{csrf}\"><span class=\"muted\">Not \
             {account}?</span><button type=\"submit\" name=\"action\" value=\"logout\" \
             class=\"link\">Log out</button></form>",
            client = escape(client),
        ),
    )
}

/// Redirects to the page itself (Post/Redirect/Get), with extra `Set-Cookie` values.
fn back_to(uri: &Uri, cookies: &[HeaderValue]) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(location) = HeaderValue::from_str(uri.path()) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    for cookie in cookies {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    web::secure_headers(response.headers_mut());
    response
}

/// `GET .../login/v2/flow/<login token>`.
pub async fn page(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let flow = match login_flows::find(&state.db, &token, db::unix_now()).await {
        Ok(Some(flow)) => flow,
        Ok(None) => return expired_page(),
        Err(err) => {
            tracing::error!(error = %err, "Login Flow v2 lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if flow.granted_user_id.is_some() {
        return done_page(&flow.client_name);
    }
    match state.web.session(&headers).await {
        Some(session) => consent_page(&state, &flow.client_name, &session),
        None => login_page(&state, &headers, StatusCode::OK, &flow.client_name, None),
    }
}

/// `POST .../login/v2/flow/<login token>`.
pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    Form(form): Form<PageForm>,
) -> Response {
    if !state.web.same_origin(&headers) {
        return web::page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "<h1>Request blocked</h1>\n<p>This form was sent from another site.</p>",
        );
    }
    let flow = match login_flows::find(&state.db, &token, db::unix_now()).await {
        Ok(Some(flow)) => flow,
        Ok(None) => return expired_page(),
        Err(err) => {
            tracing::error!(error = %err, "Login Flow v2 lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let client = client_ip(peer.ip(), &headers, &state.trusted_proxies);

    if form.action == "login" {
        if !state.web.check_login_csrf(&headers, &form.csrf) {
            return login_page(
                &state,
                &headers,
                StatusCode::FORBIDDEN,
                &flow.client_name,
                Some("The form has expired. Please sign in again."),
            );
        }
        let password = SecretString::from(form.password);
        return match state.web.sign_in(client, &form.user, password).await {
            SignIn::Ok(token) => back_to(
                &uri,
                &[
                    state.web.session_cookie(&token),
                    state.web.removal_cookie(CSRF_COOKIE),
                ],
            ),
            SignIn::Invalid => login_page(
                &state,
                &headers,
                StatusCode::FORBIDDEN,
                &flow.client_name,
                Some("Wrong username or password."),
            ),
            SignIn::RateLimited(wait) => {
                let mut response = web::page(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many attempts",
                    &format!(
                        "<h1>Too many attempts</h1>\n<p>There were too many failed sign-ins from \
                         your network. Try again in {} seconds.</p>",
                        wait.as_secs().max(1)
                    ),
                );
                retry_after(&mut response, wait.as_secs());
                response
            }
        };
    }

    let Some(session) = state.web.session(&headers).await else {
        return login_page(
            &state,
            &headers,
            StatusCode::FORBIDDEN,
            &flow.client_name,
            Some("Your session has ended. Please sign in again."),
        );
    };
    if !state.web.check_session_csrf(&session.1, &form.csrf) {
        return web::page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "<h1>Request blocked</h1>\n<p>The form has expired. Reload the page and try \
             again.</p>",
        );
    }
    if flow.granted_user_id.is_some() {
        return done_page(&flow.client_name);
    }
    let user = &session.0;
    match form.action.as_str() {
        "grant" => match login_flows::grant(&state.db, flow.id, user.user_id, db::unix_now()).await
        {
            Ok(_) => {
                tracing::info!(
                    %client,
                    user = %user.username,
                    client_name = flow.client_name,
                    "Login Flow v2 access granted"
                );
                back_to(&uri, &[])
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot grant a Login Flow v2 sign-in");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        "deny" => {
            if let Err(err) = login_flows::deny(&state.db, flow.id).await {
                tracing::error!(error = %err, "cannot cancel a Login Flow v2 sign-in");
            }
            tracing::info!(%client, user = %user.username, "Login Flow v2 access denied");
            web::page(
                StatusCode::OK,
                "Access denied",
                &format!(
                    "<h1>Access denied</h1>\n<p><span class=\"client\">{}</span> did not get \
                     access to your account.</p>\n<p class=\"muted\">You can close this \
                     window.</p>",
                    escape(&flow.client_name)
                ),
            )
        }
        "logout" => {
            state.web.sign_out(&session.1).await;
            back_to(&uri, &[state.web.removal_cookie(SESSION_COOKIE)])
        }
        _ => web::page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "<h1>Bad request</h1>\n<p>Unknown action.</p>",
        ),
    }
}
