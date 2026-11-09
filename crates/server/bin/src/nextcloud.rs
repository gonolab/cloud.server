//! HTTP endpoints of the Nextcloud protocol surface besides WebDAV: `status.php`, the
//! connectivity probe and the OCS API. The documents themselves come from
//! [`gono_nextcloud`]; this module routes, authenticates and renders them.
//!
//! OCS endpoints (each under `/ocs/v1.php/`, `/ocs/v2.php/` and their `/index.php/` aliases):
//!
//! | Method | Endpoint | Authentication | Answer |
//! |---|---|---|---|
//! | `GET` | `cloud/capabilities` | none | [`ocs::capabilities`] |
//! | `GET` | `cloud/user` | app password | the signed-in user ([`ocs::user`]) |
//! | `GET` | `cloud/users/<id>` | app password | the signed-in user if `<id>` is them, 404 otherwise |
//! | `DELETE` | `core/apppassword` | app password | revokes the app password of the request (clients call it when an account is removed) |
//! | `GET` | `core/navigation/apps` | app password | an empty list (there are no web apps to link to) |
//!
//! Anything else answers an OCS 404 without looking at credentials.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use gono_core::{PRODUCT_NAME, app_passwords};
use gono_dav::Identity;
use gono_nextcloud::{
    notify_push,
    ocs::{self, ApiVersion, Format, Outcome, Reply},
    status,
};
use serde_json::{Value, json};

use crate::{
    app::{AppState, Rejection, authenticate},
    auth::basic_challenge,
};

/// Version of this server build, reported in the `gono_cloud` capability.
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `GET /status.php`.
pub async fn status_php() -> Response {
    json_response(StatusCode::OK, &status::document(PRODUCT_NAME))
}

/// `GET /index.php/204` and `GET /204`: the connectivity probe of the mobile apps.
pub async fn connectivity() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    let mut response = (status, serde_json::to_vec(value).unwrap_or_default()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

/// The OCS endpoints a request can name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    Capabilities,
    CurrentUser,
    User(String),
    RevokeAppPassword,
    NavigationApps,
    Unknown,
}

/// Splits `/[index.php/]ocs/v<n>.php/<rest>` into the API version and `<rest>`.
fn split_ocs_path(path: &str) -> Option<(ApiVersion, &str)> {
    let path = path.strip_prefix("/index.php").unwrap_or(path);
    if let Some(rest) = path.strip_prefix("/ocs/v1.php/") {
        Some((ApiVersion::V1, rest))
    } else {
        path.strip_prefix("/ocs/v2.php/")
            .map(|rest| (ApiVersion::V2, rest))
    }
}

fn endpoint(method: &Method, rest: &str) -> Endpoint {
    let rest = rest.trim_end_matches('/');
    match (method.as_str(), rest) {
        ("GET", "cloud/capabilities") => Endpoint::Capabilities,
        ("GET", "cloud/user") => Endpoint::CurrentUser,
        ("DELETE", "core/apppassword") => Endpoint::RevokeAppPassword,
        ("GET", "core/navigation/apps") => Endpoint::NavigationApps,
        ("GET", _) => rest
            .strip_prefix("cloud/users/")
            .filter(|id| !id.is_empty() && !id.contains('/'))
            .and_then(|id| String::from_utf8(crate::app::percent_decode(id.as_bytes())).ok())
            .map_or(Endpoint::Unknown, Endpoint::User),
        _ => Endpoint::Unknown,
    }
}

fn reply(version: ApiVersion, format: Format, outcome: &Outcome, data: Value) -> Response {
    let reply = Reply::new(version, format, outcome, data);
    let mut response = (reply.status, reply.body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(reply.content_type),
    );
    if *outcome == Outcome::Unauthorized {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, basic_challenge());
    }
    response
}

/// Every OCS request (see the module documentation).
pub async fn ocs(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let Some((version, rest)) = split_ocs_path(request.uri().path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let accept = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok());
    let format = Format::negotiate(request.uri().query(), accept);
    let endpoint = endpoint(request.method(), rest);

    match endpoint {
        Endpoint::Capabilities => {
            let push = state
                .push
                .as_ref()
                .map(|_| notify_push::Endpoints::new(&state.base_url));
            let data = ocs::capabilities(PRODUCT_NAME, SERVER_VERSION, push.as_ref());
            return reply(version, format, &Outcome::Ok, data);
        }
        Endpoint::Unknown => return reply(version, format, &Outcome::NotFound, json!([])),
        _ => {}
    }

    let identity = match authenticate(&state, peer, request.headers()).await {
        Ok(identity) => identity,
        Err(Rejection::Unauthorized) => {
            return reply(version, format, &Outcome::Unauthorized, json!([]));
        }
        Err(rejection @ Rejection::RateLimited(_)) => return rejection.into_response(),
    };
    match endpoint {
        Endpoint::CurrentUser => user_reply(&state, &identity, version, format).await,
        Endpoint::User(id) if id == identity.username.as_str() => {
            user_reply(&state, &identity, version, format).await
        }
        // Other accounts are not revealed, not even whether they exist.
        Endpoint::User(_) => reply(version, format, &Outcome::NotFound, json!([])),
        Endpoint::RevokeAppPassword => {
            match app_passwords::delete(&state.db, identity.user_id, identity.app_password_id).await
            {
                Ok(_) => {
                    tracing::info!(
                        user = %identity.username,
                        app_password = identity.app_password_id,
                        "app password revoked by its device"
                    );
                    reply(version, format, &Outcome::Ok, json!([]))
                }
                Err(err) => internal_error(&err),
            }
        }
        Endpoint::NavigationApps => reply(version, format, &Outcome::Ok, json!([])),
        Endpoint::Capabilities | Endpoint::Unknown => unreachable!("answered above"),
    }
}

async fn user_reply(
    state: &AppState,
    identity: &Arc<Identity>,
    version: ApiVersion,
    format: Format,
) -> Response {
    let (used, free) = match state.dav.fs().usage(identity.user_id).await {
        Ok(usage) => usage,
        Err(err) => {
            tracing::error!(error = ?err, "cannot determine storage usage");
            (0, None)
        }
    };
    let data = ocs::user(&ocs::UserInfo {
        username: identity.username.as_str(),
        display_name: &identity.display_name,
        used,
        free,
    });
    reply(version, format, &Outcome::Ok, data)
}

fn internal_error(err: &gono_core::Error) -> Response {
    tracing::error!(error = %err, "OCS request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, Body::empty()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocs_paths_and_endpoints() {
        assert_eq!(
            split_ocs_path("/index.php/ocs/v2.php/cloud/user"),
            Some((ApiVersion::V2, "cloud/user"))
        );
        assert_eq!(
            split_ocs_path("/ocs/v1.php/cloud/capabilities"),
            Some((ApiVersion::V1, "cloud/capabilities"))
        );
        assert_eq!(split_ocs_path("/ocs/v3.php/x"), None);

        assert_eq!(
            endpoint(&Method::GET, "cloud/users/a%40b"),
            Endpoint::User("a@b".into())
        );
        assert_eq!(endpoint(&Method::GET, "cloud/users/"), Endpoint::Unknown);
        assert_eq!(endpoint(&Method::POST, "cloud/user"), Endpoint::Unknown);
        assert_eq!(
            endpoint(&Method::DELETE, "core/apppassword"),
            Endpoint::RevokeAppPassword
        );
    }
}
