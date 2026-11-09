//! HTTP routing.
//!
//! Only the health check exists so far. The next stage mounts, on this one router:
//!
//! - `/remote.php/dav/files/<user>/` and `/remote.php/webdav/` -> the single `DavHandler`
//!   from `gono_dav` (via `handle_guarded`),
//! - `/remote.php/dav/uploads/<user>/` -> chunked upload v2,
//! - `/status.php`, `/ocs/...`, `/index.php/login/v2...` -> `gono_nextcloud`,
//! - the notify_push WebSocket and, when `admin.enabled`, the web admin UI.

use axum::{Router, extract::State, http::StatusCode, routing::get};
use gono_core::db;

/// State shared by all request handlers. The next stage adds the configuration, the
/// `DavHandler` and the notify_push hub.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: db::Pool,
}

/// Builds the application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
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
