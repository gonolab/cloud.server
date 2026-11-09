//! Graceful shutdown on SIGTERM and Ctrl-C.

use std::{future::IntoFuture, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::Router;
use tokio::{net::TcpListener, sync::Notify};

/// How long in-flight requests may keep running after a shutdown signal. Long uploads and
/// WebSocket connections are cut off after this.
pub const GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Serves `app` until a shutdown signal arrives, then stops accepting connections and waits up
/// to [`GRACE_PERIOD`] for in-flight requests to finish.
pub async fn serve(listener: TcpListener, app: Router) -> anyhow::Result<()> {
    let signalled = Arc::new(Notify::new());
    let notify = Arc::clone(&signalled);

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_signal().await;
        tracing::info!(
            grace_period_secs = GRACE_PERIOD.as_secs(),
            "shutting down; waiting for in-flight requests"
        );
        notify.notify_one();
    })
    .into_future();

    tokio::select! {
        result = server => result.context("HTTP server failed"),
        () = async {
            signalled.notified().await;
            tokio::time::sleep(GRACE_PERIOD).await;
        } => {
            tracing::warn!("grace period expired; aborting remaining requests");
            Ok(())
        }
    }
}

/// Resolves on the first SIGTERM or Ctrl-C (SIGINT).
async fn wait_for_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "cannot listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received Ctrl-C"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
}
