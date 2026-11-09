//! Graceful shutdown on SIGTERM and Ctrl-C.

use std::{future::IntoFuture, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Router,
    serve::{ListenerExt as _, TapIo},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Notify,
};

/// How long in-flight requests may keep running after a shutdown signal. Long uploads and
/// WebSocket connections are cut off after this.
pub const GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Serves `app` until a shutdown signal arrives, then stops accepting connections and waits up
/// to [`GRACE_PERIOD`] for in-flight requests to finish.
///
/// `on_signal` runs as soon as the signal arrives, to end long-lived connections (notify_push
/// WebSockets) that would otherwise hold the shutdown up.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    on_signal: impl FnOnce() + Send + 'static,
) -> anyhow::Result<()> {
    let signalled = Arc::new(Notify::new());
    let notify = Arc::clone(&signalled);

    let server = axum::serve(
        with_nodelay(listener),
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_signal().await;
        tracing::info!(
            grace_period_secs = GRACE_PERIOD.as_secs(),
            "shutting down; waiting for in-flight requests"
        );
        on_signal();
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

/// Wraps `listener` so that every accepted connection has `TCP_NODELAY` set.
///
/// hyper writes a response in more than one segment (the head, then the body). With Nagle's
/// algorithm on, the last small segment waits until the client acknowledges the previous one,
/// and a client that delays its ACK (Linux does, by up to 40 ms) stalls every request on a
/// kept-alive connection, including the reverse proxy's upstream keepalive. axum does not set
/// the option itself. Measured on Linux: PROPFIND went from about 1450 to 4300 requests per
/// second and the median latency from 44 ms to under 11 ms.
///
/// The concrete [`TapIo`] type (not `impl Listener`) is what axum's `ConnectInfo<SocketAddr>`
/// support is implemented for.
fn with_nodelay(listener: TcpListener) -> TapIo<TcpListener, fn(&mut TcpStream)> {
    listener.tap_io(set_nodelay)
}

fn set_nodelay(stream: &mut TcpStream) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(error = %err, "cannot set TCP_NODELAY on an accepted connection");
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

#[cfg(test)]
mod tests {
    use axum::serve::Listener as _;

    use super::*;

    #[tokio::test]
    async fn accepted_connections_have_nodelay_set() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = with_nodelay(listener);
        let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        let (stream, peer) = accepted;
        let client = client.unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
        assert!(stream.nodelay().unwrap());
        // The client side is untouched; only the server's sockets are tuned.
        assert!(!client.nodelay().unwrap());
    }
}
