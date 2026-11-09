//! notify_push: real-time change notifications over WebSocket.
//!
//! Implements the client side of Nextcloud's `notify_push` app, so desktop and mobile clients
//! sync as soon as something changes instead of polling:
//!
//! - The capabilities advertise the WebSocket and the pre-auth endpoint ([`Endpoints`]).
//! - A client opens `wss://<host>/push/ws` and sends its username and app password, or an
//!   empty username and a single-use pre-auth token obtained with
//!   `POST /index.php/apps/notify_push/pre_auth` ([`message`] lists every frame).
//! - The [`Hub`] receives every committed change from the `MetaStore` (and, through
//!   [`run_feed`], changes logged by other processes) and hands it to the connections of the
//!   owner.
//! - Each connection keeps an [`Outbox`] that drops changes its app password cannot see and
//!   debounces the rest (`notify_push.debounce_secs`).
//!
//! The WebSocket handling itself (upgrade, authentication, heartbeat) lives in the server
//! crate, which owns the HTTP stack.

mod hub;
pub mod message;
mod outbox;

use url::Url;

pub use hub::{
    FEED_INTERVAL, Handshake, Hub, MAX_HANDSHAKES, PushSettings, SubscribeError, Subscription,
    run_feed,
};
pub use outbox::{COALESCE, Outbox, PushEvent, visible};

/// Path of the WebSocket endpoint.
pub const WEBSOCKET_PATH: &str = "/push/ws";

/// Path of the pre-auth endpoint advertised in the capabilities. The same endpoint is also
/// served without the `/index.php` prefix.
pub const PRE_AUTH_PATH: &str = "/index.php/apps/notify_push/pre_auth";

/// The absolute URLs advertised in the `notify_push` capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// `ws://` or `wss://` URL of the WebSocket.
    pub websocket: String,
    /// `http://` or `https://` URL of the pre-auth endpoint.
    pub pre_auth: String,
}

impl Endpoints {
    /// The endpoints below the public origin `base_url`.
    pub fn new(base_url: &Url) -> Self {
        let origin = base_url.as_str().trim_end_matches('/');
        let websocket = format!("{origin}{WEBSOCKET_PATH}");
        let websocket = if let Some(rest) = websocket.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = websocket.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            websocket
        };
        Self {
            websocket,
            pre_auth: format!("{origin}{PRE_AUTH_PATH}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_follow_the_public_origin() {
        let https = Endpoints::new(&Url::parse("https://cloud.example.com").unwrap());
        assert_eq!(https.websocket, "wss://cloud.example.com/push/ws");
        assert_eq!(
            https.pre_auth,
            "https://cloud.example.com/index.php/apps/notify_push/pre_auth"
        );
        let http = Endpoints::new(&Url::parse("http://127.0.0.1:16102/").unwrap());
        assert_eq!(http.websocket, "ws://127.0.0.1:16102/push/ws");
        assert_eq!(
            http.pre_auth,
            "http://127.0.0.1:16102/index.php/apps/notify_push/pre_auth"
        );
    }
}
