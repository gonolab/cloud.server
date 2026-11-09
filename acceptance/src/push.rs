//! notify_push WebSocket client.

use std::{
    sync::Once,
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A connected notify_push WebSocket.
pub struct Push {
    socket: Socket,
    pub url: String,
}

/// Outcome of reading the next text frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Text(String),
    Timeout,
    Closed(String),
}

impl Push {
    pub async fn connect(url: &str) -> Result<Push, String> {
        install_crypto_provider();
        let (socket, _response) = connect_async(url)
            .await
            .map_err(|err| format!("WebSocket connect to {url} failed: {err}"))?;
        Ok(Push {
            socket,
            url: url.to_owned(),
        })
    }

    /// Connects and sends the two notify_push authentication frames (username, password).
    /// Returns the socket and the server's first text reply.
    pub async fn login(
        url: &str,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Result<(Push, Frame), String> {
        let mut push = Push::connect(url).await?;
        push.send_text(username).await?;
        push.send_text(password).await?;
        let reply = push.next_text(timeout).await;
        Ok((push, reply))
    }

    /// Like [`Push::login`] but panics unless the server replies `authenticated`.
    pub async fn authenticated(
        url: &str,
        username: &str,
        password: &str,
        timeout: Duration,
    ) -> Push {
        let (push, reply) = match Push::login(url, username, password, timeout).await {
            Ok(result) => result,
            Err(err) => panic!("{err}"),
        };
        assert_eq!(
            reply,
            Frame::Text("authenticated".to_owned()),
            "notify_push authentication reply from {url}"
        );
        push
    }

    pub async fn send_text(&mut self, text: &str) -> Result<(), String> {
        self.socket
            .send(Message::text(text.to_owned()))
            .await
            .map_err(|err| format!("WebSocket send failed: {err}"))
    }

    /// Reads frames until a text frame arrives, answering pings on the way.
    pub async fn next_text(&mut self, timeout: Duration) -> Frame {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Frame::Timeout;
            }
            let next = match tokio::time::timeout(remaining, self.socket.next()).await {
                Ok(next) => next,
                Err(_) => return Frame::Timeout,
            };
            match next {
                Some(Ok(Message::Text(text))) => return Frame::Text(text.to_string()),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = self.socket.send(Message::Pong(payload)).await;
                }
                Some(Ok(Message::Close(frame))) => {
                    return Frame::Closed(format!("close frame {frame:?}"));
                }
                Some(Ok(_)) => {}
                Some(Err(err)) => return Frame::Closed(format!("error: {err}")),
                None => return Frame::Closed("stream ended".to_owned()),
            }
        }
    }

    /// Discards incoming text frames until none arrives for `quiet`.
    pub async fn drain(&mut self, quiet: Duration) -> Vec<String> {
        let mut drained = Vec::new();
        while let Frame::Text(text) = self.next_text(quiet).await {
            drained.push(text);
        }
        drained
    }

    /// Waits for a `notify_file` or `notify_file_id` message.
    pub async fn wait_file_notification(&mut self, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.next_text(remaining).await {
                Frame::Text(text) if is_file_notification(&text) => return Some(text),
                Frame::Text(_) => {}
                Frame::Timeout | Frame::Closed(_) => return None,
            }
        }
    }

    pub async fn close(mut self) {
        let _ = self.socket.close(None).await;
    }
}

pub fn is_file_notification(text: &str) -> bool {
    text == "notify_file" || text.starts_with("notify_file_id")
}

/// Parses the ids of a `notify_file_id [1,2]` message.
pub fn notified_file_ids(text: &str) -> Option<Vec<String>> {
    let list = text.strip_prefix("notify_file_id")?.trim();
    let list = list.strip_prefix('[')?.strip_suffix(']')?;
    Some(
        list.split(',')
            .map(|id| id.trim().trim_matches('"').to_owned())
            .filter(|id| !id.is_empty())
            .collect(),
    )
}

/// rustls needs an explicit process-wide provider when more than one is compiled in.
fn install_crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
