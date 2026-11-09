//! Raw HTTP/1.1 requests for request targets that a URL parser would normalize away
//! (for example `%2e%2e` segments). Only plain `http://` base URLs are supported.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::Cred;

/// Sends `method target` verbatim and returns the response status code.
///
/// Returns `Err` when the base URL is not plain HTTP (callers skip the check then).
pub async fn status(
    base_url: &str,
    method: &str,
    target: &str,
    cred: &Cred,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<u16, String> {
    let url = url::Url::parse(base_url).map_err(|err| format!("invalid base URL: {err}"))?;
    if url.scheme() != "http" {
        return Err(format!(
            "raw requests need a plain http:// base URL, got {}",
            url.scheme()
        ));
    }
    let host = url.host_str().ok_or("base URL without host")?.to_owned();
    let port = url.port_or_known_default().unwrap_or(80);
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    let base_path = url.path().trim_end_matches('/');
    let credentials = STANDARD.encode(format!("{}:{}", cred.user, cred.password));

    let mut request = format!(
        "{method} {base_path}{target} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Basic {credentials}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");

    let exchange = async {
        let mut stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|err| format!("connect: {err}"))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|err| format!("write: {err}"))?;
        stream
            .write_all(body)
            .await
            .map_err(|err| format!("write body: {err}"))?;
        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        while !response.windows(2).any(|window| window == b"\r\n") {
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|err| format!("read: {err}"))?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
        }
        let line = String::from_utf8_lossy(&response);
        line.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| format!("no HTTP status line in {line:?}"))
    };
    tokio::time::timeout(Duration::from_secs(60), exchange)
        .await
        .map_err(|_| "raw request timed out".to_owned())?
}
