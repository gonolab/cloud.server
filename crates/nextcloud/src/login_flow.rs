//! Login Flow v2: the protocol documents.
//!
//! 1. `POST /index.php/login/v2` (or `/login/v2`) starts a flow
//!    ([`gono_core::login_flows::create`]) and answers [`init_document`]: a login URL for the
//!    browser and a token to poll with.
//! 2. The user opens the login URL, signs in with their web login password and approves the
//!    device on an explicit consent page that names the client ([`client_name`]). The pages
//!    are part of the server's web UI.
//! 3. `POST .../login/v2/poll` with `token=<poll token>` answers `404` until then, and once
//!    [`poll_document`] with a newly minted app password for this device
//!    ([`gono_core::login_flows::complete`]). Every device gets its own app password; the
//!    plaintext is never stored.

use serde_json::{Value, json};
use url::Url;

/// Longest client name kept, in characters.
const MAX_CLIENT_NAME_CHARS: usize = 100;

/// Name shown for a client that sends no usable `User-Agent`.
pub const UNKNOWN_CLIENT: &str = "Unknown client";

/// A readable name for the client that started a flow, from its `User-Agent`. It is shown on
/// the consent page and becomes the label of the app password.
///
/// The Nextcloud clients are recognized (`Nextcloud desktop 3.13.0 (macOS)`,
/// `Nextcloud Android 3.29.0`, `Nextcloud iOS 5.4.0`); anything else is the `User-Agent`
/// itself, without control characters and shortened to [`MAX_CLIENT_NAME_CHARS`].
pub fn client_name(user_agent: Option<&str>) -> String {
    let Some(agent) = user_agent.map(str::trim).filter(|agent| !agent.is_empty()) else {
        return UNKNOWN_CLIENT.to_owned();
    };
    let version_after = |marker: &str| -> Option<String> {
        let rest = &agent[agent.find(marker)? + marker.len()..];
        let version: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
            .collect();
        Some(version).filter(|version| !version.is_empty())
    };
    let name = if let Some(version) = version_after("mirall/") {
        // Desktop client: "Mozilla/5.0 (Macintosh) mirall/3.13.0 (Nextcloud, osx-23.5.0 ...)".
        let lower = agent.to_ascii_lowercase();
        let os = if lower.contains("osx") || lower.contains("macintosh") || lower.contains("macos")
        {
            Some("macOS")
        } else if lower.contains("windows") {
            Some("Windows")
        } else if lower.contains("linux") {
            Some("Linux")
        } else {
            None
        };
        match os {
            Some(os) => format!("Nextcloud desktop {version} ({os})"),
            None => format!("Nextcloud desktop {version}"),
        }
    } else if let Some(version) = version_after("Nextcloud-android/") {
        format!("Nextcloud Android {version}")
    } else if let Some(version) = version_after("Nextcloud-iOS/") {
        format!("Nextcloud iOS {version}")
    } else {
        agent.to_owned()
    };
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_CLIENT_NAME_CHARS)
        .collect();
    if cleaned.trim().is_empty() {
        UNKNOWN_CLIENT.to_owned()
    } else {
        cleaned.trim().to_owned()
    }
}

/// The answer to a flow start. `prefix` is the path the client used (`/index.php` or empty),
/// so the URLs follow the client's choice of front controller.
pub fn init_document(base_url: &Url, prefix: &str, poll_token: &str, login_token: &str) -> Value {
    let origin = base_url.as_str().trim_end_matches('/');
    json!({
        "poll": {
            "token": poll_token,
            "endpoint": format!("{origin}{prefix}/login/v2/poll"),
        },
        "login": format!("{origin}{prefix}/login/v2/flow/{login_token}"),
    })
}

/// The answer to the poll that completes a flow.
pub fn poll_document(base_url: &Url, username: &str, app_password: &str) -> Value {
    json!({
        "server": base_url.as_str().trim_end_matches('/'),
        "loginName": username,
        "appPassword": app_password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nextcloud_clients_get_readable_names() {
        assert_eq!(
            client_name(Some(
                "Mozilla/5.0 (Macintosh) mirall/3.13.0git (Nextcloud, osx-23.5.0 ClientArchitecture: arm64 OsArchitecture: arm64)"
            )),
            "Nextcloud desktop 3.13.0git (macOS)"
        );
        assert_eq!(
            client_name(Some(
                "Mozilla/5.0 (Linux) mirall/3.11.0 (Nextcloud, ubuntu-6.8.0 ClientArchitecture: x86_64)"
            )),
            "Nextcloud desktop 3.11.0 (Linux)"
        );
        assert_eq!(
            client_name(Some("Mozilla/5.0 (Android) Nextcloud-android/3.29.0")),
            "Nextcloud Android 3.29.0"
        );
        assert_eq!(
            client_name(Some("Mozilla/5.0 (iOS) Nextcloud-iOS/5.4.0")),
            "Nextcloud iOS 5.4.0"
        );
        assert_eq!(client_name(Some("curl/8.0")), "curl/8.0");
        assert_eq!(client_name(None), UNKNOWN_CLIENT);
        assert_eq!(client_name(Some(" \t")), UNKNOWN_CLIENT);
        let long = client_name(Some(&format!("x\u{7}{}", "y".repeat(500))));
        assert_eq!(long.chars().count(), MAX_CLIENT_NAME_CHARS);
        assert!(!long.contains('\u{7}'));
    }

    #[test]
    fn documents_point_at_the_public_origin() {
        let base = Url::parse("https://cloud.example.com").unwrap();
        let init = init_document(&base, "/index.php", "p", "l");
        assert_eq!(
            init["poll"]["endpoint"],
            "https://cloud.example.com/index.php/login/v2/poll"
        );
        assert_eq!(
            init["login"],
            "https://cloud.example.com/index.php/login/v2/flow/l"
        );
        assert_eq!(
            init_document(&base, "", "p", "l")["poll"]["endpoint"],
            "https://cloud.example.com/login/v2/poll"
        );
        let poll = poll_document(&base, "alice", "secret");
        assert_eq!(poll["server"], "https://cloud.example.com");
        assert_eq!(poll["loginName"], "alice");
        assert_eq!(poll["appPassword"], "secret");
    }
}
