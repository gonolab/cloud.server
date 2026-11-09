//! `GET /status.php`.
//!
//! The first request every Nextcloud client makes. It reports that the instance is installed and
//! not in maintenance mode, the Nextcloud version the server is compatible with, and the product
//! name.
//!
//! Clients decide what to do from these fields:
//!
//! - `installed`, `maintenance` and `needsDbUpgrade` must say "ready", or the clients refuse to
//!   connect.
//! - `version` / `versionstring` select protocol features. The desktop client uses Login Flow v2
//!   only for servers from 16.0 on and warns about versions it no longer supports, and the mobile
//!   apps refuse servers below their minimum version. Gono Cloud therefore reports the Nextcloud
//!   release whose protocol it implements, [`NEXTCLOUD_VERSION`].
//! - `productname` is only displayed. Gono Cloud reports its own name (see
//!   `docs/v1-scope.md`, "Open questions").

use serde_json::{Value, json};

/// The Nextcloud release whose client protocol Gono Cloud implements: `major.minor.micro`.
///
/// Reported in `status.php` and in the capabilities. Clients compare it with their own minimum
/// versions, so it must stay a release they support; features beyond the v1 scope are
/// switched off through the capabilities instead.
pub const NEXTCLOUD_VERSION: (u32, u32, u32) = (30, 0, 0);

/// [`NEXTCLOUD_VERSION`] as `major.minor.micro`.
pub fn version_string() -> String {
    let (major, minor, micro) = NEXTCLOUD_VERSION;
    format!("{major}.{minor}.{micro}")
}

/// The `status.php` document.
pub fn document(product_name: &str) -> Value {
    let (major, minor, micro) = NEXTCLOUD_VERSION;
    json!({
        "installed": true,
        "maintenance": false,
        "needsDbUpgrade": false,
        // Nextcloud reports four components here and three in `versionstring`.
        "version": format!("{major}.{minor}.{micro}.0"),
        "versionstring": version_string(),
        "edition": "",
        "productname": product_name,
        "extendedSupport": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_ready_installation() {
        let status = document("Gono Cloud");
        assert_eq!(status["installed"], true);
        assert_eq!(status["maintenance"], false);
        assert_eq!(status["needsDbUpgrade"], false);
        assert_eq!(status["productname"], "Gono Cloud");
        assert_eq!(status["versionstring"], version_string());
        assert!(
            status["version"]
                .as_str()
                .unwrap()
                .starts_with(&version_string())
        );
    }
}
