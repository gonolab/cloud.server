//! Nextcloud protocol surface of Gono Cloud.
//!
//! Everything Nextcloud clients expect besides plain WebDAV lives here:
//!
//! - [`status`]: `GET /status.php`.
//! - [`ocs`]: the OCS API (`/ocs/v1.php`, `/ocs/v2.php`): capabilities and the user endpoints
//!   clients call at startup.
//! - [`login_flow`]: Login Flow v2 with an explicit consent page.
//! - [`chunking`]: chunked upload v2 under `/remote.php/dav/uploads/`.
//! - [`notify_push`]: real-time change notifications over WebSocket.

pub mod chunking;
pub mod login_flow;
pub mod notify_push;
pub mod ocs;
pub mod status;
