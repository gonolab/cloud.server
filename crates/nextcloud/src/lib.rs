//! Nextcloud protocol surface of Gono Cloud.
//!
//! Everything Nextcloud clients expect besides plain WebDAV lives here:
//!
//! - [`status`]: `GET /status.php`.
//! - [`ocs`]: the OCS API (`/ocs/v1.php`, `/ocs/v2.php`) documents: capabilities and the user
//!   endpoints clients call at startup.
//! - [`login_flow`]: Login Flow v2 protocol documents and client naming. The sign-in and
//!   consent pages are part of the server's web UI.
//! - [`chunking`]: chunked upload v2 under `/remote.php/dav/uploads/`.
//! - [`notify_push`]: real-time change notifications over WebSocket (not implemented yet).
//!
//! The HTTP routing and authentication live in the server crate; the services here take an
//! authenticated identity and `http` requests, like `gono_dav::DavService`.

pub mod chunking;
pub mod login_flow;
pub mod notify_push;
pub mod ocs;
pub mod status;
