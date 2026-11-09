//! `GET /status.php`.
//!
//! The first request every Nextcloud client makes. Reports that the instance is installed and
//! not in maintenance mode, plus version and product name fields. Which fields the clients
//! actually require is an open question resolved by testing against real clients; the default
//! is to report Gono Cloud's own product name.
