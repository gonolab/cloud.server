//! OCS API endpoints (`/ocs/v1.php/...` and `/ocs/v2.php/...`).
//!
//! - Capabilities (`/cloud/capabilities`), advertising only what the server implements:
//!   chunked upload v2, notify_push, and no sharing, versions or trash bin.
//! - The user endpoints clients call at startup (`/cloud/user`, `/cloud/users/<id>`), and
//!   empty-but-valid answers for endpoints the mobile apps call that have no v1 equivalent.
//! - The OCS envelope (`ocs.meta` + `ocs.data`) in both XML and JSON (`format=json`), with the
//!   v1/v2 status code conventions.
