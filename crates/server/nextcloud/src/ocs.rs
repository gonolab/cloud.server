//! OCS API documents (`/ocs/v1.php/...` and `/ocs/v2.php/...`).
//!
//! - [`capabilities`]: what the server implements, so clients enable exactly those features:
//!   chunked upload v2 and notify_push (when enabled), and no sharing, versions, trash bin or
//!   notifications.
//! - [`user`]: the profile of the signed-in user (`/cloud/user`, `/cloud/users/<id>`), which
//!   clients read at startup for the display name and the quota.
//! - [`Reply`]: the OCS envelope (`ocs.meta` + `ocs.data`) in JSON (`format=json` or
//!   `Accept: application/json`) or XML, with the status code conventions of API v1 and v2.
//!
//! The HTTP routing and authentication live in the server; this module only builds documents.

use http::StatusCode;
use serde_json::{Map, Value, json};

use crate::status;

/// OCS API version, from the path (`/ocs/v1.php` or `/ocs/v2.php`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiVersion {
    /// `/ocs/v1.php`: HTTP 200 for everything but 401, `statuscode` 100 for success.
    V1,
    /// `/ocs/v2.php`: the HTTP status mirrors the outcome, `statuscode` 200 for success.
    V2,
}

/// Response format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `application/json`.
    Json,
    /// `application/xml`, the OCS default.
    Xml,
}

impl Format {
    /// Picks the format from the `format` query parameter, falling back to the `Accept` header
    /// and then to XML, like Nextcloud.
    pub fn negotiate(query: Option<&str>, accept: Option<&str>) -> Self {
        let requested = query
            .into_iter()
            .flat_map(|query| query.split('&'))
            .find_map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                (name == "format").then_some(value)
            });
        match requested {
            Some(value) if value.eq_ignore_ascii_case("json") => Self::Json,
            Some(value) if value.eq_ignore_ascii_case("xml") => Self::Xml,
            _ if accept.is_some_and(|accept| accept.contains("application/json")) => Self::Json,
            _ => Self::Xml,
        }
    }
}

/// Outcome of an OCS call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Success.
    Ok,
    /// Missing or wrong credentials (`statuscode` 997, HTTP 401 in both versions).
    Unauthorized,
    /// The resource does not exist (or must not be revealed).
    NotFound,
    /// The call is not allowed for this user.
    Forbidden,
    /// The parameters are invalid.
    BadRequest,
}

/// A rendered OCS response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status.
    pub status: StatusCode,
    /// `Content-Type` header value.
    pub content_type: &'static str,
    /// Response body.
    pub body: Vec<u8>,
}

impl Reply {
    /// Wraps `data` in the OCS envelope of `version`, rendered as `format`.
    pub fn new(version: ApiVersion, format: Format, outcome: &Outcome, data: Value) -> Self {
        let (http, message) = match outcome {
            Outcome::Ok => (StatusCode::OK, "OK"),
            Outcome::Unauthorized => (StatusCode::UNAUTHORIZED, "Current user is not logged in"),
            Outcome::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            Outcome::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
            Outcome::BadRequest => (StatusCode::BAD_REQUEST, "Bad request"),
        };
        let statuscode = match (version, outcome) {
            (ApiVersion::V1, Outcome::Ok) => 100,
            (ApiVersion::V2, Outcome::Ok) => 200,
            (_, Outcome::Unauthorized) => 997,
            (ApiVersion::V1, Outcome::NotFound) => 998,
            _ => http.as_u16(),
        };
        let status = match version {
            ApiVersion::V1 if http != StatusCode::UNAUTHORIZED => StatusCode::OK,
            _ => http,
        };
        let document = json!({
            "ocs": {
                "meta": {
                    "status": if *outcome == Outcome::Ok { "ok" } else { "failure" },
                    "statuscode": statuscode,
                    "message": message,
                    "totalitems": "",
                    "itemsperpage": "",
                },
                "data": data,
            }
        });
        match format {
            Format::Json => Self {
                status,
                content_type: "application/json; charset=utf-8",
                body: serde_json::to_vec(&document).unwrap_or_default(),
            },
            Format::Xml => Self {
                status,
                content_type: "application/xml; charset=utf-8",
                body: to_xml(&document).into_bytes(),
            },
        }
    }
}

/// Renders an OCS envelope as XML: object keys become elements, array items become
/// `<element>`, `true` is `1`, `false` and `null` are empty, like Nextcloud's XML responses.
fn to_xml(document: &Value) -> String {
    fn write(out: &mut String, name: &str, value: &Value, depth: usize) {
        let name = if is_xml_name(name) { name } else { "element" };
        let indent = " ".repeat(depth);
        match value {
            Value::Object(map) => {
                out.push_str(&format!("{indent}<{name}>\n"));
                for (key, child) in map {
                    write(out, key, child, depth + 1);
                }
                out.push_str(&format!("{indent}</{name}>\n"));
            }
            Value::Array(items) => {
                out.push_str(&format!("{indent}<{name}>\n"));
                for item in items {
                    write(out, "element", item, depth + 1);
                }
                out.push_str(&format!("{indent}</{name}>\n"));
            }
            scalar => {
                let text = match scalar {
                    Value::Bool(true) => "1".to_owned(),
                    Value::Bool(false) | Value::Null => String::new(),
                    Value::String(text) => escape(text),
                    other => other.to_string(),
                };
                out.push_str(&format!("{indent}<{name}>{text}</{name}>\n"));
            }
        }
    }

    // `meta` before `data`, as Nextcloud writes it (JSON objects here are sorted by key).
    let mut out = String::from("<?xml version=\"1.0\"?>\n<ocs>\n");
    for part in ["meta", "data"] {
        if let Some(value) = document["ocs"].get(part) {
            write(&mut out, part, value, 1);
        }
    }
    out.push_str("</ocs>\n");
    out
}

/// Whether `name` can be used as an element name as is (ASCII subset of the XML rules).
fn is_xml_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !name.to_ascii_lowercase().starts_with("xml")
}

/// Escapes text content for XML.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// The capabilities document (`ocs.data` of `/cloud/capabilities`).
///
/// Only implemented features are advertised, and features clients would otherwise assume are
/// switched off explicitly:
///
/// - `dav.chunking = "1.0"`: chunked upload under `/remote.php/dav/uploads/`. The server
///   implements the v2 protocol (`Destination` and `OC-Total-Length` on `MKCOL` and `MOVE`)
///   and also accepts sessions created without a `Destination`.
/// - `files.bigfilechunking = false`: the old `<name>-chunking-<id>-<n>-<i>` PUT chunking does
///   not exist; clients that cannot use chunking v2 upload in one PUT.
/// - `files_sharing.api_enabled = false`, no `notifications`, no `user_status`, no versions or
///   trash bin.
/// - `notify_push` with the WebSocket and pre-auth URLs when the push endpoint is enabled.
///   `type` lists only `files`: there are no activities or notifications to announce, so
///   clients keep their own behavior for those.
/// - Login Flow v2 has no Nextcloud capability: clients use it for every server from version 16
///   on, which [`status::NEXTCLOUD_VERSION`] satisfies. `gono_cloud.login_flow_v2` states it
///   explicitly for the Gono client.
pub fn capabilities(
    product_name: &str,
    server_version: &str,
    push: Option<&crate::notify_push::Endpoints>,
) -> Value {
    let (major, minor, micro) = status::NEXTCLOUD_VERSION;
    let mut document = json!({
        "version": {
            "major": major,
            "minor": minor,
            "micro": micro,
            "string": status::version_string(),
            "edition": "",
            "extendedSupport": false,
        },
        "capabilities": {
            "core": {
                "pollinterval": 60,
                "webdav-root": "remote.php/webdav",
            },
            "dav": {
                "chunking": "1.0",
            },
            "files": {
                "bigfilechunking": false,
                "blacklisted_files": [],
                "comments": false,
                "undelete": false,
                "versioning": false,
            },
            "files_sharing": {
                "api_enabled": false,
                "public": { "enabled": false },
                "resharing": false,
                "group_sharing": false,
                "user": { "send_mail": false },
                "federation": { "outgoing": false, "incoming": false },
                "sharebymail": { "enabled": false },
            },
            "gono_cloud": {
                "productname": product_name,
                "version": server_version,
                "login_flow_v2": true,
                "chunking_v2": true,
                "filter_files_favorites": true,
                "notify_push": push.is_some(),
            },
        },
    });
    if let Some(push) = push {
        document["capabilities"]["notify_push"] = json!({
            "type": ["files"],
            "endpoints": {
                "websocket": push.websocket,
                "pre_auth": push.pre_auth,
            },
        });
    }
    document
}

/// What [`user`] reports about the signed-in user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo<'a> {
    /// Login name (`id`).
    pub username: &'a str,
    /// Display name.
    pub display_name: &'a str,
    /// Bytes stored by the user (`oc:size` of the root).
    pub used: u64,
    /// Free bytes on the storage, if known.
    pub free: Option<u64>,
}

/// The user document (`ocs.data` of `/cloud/user`). There are no per-user quotas in v1, so
/// the quota is unlimited (`-3`) and `free` is the free space of the storage.
pub fn user(info: &UserInfo<'_>) -> Value {
    let free = info.free.unwrap_or(0);
    let total = info.used.saturating_add(free);
    // Two decimals, as Nextcloud reports it.
    #[allow(clippy::cast_precision_loss)]
    let relative = if total == 0 {
        0.0
    } else {
        (info.used as f64 * 10_000.0 / total as f64).round() / 100.0
    };
    let mut data = Map::new();
    data.insert("enabled".into(), json!(true));
    data.insert("id".into(), json!(info.username));
    data.insert("displayname".into(), json!(info.display_name));
    data.insert("display-name".into(), json!(info.display_name));
    data.insert("email".into(), Value::Null);
    data.insert("additional_mail".into(), json!([]));
    data.insert("phone".into(), json!(""));
    data.insert("address".into(), json!(""));
    data.insert("website".into(), json!(""));
    data.insert("twitter".into(), json!(""));
    data.insert("organisation".into(), json!(""));
    data.insert("role".into(), json!(""));
    data.insert("headline".into(), json!(""));
    data.insert("biography".into(), json!(""));
    data.insert("profile_enabled".into(), json!("0"));
    data.insert("groups".into(), json!([]));
    data.insert("subadmin".into(), json!([]));
    data.insert("language".into(), json!("en"));
    data.insert("locale".into(), json!(""));
    data.insert("backend".into(), json!("Database"));
    data.insert(
        "backendCapabilities".into(),
        json!({ "setDisplayName": false, "setPassword": false }),
    );
    data.insert(
        "quota".into(),
        json!({
            "free": free,
            "used": info.used,
            "total": total,
            "relative": relative,
            // SPACE_UNLIMITED: there are no per-user quotas.
            "quota": -3,
        }),
    );
    Value::Object(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_follows_the_query_then_the_accept_header() {
        assert_eq!(Format::negotiate(Some("format=json"), None), Format::Json);
        assert_eq!(
            Format::negotiate(Some("a=1&format=xml"), Some("application/json")),
            Format::Xml
        );
        assert_eq!(
            Format::negotiate(None, Some("application/json, text/plain")),
            Format::Json
        );
        assert_eq!(Format::negotiate(None, None), Format::Xml);
    }

    #[test]
    fn status_codes_follow_the_api_version() {
        let body = |reply: &Reply| -> Value { serde_json::from_slice(&reply.body).unwrap() };
        let ok1 = Reply::new(ApiVersion::V1, Format::Json, &Outcome::Ok, json!({}));
        assert_eq!(ok1.status, StatusCode::OK);
        assert_eq!(body(&ok1)["ocs"]["meta"]["statuscode"], 100);
        assert_eq!(body(&ok1)["ocs"]["meta"]["status"], "ok");
        let ok2 = Reply::new(ApiVersion::V2, Format::Json, &Outcome::Ok, json!({}));
        assert_eq!(body(&ok2)["ocs"]["meta"]["statuscode"], 200);

        let missing1 = Reply::new(ApiVersion::V1, Format::Json, &Outcome::NotFound, json!([]));
        assert_eq!(missing1.status, StatusCode::OK, "v1 failures are HTTP 200");
        assert_eq!(body(&missing1)["ocs"]["meta"]["statuscode"], 998);
        let missing2 = Reply::new(ApiVersion::V2, Format::Json, &Outcome::NotFound, json!([]));
        assert_eq!(missing2.status, StatusCode::NOT_FOUND);
        assert_eq!(body(&missing2)["ocs"]["meta"]["status"], "failure");

        for version in [ApiVersion::V1, ApiVersion::V2] {
            let denied = Reply::new(version, Format::Json, &Outcome::Unauthorized, json!([]));
            assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
            assert_eq!(body(&denied)["ocs"]["meta"]["statuscode"], 997);
        }
    }

    #[test]
    fn xml_mirrors_the_json_document() {
        let reply = Reply::new(
            ApiVersion::V1,
            Format::Xml,
            &Outcome::Ok,
            json!({"id": "a<b", "list": [1, 2], "flag": true, "off": false, "1x": null}),
        );
        let xml = String::from_utf8(reply.body).unwrap();
        assert!(
            xml.starts_with("<?xml version=\"1.0\"?>\n<ocs>\n <meta>\n"),
            "{xml}"
        );
        assert!(xml.contains("<statuscode>100</statuscode>"), "{xml}");
        assert!(xml.contains("<id>a&lt;b</id>"), "{xml}");
        assert!(
            xml.contains("<list>\n   <element>1</element>\n   <element>2</element>\n  </list>"),
            "{xml}"
        );
        assert!(xml.contains("<flag>1</flag>"), "{xml}");
        assert!(xml.contains("<off></off>"), "{xml}");
        assert!(xml.contains("<element></element>"), "invalid names: {xml}");
        assert!(xmltree::Element::parse(xml.as_bytes()).is_ok(), "{xml}");
    }

    #[test]
    fn capabilities_advertise_chunking_and_nothing_unimplemented() {
        let document = capabilities("Gono Cloud", "1.0.0", None);
        let capabilities = &document["capabilities"];
        assert_eq!(capabilities["dav"]["chunking"], "1.0");
        assert_eq!(capabilities["files"]["bigfilechunking"], false);
        assert_eq!(capabilities["files_sharing"]["api_enabled"], false);
        for absent in ["notify_push", "notifications", "user_status"] {
            assert!(capabilities.get(absent).is_none(), "{absent}");
        }
        assert_eq!(document["version"]["string"], status::version_string());
        assert_eq!(capabilities["gono_cloud"]["login_flow_v2"], true);
        assert_eq!(capabilities["gono_cloud"]["notify_push"], false);
    }

    #[test]
    fn capabilities_advertise_notify_push_when_enabled() {
        let endpoints = crate::notify_push::Endpoints::new(
            &url::Url::parse("https://cloud.example.com").unwrap(),
        );
        let document = capabilities("Gono Cloud", "1.0.0", Some(&endpoints));
        let push = &document["capabilities"]["notify_push"];
        assert_eq!(push["type"], serde_json::json!(["files"]));
        assert_eq!(
            push["endpoints"]["websocket"],
            "wss://cloud.example.com/push/ws"
        );
        assert_eq!(
            push["endpoints"]["pre_auth"],
            "https://cloud.example.com/index.php/apps/notify_push/pre_auth"
        );
        assert_eq!(document["capabilities"]["gono_cloud"]["notify_push"], true);
    }

    #[test]
    fn user_quota_is_unlimited_with_the_free_space() {
        let data = user(&UserInfo {
            username: "alice",
            display_name: "Alice",
            used: 25,
            free: Some(75),
        });
        assert_eq!(data["id"], "alice");
        assert_eq!(data["display-name"], "Alice");
        assert_eq!(data["quota"]["total"], 100);
        assert_eq!(data["quota"]["relative"], 25.0);
        assert_eq!(data["quota"]["quota"], -3);
    }
}
