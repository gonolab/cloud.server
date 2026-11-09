//! HTTP and WebDAV request helpers.

use std::fmt::Write as _;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{
    Method, RequestBuilder, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};

use crate::{
    Cred,
    xml::{self, Multistatus},
};

/// Characters left unescaped in a path segment.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encodes every segment of a slash-separated relative path.
pub fn encode_path(rel: &str) -> String {
    rel.split('/')
        .map(|segment| utf8_percent_encode(segment, SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).expect("valid HTTP method")
}

/// A fully buffered HTTP response with the request line it answers.
#[derive(Debug, Clone)]
pub struct Resp {
    pub method: String,
    pub url: String,
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn code(&self) -> u16 {
        self.status.as_u16()
    }

    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
    }

    /// A short description of the exchange for assertion messages.
    pub fn describe(&self) -> String {
        let mut text = format!("{} {} -> {}", self.method, self.url, self.status);
        for (name, value) in &self.headers {
            let _ = write!(
                text,
                "\n  {name}: {}",
                String::from_utf8_lossy(value.as_bytes())
            );
        }
        let body = self.text();
        if !body.is_empty() {
            let excerpt: String = body.chars().take(1500).collect();
            let _ = write!(text, "\n  body: {excerpt}");
        }
        text
    }

    /// Panics unless the status is one of `codes`.
    #[track_caller]
    pub fn expect(&self, codes: &[u16]) -> &Self {
        assert!(
            codes.contains(&self.code()),
            "expected status {codes:?}\n{}",
            self.describe()
        );
        self
    }

    /// Panics unless the status is 2xx.
    #[track_caller]
    pub fn expect_success(&self) -> &Self {
        assert!(self.is_success(), "expected 2xx\n{}", self.describe());
        self
    }

    #[track_caller]
    pub fn multistatus(&self) -> Multistatus {
        self.expect(&[207]);
        match Multistatus::parse(&self.body) {
            Ok(multistatus) => multistatus,
            Err(err) => panic!("{err}\n{}", self.describe()),
        }
    }

    #[track_caller]
    pub fn json(&self) -> serde_json::Value {
        match serde_json::from_slice(&self.body) {
            Ok(value) => value,
            Err(err) => panic!("invalid JSON: {err}\n{}", self.describe()),
        }
    }
}

/// Sends a request and buffers the response, panicking on transport errors.
pub async fn send(client: &reqwest::Client, request: RequestBuilder) -> Resp {
    let request = request.build().expect("build HTTP request");
    let method = request.method().to_string();
    let url = request.url().to_string();
    let response = match client.execute(request).await {
        Ok(response) => response,
        Err(err) => panic!("{method} {url} failed: {err}"),
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body = match response.bytes().await {
        Ok(body) => body.to_vec(),
        Err(err) => panic!("{method} {url}: reading the body failed: {err}"),
    };
    Resp {
        method,
        url,
        status,
        headers,
        body,
    }
}

/// A WebDAV client bound to one credential and that user's files root
/// (`/remote.php/dav/files/<user>/`).
#[derive(Clone)]
pub struct Dav {
    pub http: reqwest::Client,
    pub base_url: String,
    pub cred: Cred,
}

impl Dav {
    pub fn new(http: reqwest::Client, base_url: &str, cred: Cred) -> Dav {
        Dav {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            cred,
        }
    }

    /// The path component of the base URL (empty when the server is mounted at `/`).
    pub fn base_path(&self) -> String {
        url::Url::parse(&self.base_url)
            .map(|url| url.path().trim_end_matches('/').to_owned())
            .unwrap_or_default()
    }

    /// `{base}/remote.php/dav/files/<user>/<rel>` with every segment percent-encoded.
    pub fn url(&self, rel: &str) -> String {
        self.url_for_user(&self.cred.user, rel)
    }

    pub fn url_for_user(&self, user: &str, rel: &str) -> String {
        format!(
            "{}/remote.php/dav/files/{}/{}",
            self.base_url,
            encode_path(user),
            encode_path(rel.trim_start_matches('/'))
        )
    }

    /// The decoded href path the server reports for `rel`, without trailing slash.
    pub fn href_path(&self, rel: &str) -> String {
        let rel = rel.trim_matches('/');
        let mut path = format!(
            "{}/remote.php/dav/files/{}",
            self.base_path(),
            self.cred.user
        );
        if !rel.is_empty() {
            path.push('/');
            path.push_str(rel);
        }
        path
    }

    /// `{base}/remote.php/dav/uploads/<user>/<rel>`.
    pub fn upload_url(&self, rel: &str) -> String {
        format!(
            "{}/remote.php/dav/uploads/{}/{}",
            self.base_url,
            encode_path(&self.cred.user),
            encode_path(rel.trim_start_matches('/'))
        )
    }

    /// Best-effort removal of a chunked upload session.
    pub async fn delete_upload(&self, upload: &str) {
        let _ = self
            .send(self.request("DELETE", &self.upload_url(upload)))
            .await;
    }

    /// A request with this client's Basic credentials.
    pub fn request(&self, method_name: &str, url: &str) -> RequestBuilder {
        self.http
            .request(method(method_name), url)
            .basic_auth(&self.cred.user, Some(&self.cred.password))
    }

    pub async fn send(&self, request: RequestBuilder) -> Resp {
        send(&self.http, request).await
    }

    pub async fn put(&self, rel: &str, body: impl Into<reqwest::Body>) -> Resp {
        self.send(self.request("PUT", &self.url(rel)).body(body))
            .await
    }

    pub async fn get(&self, rel: &str) -> Resp {
        self.send(self.request("GET", &self.url(rel))).await
    }

    pub async fn head(&self, rel: &str) -> Resp {
        self.send(self.request("HEAD", &self.url(rel))).await
    }

    pub async fn delete(&self, rel: &str) -> Resp {
        self.send(self.request("DELETE", &self.url(rel))).await
    }

    pub async fn mkcol(&self, rel: &str) -> Resp {
        self.send(self.request("MKCOL", &self.url(rel))).await
    }

    pub async fn copy(&self, rel: &str, dest_rel: &str, overwrite: Option<bool>) -> Resp {
        self.transfer("COPY", rel, &self.url(dest_rel), overwrite)
            .await
    }

    pub async fn mv(&self, rel: &str, dest_rel: &str, overwrite: Option<bool>) -> Resp {
        self.transfer("MOVE", rel, &self.url(dest_rel), overwrite)
            .await
    }

    /// COPY or MOVE with an arbitrary Destination URL.
    pub async fn transfer(
        &self,
        method_name: &str,
        rel: &str,
        destination: &str,
        overwrite: Option<bool>,
    ) -> Resp {
        let mut request = self
            .request(method_name, &self.url(rel))
            .header("Destination", destination);
        if let Some(overwrite) = overwrite {
            request = request.header("Overwrite", if overwrite { "T" } else { "F" });
        }
        self.send(request).await
    }

    pub async fn propfind(&self, rel: &str, depth: &str, body: &str) -> Resp {
        self.propfind_url(&self.url(rel), depth, body).await
    }

    pub async fn propfind_url(&self, url: &str, depth: &str, body: &str) -> Resp {
        self.send(
            self.request("PROPFIND", url)
                .header("Depth", depth)
                .header("Content-Type", "application/xml; charset=utf-8")
                .body(body.to_owned()),
        )
        .await
    }

    /// PROPFIND Depth 0 for the standard property set; panics unless it returns 207 with an
    /// entry for `rel`.
    pub async fn stat(&self, rel: &str) -> xml::DavResponse {
        let response = self.propfind(rel, "0", PROPFIND_STANDARD).await;
        let multistatus = response.multistatus();
        let href = self.href_path(rel);
        match multistatus.get(&href) {
            Some(entry) => entry.clone(),
            None => panic!(
                "PROPFIND result has no entry for {href}; got {:?}\n{}",
                multistatus.paths(),
                response.describe()
            ),
        }
    }

    /// The `DAV:getetag` value of `rel`, normalized with [`normalize_etag`].
    pub async fn etag(&self, rel: &str) -> String {
        let entry = self.stat(rel).await;
        let etag = entry
            .text(xml::DAV, "getetag")
            .unwrap_or_else(|| panic!("{rel} has no DAV:getetag: {entry:?}"));
        normalize_etag(&etag)
    }

    /// The `oc:fileid` value of `rel`.
    pub async fn fileid(&self, rel: &str) -> String {
        let entry = self.stat(rel).await;
        entry
            .text(xml::OC, "fileid")
            .unwrap_or_else(|| panic!("{rel} has no oc:fileid: {entry:?}"))
    }

    pub async fn proppatch(&self, rel: &str, body: &str) -> Resp {
        self.send(
            self.request("PROPPATCH", &self.url(rel))
                .header("Content-Type", "application/xml; charset=utf-8")
                .body(body.to_owned()),
        )
        .await
    }

    pub async fn report(&self, rel: &str, body: &str) -> Resp {
        self.send(
            self.request("REPORT", &self.url(rel))
                .header("Content-Type", "application/xml; charset=utf-8")
                .body(body.to_owned()),
        )
        .await
    }

    /// GET that panics unless the status is 200, returning the body.
    pub async fn read(&self, rel: &str) -> Vec<u8> {
        let response = self.get(rel).await;
        response.expect(&[200]);
        response.body
    }

    /// PUT that panics unless the status is 201 or 204.
    pub async fn write(&self, rel: &str, body: impl Into<reqwest::Body>) -> Resp {
        let response = self.put(rel, body).await;
        response.expect(&[201, 204]);
        response
    }

    /// MKCOL that panics unless the status is 201.
    pub async fn create_dir(&self, rel: &str) {
        self.mkcol(rel).await.expect(&[201]);
    }

    /// Creates every missing collection along `rel`, tolerating existing ones.
    pub async fn create_dir_all(&self, rel: &str) {
        let mut current = String::new();
        for segment in rel.trim_matches('/').split('/') {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(segment);
            let response = self.mkcol(&current).await;
            response.expect(&[201, 405]);
        }
    }
}

/// Strips the weak marker and the quotes from an entity tag.
pub fn normalize_etag(etag: &str) -> String {
    let etag = etag.trim();
    let etag = etag.strip_prefix("W/").unwrap_or(etag);
    etag.trim_matches('"').to_owned()
}

/// Adds a header to a request header map, panicking on invalid input.
pub fn header(map: &mut HeaderMap, name: &str, value: &str) {
    map.insert(
        HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
        HeaderValue::from_str(value).expect("valid header value"),
    );
}

/// PROPFIND body requesting the DAV and Nextcloud properties the tests inspect.
pub const PROPFIND_STANDARD: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <d:prop>
    <d:resourcetype/>
    <d:getetag/>
    <d:getlastmodified/>
    <d:getcontentlength/>
    <d:getcontenttype/>
    <oc:fileid/>
    <oc:id/>
    <oc:permissions/>
    <oc:favorite/>
    <oc:size/>
  </d:prop>
</d:propfind>"#;

/// PROPPATCH body setting `oc:favorite`.
pub fn proppatch_favorite(value: u8) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:set><d:prop><oc:favorite>{value}</oc:favorite></d:prop></d:set>
</d:propertyupdate>"#
    )
}

/// Namespace used for dead properties in the tests.
pub const DEAD_NS: &str = "urn:gono-acceptance:dead";

/// PROPPATCH body setting dead properties in [`DEAD_NS`].
pub fn proppatch_set_dead(props: &[(&str, &str)]) -> String {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:propertyupdate xmlns:d="DAV:" xmlns:x="urn:gono-acceptance:dead"><d:set><d:prop>"#,
    );
    for (name, value) in props {
        let _ = write!(body, "<x:{name}>{}</x:{name}>", xml::escape(value));
    }
    body.push_str("</d:prop></d:set></d:propertyupdate>");
    body
}

/// PROPPATCH body removing dead properties in [`DEAD_NS`].
pub fn proppatch_remove_dead(names: &[&str]) -> String {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:propertyupdate xmlns:d="DAV:" xmlns:x="urn:gono-acceptance:dead"><d:remove><d:prop>"#,
    );
    for name in names {
        let _ = write!(body, "<x:{name}/>");
    }
    body.push_str("</d:prop></d:remove></d:propertyupdate>");
    body
}

/// PROPFIND body requesting dead properties in [`DEAD_NS`] plus `oc:fileid`.
pub fn propfind_dead(names: &[&str]) -> String {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:x="urn:gono-acceptance:dead"><d:prop><oc:fileid/>"#,
    );
    for name in names {
        let _ = write!(body, "<x:{name}/>");
    }
    body.push_str("</d:prop></d:propfind>");
    body
}

/// `oc:filter-files` REPORT body selecting favorites.
pub const FILTER_FILES_FAVORITES: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <oc:filter-rules>
    <oc:favorite>1</oc:favorite>
  </oc:filter-rules>
  <d:prop>
    <d:getetag/>
    <d:resourcetype/>
    <oc:fileid/>
    <oc:favorite/>
  </d:prop>
</oc:filter-files>"#;

/// `DAV:lockinfo` body for an exclusive write lock.
pub const LOCKINFO_EXCLUSIVE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:lockinfo xmlns:d="DAV:">
  <d:lockscope><d:exclusive/></d:lockscope>
  <d:locktype><d:write/></d:locktype>
  <d:owner><d:href>gono-acceptance</d:href></d:owner>
</d:lockinfo>"#;
