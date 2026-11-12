//! The web file UI and the account page through the router, with a cookie-keeping client.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
};
use base64::Engine as _;
use gono_server_core::{
    Username, app_passwords,
    config::DbConfig,
    db::{self, OpenMode},
    meta::MetaStore,
    password,
    storage::DataLayout,
    users::{self, NewUser},
};
use gono_server_nextcloud::chunking::ChunkedUploads;
use http_body_util::BodyExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use tower::ServiceExt as _;
use url::Url;

use super::Files;
use crate::{
    app::{self, AppState},
    auth::Authenticator,
    ratelimit::RateLimiter,
    web::Web,
};

const ORIGIN: &str = "https://cloud.example.com";
const ALICE_PASSWORD: &str = "alice password";

struct Fixture {
    _dir: tempfile::TempDir,
    state: AppState,
    /// A full-scope app password of `alice`.
    device: String,
}

async fn fixture_with(files: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let layout = DataLayout::new(dir.path().join("data"));
    layout.create().unwrap();
    let config = DbConfig {
        path: dir.path().join("db.sqlite"),
        max_connections: 4,
        busy_timeout_secs: 5,
    };
    let pool = db::connect(&config, OpenMode::CreateIfMissing)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let username = Username::new("alice").unwrap();
    let hash = password::hash(&SecretString::from(ALICE_PASSWORD.to_owned())).unwrap();
    let alice = users::create(
        &pool,
        &NewUser {
            username: &username,
            display_name: "Alice Example",
            password_hash: &hash,
            is_admin: false,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap();
    let (_, device) = app_passwords::create(&pool, alice, "laptop", Vec::new(), None)
        .await
        .unwrap();
    let dav = crate::commands::serve::dav_service(
        Duration::from_secs(600),
        layout.clone(),
        MetaStore::new(pool.clone()),
    )
    .await
    .unwrap();
    let uploads = ChunkedUploads::new(
        dav.fs().clone(),
        gono_server_core::locks::LockStore::new(pool.clone()),
    );
    let limiter = Arc::new(RateLimiter::new());
    let base_url = Url::parse(ORIGIN).unwrap();
    let state = AppState {
        db: pool.clone(),
        auth: Arc::new(Authenticator::new(pool.clone(), limiter.clone())),
        dav,
        uploads,
        web: Arc::new(Web::new(pool, limiter, &base_url)),
        base_url: Arc::new(base_url),
        flow_starts: Arc::new(RateLimiter::new()),
        trusted_proxies: Arc::new(Vec::new()),
        push: None,
        admin: None,
        files: files.then(|| Arc::new(Files::new())),
    };
    Fixture {
        _dir: dir,
        state,
        device: device.expose_secret().to_owned(),
    }
}

async fn fixture() -> Fixture {
    fixture_with(true).await
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn location(&self) -> &str {
        self.header("location")
    }

    /// The value of the first `name="<field>"` hidden input or meta tag.
    fn field(&self, attribute: &str) -> String {
        let text = self.text();
        let start = text
            .find(attribute)
            .unwrap_or_else(|| panic!("{attribute} in {text}"))
            + attribute.len();
        let rest = &text[start..];
        rest[..rest.find('"').unwrap()].to_owned()
    }

    /// The session's CSRF token, from the page's meta tag.
    fn csrf(&self) -> String {
        self.field("name=\"gono-csrf\" content=\"")
    }
}

/// A browser: keeps cookies, sends forms from this origin.
struct Browser {
    router: Router,
    cookies: HashMap<String, String>,
}

impl Browser {
    fn new(state: &AppState) -> Self {
        Self {
            router: app::router(state.clone()),
            cookies: HashMap::new(),
        }
    }

    async fn send(&mut self, method: &str, uri: &str, extra: &[(&str, &str)], body: Body) -> Reply {
        let mut request = Request::builder().method(method).uri(uri);
        if !self.cookies.is_empty() {
            let cookies: Vec<String> = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            request = request.header("Cookie", cookies.join("; "));
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let mut request = request.body(body).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 4000))));
        let response = self.router.clone().oneshot(request).await.unwrap();
        for value in response.headers().get_all("set-cookie") {
            let value = value.to_str().unwrap();
            let pair = value.split(';').next().unwrap();
            let (name, content) = pair.split_once('=').unwrap();
            if value.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), content.to_owned());
            }
        }
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body: body.to_vec(),
        }
    }

    async fn get(&mut self, uri: &str) -> Reply {
        self.send("GET", uri, &[], Body::empty()).await
    }

    async fn post(&mut self, uri: &str, fields: &[(&str, &str)]) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send(
            "POST",
            uri,
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", ORIGIN),
            ],
            Body::from(body),
        )
        .await
    }

    /// Signs in as alice; returns the session's CSRF token.
    async fn sign_in(&mut self) -> String {
        let form = self.get("/login").await;
        let csrf = form.field("name=\"csrf\" value=\"");
        let reply = self
            .post(
                "/login",
                &[
                    ("csrf", &csrf),
                    ("user", "alice"),
                    ("password", ALICE_PASSWORD),
                ],
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text());
        self.get("/apps/files/").await.csrf()
    }

    /// A WebDAV request with alice's app password.
    async fn dav(&mut self, device: &str, method: &str, rest: &str, body: &str) -> Reply {
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("alice:{device}"))
        );
        let mut router = Browser {
            router: self.router.clone(),
            cookies: HashMap::new(),
        };
        router
            .send(
                method,
                &format!("/remote.php/dav/files/alice/{rest}"),
                &[("Authorization", &basic), ("Depth", "0")],
                Body::from(body.to_owned()),
            )
            .await
    }
}

/// The `getetag` of a WebDAV `PROPFIND` reply.
fn etag(reply: &Reply) -> String {
    let text = reply.text();
    let start = text.find("getetag>").expect("getetag") + 8;
    text[start..start + text[start..].find('<').unwrap()].to_owned()
}

#[tokio::test]
async fn pages_need_a_web_session_and_webdav_needs_an_app_password() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);

    let anonymous = browser.get("/apps/files/Documents/").await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(
        anonymous.location(),
        "/login?next=%2Fapps%2Ffiles%2FDocuments%2F"
    );
    assert_eq!(browser.get("/").await.location(), "/apps/files/");

    // App passwords neither open pages nor sign in.
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("alice:{}", f.device))
    );
    let with_basic = browser
        .send(
            "GET",
            "/apps/files/",
            &[("Authorization", &basic)],
            Body::empty(),
        )
        .await;
    assert_eq!(with_basic.status, StatusCode::SEE_OTHER);
    let form = browser.get("/login").await;
    let csrf = form.field("name=\"csrf\" value=\"");
    let device = browser
        .post(
            "/login",
            &[("csrf", &csrf), ("user", "alice"), ("password", &f.device)],
        )
        .await;
    assert_eq!(device.status, StatusCode::FORBIDDEN);

    let token = browser.sign_in().await;
    assert_eq!(token.len(), 43);
    let page = browser.get("/apps/files/").await;
    assert_eq!(page.status, StatusCode::OK);
    let csp = page.header("content-security-policy");
    assert!(
        csp.contains("script-src 'nonce-") && !csp.contains("unsafe"),
        "{csp}"
    );
    // Signed in, the sign-in page sends the browser on.
    assert_eq!(
        browser.get("/login?next=/apps/account/").await.location(),
        "/apps/account/"
    );
    assert_eq!(
        browser.get("/login?next=//evil.example/").await.location(),
        "/apps/files/"
    );

    // The session cookie means nothing to the WebDAV routes.
    let cookie_dav = browser
        .send(
            "PROPFIND",
            "/remote.php/dav/files/alice/",
            &[("Depth", "0")],
            Body::empty(),
        )
        .await;
    assert_eq!(cookie_dav.status, StatusCode::UNAUTHORIZED);

    // Signing out ends the session.
    let out = browser.post("/logout", &[("csrf", &token)]).await;
    assert_eq!(out.location(), "/login?done=signed-out");
    assert_eq!(
        browser.get("/apps/files/").await.status,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn names_are_escaped_and_urls_encoded() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let evil = "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E%22.txt";
    assert_eq!(
        browser.dav(&f.device, "PUT", evil, "x").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        browser.dav(&f.device, "MKCOL", "a%20b", "").await.status,
        StatusCode::CREATED
    );
    browser.sign_in().await;
    let page = browser.get("/apps/files/").await;
    let text = page.text();
    assert!(!text.contains("<img src=x"), "{text}");
    assert!(
        text.contains("&#60;img src=x onerror=alert(1)&#62;&#34;.txt"),
        "{text}"
    );
    assert!(text.contains("href=\"/apps/files/a%20b/\""), "{text}");
    assert!(
        text.contains("href=\"/apps/files/%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%22.txt\""),
        "{text}"
    );
    // A folder without its slash, a file with one: redirects.
    assert_eq!(
        browser.get("/apps/files/a%20b").await.location(),
        "/apps/files/a%20b/"
    );
    // Dot segments never reach the file system.
    assert_eq!(
        browser.get("/apps/files/a%20b/%2e%2e/").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn forms_change_files_through_webdav() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let before = etag(&browser.dav(&f.device, "PROPFIND", "", "").await);

    let made = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "mkdir"), ("name", "Docs")],
        )
        .await;
    assert_eq!(made.location(), "/apps/files/?done=created&name=Docs");
    assert_eq!(
        browser.dav(&f.device, "PROPFIND", "Docs", "").await.status,
        StatusCode::MULTI_STATUS
    );
    // The sync clients see the change: the root's ETag moved.
    assert_ne!(
        etag(&browser.dav(&f.device, "PROPFIND", "", "").await),
        before
    );

    let again = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "mkdir"), ("name", "Docs")],
        )
        .await;
    assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY, "exists");
    let slash = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "mkdir"), ("name", "a/b")],
        )
        .await;
    assert_eq!(slash.status, StatusCode::UNPROCESSABLE_ENTITY, "bad name");

    browser.dav(&f.device, "PUT", "Docs/a.txt", "hello").await;
    let renamed = browser
        .post(
            "/apps/files/Docs/",
            &[
                ("csrf", &csrf),
                ("action", "rename"),
                ("item", "a.txt"),
                ("name", "b.txt"),
            ],
        )
        .await;
    assert_eq!(
        renamed.location(),
        "/apps/files/Docs/?done=renamed&name=b.txt"
    );
    assert_eq!(
        browser.dav(&f.device, "GET", "Docs/b.txt", "").await.text(),
        "hello"
    );

    // Moving is chosen on a page, then confirmed; a folder never goes into itself.
    let picker = browser
        .post(
            "/apps/files/",
            &[("csrf", &csrf), ("action", "move"), ("item", "Docs")],
        )
        .await;
    assert_eq!(picker.status, StatusCode::OK);
    browser.dav(&f.device, "MKCOL", "Archive", "").await;
    let into_itself = browser
        .post(
            "/apps/files/",
            &[
                ("csrf", &csrf),
                ("action", "move"),
                ("item", "Docs"),
                ("at", "/Docs"),
                ("confirm", "1"),
            ],
        )
        .await;
    assert_eq!(
        into_itself.status,
        StatusCode::OK,
        "the picker again, with the error"
    );
    let moved = browser
        .post(
            "/apps/files/",
            &[
                ("csrf", &csrf),
                ("action", "move"),
                ("item", "Docs"),
                ("at", "/Archive"),
                ("confirm", "1"),
            ],
        )
        .await;
    assert_eq!(moved.location(), "/apps/files/?done=moved&n=1");
    assert_eq!(
        browser
            .dav(&f.device, "GET", "Archive/Docs/b.txt", "")
            .await
            .status,
        StatusCode::OK
    );

    // Deleting asks first; GET never changes anything.
    let asked = browser
        .get("/apps/files/Archive/?action=delete&item=Docs")
        .await;
    assert_eq!(asked.status, StatusCode::OK);
    assert!(
        asked.text().contains("there is no trash"),
        "{}",
        asked.text()
    );
    assert_eq!(
        browser
            .dav(&f.device, "PROPFIND", "Archive/Docs", "")
            .await
            .status,
        StatusCode::MULTI_STATUS
    );
    let deleted = browser
        .post(
            "/apps/files/Archive/",
            &[
                ("csrf", &csrf),
                ("action", "delete"),
                ("item", "Docs"),
                ("item", "gone"),
                ("confirm", "1"),
            ],
        )
        .await;
    assert_eq!(
        deleted.location(),
        "/apps/files/Archive/?done=deleted&n=1&error=partial&f=1&of=2"
    );
    assert_eq!(
        browser
            .dav(&f.device, "PROPFIND", "Archive/Docs", "")
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // Without the token, or from another site: refused.
    let forged = browser
        .post(
            "/apps/files/",
            &[("csrf", "nope"), ("action", "mkdir"), ("name", "X")],
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let body = format!("csrf={csrf}&action=mkdir&name=X");
    let cross = browser
        .send(
            "POST",
            "/apps/files/",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "https://evil.example"),
            ],
            Body::from(body),
        )
        .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
    assert_eq!(
        browser.dav(&f.device, "PROPFIND", "X", "").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn downloads_are_sandboxed_attachments_and_previews_passive() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser
        .dav(&f.device, "PUT", "page.html", "<script>alert(1)</script>")
        .await;
    browser
        .dav(&f.device, "PUT", "x.svg", "<svg onload=alert(1)/>")
        .await;
    browser
        .dav(&f.device, "PUT", "pic.png", "not really a png")
        .await;
    browser.sign_in().await;

    let download = browser.get("/apps/files/page.html?download").await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(
        download.header("content-disposition"),
        "attachment; filename*=UTF-8''page.html"
    );
    assert_eq!(
        download.header("content-security-policy"),
        "default-src 'none'; sandbox"
    );
    assert_eq!(download.header("x-content-type-options"), "nosniff");
    assert_eq!(
        download.header("cross-origin-resource-policy"),
        "same-origin"
    );

    // Only images, video and audio open inline, with a type the server picks.
    assert_eq!(
        browser.get("/apps/files/page.html?raw").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        browser.get("/apps/files/x.svg?raw").await.status,
        StatusCode::NOT_FOUND
    );
    let png = browser.get("/apps/files/pic.png?raw").await;
    assert_eq!(png.header("content-type"), "image/png");
    assert_eq!(png.header("content-disposition"), "inline");
    assert_eq!(
        png.header("content-security-policy"),
        "default-src 'none'; sandbox"
    );

    // HTML is shown as escaped text inside the page, never as a page.
    let page = browser.get("/apps/files/page.html").await;
    assert!(
        page.text()
            .contains("&#60;script&#62;alert(1)&#60;/script&#62;")
    );
    assert!(!page.text().contains("<script>alert"));

    let range = browser
        .send(
            "GET",
            "/apps/files/page.html?download",
            &[("Range", "bytes=0-7")],
            Body::empty(),
        )
        .await;
    assert_eq!(range.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(range.text(), "<script>");
}

#[tokio::test]
async fn folders_download_as_zip_archives() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.dav(&f.device, "MKCOL", "Docs", "").await;
    browser.dav(&f.device, "MKCOL", "Docs/sub", "").await;
    browser.dav(&f.device, "PUT", "Docs/a.txt", "alpha").await;
    browser
        .dav(&f.device, "PUT", "Docs/sub/b.txt", "beta")
        .await;
    let csrf = browser.sign_in().await;

    let zip = browser.get("/apps/files/Docs/?download").await;
    assert_eq!(zip.status, StatusCode::OK);
    assert_eq!(zip.header("content-type"), "application/zip");
    assert_eq!(
        zip.header("content-disposition"),
        "attachment; filename*=UTF-8''Docs.zip"
    );
    let bytes = &zip.body;
    assert!(bytes.starts_with(b"PK\x03\x04"));
    let end = bytes.len() - 22;
    assert_eq!(&bytes[end..end + 4], b"PK\x05\x06");
    assert_eq!(
        u16::from_le_bytes([bytes[end + 10], bytes[end + 11]]),
        4,
        "entries"
    );
    let text = String::from_utf8_lossy(bytes);
    for name in [
        "Docs/",
        "Docs/a.txt",
        "Docs/sub/",
        "Docs/sub/b.txt",
        "alpha",
        "beta",
    ] {
        assert!(text.contains(name), "{name}");
    }

    // A selection, through the form.
    let selection = browser
        .post(
            "/apps/files/Docs/",
            &[("csrf", &csrf), ("action", "zip"), ("item", "a.txt")],
        )
        .await;
    assert_eq!(selection.header("content-type"), "application/zip");
    let text = String::from_utf8_lossy(&selection.body);
    assert!(text.contains("a.txt") && !text.contains("sub/b.txt"));
}

/// A `multipart/form-data` body with the given parts: `(name, file name, content)`.
fn multipart(parts: &[(&str, Option<&str>, &str)]) -> (String, String) {
    let boundary = "----gonoTestBoundary";
    let mut body = String::new();
    for (name, file, content) in parts {
        body.push_str(&format!("--{boundary}\r\n"));
        match file {
            Some(file) => body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"{file}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )),
            None => body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"
            )),
        }
        body.push_str(content);
        body.push_str("\r\n");
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    (format!("multipart/form-data; boundary={boundary}"), body)
}

#[tokio::test]
async fn uploads_from_forms_and_from_the_script() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;

    // Form upload: the token first, then the files; folders in names are dropped.
    let (kind, body) = multipart(&[
        ("csrf", None, &csrf),
        ("file", Some("one.txt"), "1"),
        ("file", Some("../evil/two.txt"), "22"),
    ]);
    let uploaded = browser
        .send(
            "POST",
            "/apps/files/?upload",
            &[("Content-Type", &kind), ("Origin", ORIGIN)],
            Body::from(body),
        )
        .await;
    assert_eq!(
        uploaded.location(),
        "/apps/files/?done=uploaded&n=2&skipped=0"
    );
    assert_eq!(
        browser.dav(&f.device, "GET", "two.txt", "").await.text(),
        "22"
    );
    let (kind, body) = multipart(&[("csrf", None, &csrf), ("file", Some("one.txt"), "x")]);
    let skipped = browser
        .send(
            "POST",
            "/apps/files/?upload",
            &[("Content-Type", &kind), ("Origin", ORIGIN)],
            Body::from(body),
        )
        .await;
    assert_eq!(
        skipped.location(),
        "/apps/files/?done=uploaded&n=0&skipped=1"
    );
    let (kind, body) = multipart(&[("file", Some("late.txt"), "x"), ("csrf", None, &csrf)]);
    let late_token = browser
        .send(
            "POST",
            "/apps/files/?upload",
            &[("Content-Type", &kind), ("Origin", ORIGIN)],
            Body::from(body),
        )
        .await;
    assert_eq!(
        late_token.status,
        StatusCode::FORBIDDEN,
        "the token must come first"
    );

    // Script: the token in a header.
    let headers = |extra: &'static [(&'static str, &'static str)]| {
        let mut all = vec![("Origin", ORIGIN)];
        all.extend_from_slice(extra);
        all
    };
    let without = browser
        .send("PUT", "/apps/files/s.txt", &headers(&[]), Body::from("s"))
        .await;
    assert_eq!(without.status, StatusCode::FORBIDDEN);
    let mut with = headers(&[("If-None-Match", "*")]);
    with.push(("X-Gono-CSRF", &csrf));
    assert_eq!(
        browser
            .send("PUT", "/apps/files/s.txt", &with, Body::from("s"))
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(
        browser
            .send("PUT", "/apps/files/s.txt", &with, Body::from("t"))
            .await
            .status,
        StatusCode::PRECONDITION_FAILED
    );
    let token = [("Origin", ORIGIN), ("X-Gono-CSRF", csrf.as_str())];
    assert_eq!(
        browser
            .send("MKCOL", "/apps/files/Up/", &token, Body::empty())
            .await
            .status,
        StatusCode::CREATED
    );

    // Chunked: start, two byte ranges, finish.
    let base = "/apps/files/Up/big.bin?id=abcdef0123456789";
    let start = browser
        .send(
            "POST",
            &format!("{base}&chunked=start&total=10"),
            &token,
            Body::empty(),
        )
        .await;
    assert_eq!(start.status, StatusCode::CREATED, "{}", start.text());
    for (range, data) in [("start=0&end=5", "012345"), ("start=6&end=9", "6789")] {
        let part = browser
            .send(
                "PUT",
                &format!("{base}&chunked=part&{range}"),
                &token,
                Body::from(data),
            )
            .await;
        assert!(part.status.is_success(), "{} {}", part.status, part.text());
    }
    let finish = browser
        .send(
            "POST",
            &format!("{base}&chunked=finish&total=10"),
            &token,
            Body::empty(),
        )
        .await;
    assert!(
        finish.status.is_success(),
        "{} {}",
        finish.status,
        finish.text()
    );
    assert_eq!(
        browser.dav(&f.device, "GET", "Up/big.bin", "").await.text(),
        "0123456789"
    );
    let bad_id = browser
        .send(
            "POST",
            "/apps/files/Up/x?id=../../x&chunked=start&total=1",
            &token,
            Body::empty(),
        )
        .await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn search_and_favorites() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    browser.dav(&f.device, "MKCOL", "Trips", "").await;
    browser
        .dav(&f.device, "PUT", "Trips/Beach%20day.jpg", "x")
        .await;
    browser.dav(&f.device, "PUT", "beachball.txt", "x").await;
    let csrf = browser.sign_in().await;

    let found = browser.get("/apps/files/?q=BEACH").await.text();
    assert!(
        found.contains("Beach day.jpg") && found.contains("beachball.txt"),
        "{found}"
    );
    let scoped = browser.get("/apps/files/Trips/?q=beach").await.text();
    assert!(scoped.contains("Beach day.jpg") && !scoped.contains("beachball.txt"));

    let starred = browser
        .post(
            "/apps/files/Trips/",
            &[
                ("csrf", &csrf),
                ("action", "favorite"),
                ("item", "Beach day.jpg"),
                ("value", "1"),
            ],
        )
        .await;
    assert_eq!(starred.location(), "/apps/files/Trips/?done=favorite");
    let favorites = browser.get("/apps/files/?view=favorites").await.text();
    assert!(favorites.contains("Beach day.jpg") && !favorites.contains("beachball.txt"));
    // Shared with the sync clients.
    let props = browser
        .dav(
            &f.device,
            "PROPFIND",
            "Trips/Beach%20day.jpg",
            r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:favorite/></d:prop></d:propfind>"#,
        )
        .await
        .text();
    assert!(props.contains("favorite>1<"), "{props}");
}

#[tokio::test]
async fn the_account_page_manages_password_and_app_passwords() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.sign_in().await;
    let page = browser.get("/apps/account/").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains("laptop"));

    let renamed = browser
        .post(
            "/apps/account/display-name",
            &[("csrf", &csrf), ("display_name", "Alice B.")],
        )
        .await;
    assert_eq!(renamed.location(), "/apps/account/?done=display-name");

    let wrong = browser
        .post(
            "/apps/account/password",
            &[
                ("csrf", &csrf),
                ("current", "nope"),
                ("password", "new password"),
                ("password_repeat", "new password"),
            ],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNPROCESSABLE_ENTITY);
    let changed = browser
        .post(
            "/apps/account/password",
            &[
                ("csrf", &csrf),
                ("current", ALICE_PASSWORD),
                ("password", "new password"),
                ("password_repeat", "new password"),
            ],
        )
        .await;
    assert_eq!(changed.location(), "/apps/account/?done=password");
    assert_eq!(
        browser.get("/apps/account/").await.status,
        StatusCode::OK,
        "still signed in"
    );

    let created = browser
        .post(
            "/apps/account/app-passwords",
            &[("csrf", &csrf), ("label", "rclone"), ("access", "view")],
        )
        .await;
    assert_eq!(created.location(), "/apps/account/created");
    let shown = browser.get("/apps/account/created").await;
    let text = shown.text();
    let start = text.find("<div class=\"secret\">").expect("secret") + 20;
    let token = text[start..start + text[start..].find('<').unwrap()].to_owned();
    assert!(token.len() >= 29, "{token}");
    assert_eq!(
        browser.get("/apps/account/created").await.location(),
        "/apps/account/",
        "shown once"
    );
    // The new app password is read only.
    assert_eq!(
        browser.dav(&token, "PUT", "ro.txt", "x").await.status,
        StatusCode::FORBIDDEN
    );

    let list = app_passwords::list(&f.state.db, 1).await.unwrap();
    let id = list.iter().find(|p| p.label == "rclone").unwrap().id;
    let revoked = browser
        .post(
            &format!("/apps/account/app-passwords/{id}/delete"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(revoked.location(), "/apps/account/?done=revoked");
    assert_eq!(
        browser.dav(&token, "PROPFIND", "", "").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn theme_switch_and_assets() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let light = browser.post("/apps/theme", &[("back", "/login")]).await;
    assert_eq!(light.location(), "/login");
    assert_eq!(
        browser.cookies.get("gono_theme").map(String::as_str),
        Some("light")
    );
    let page = browser.get("/login").await;
    assert!(
        page.text()
            .contains("<html lang=\"en\" data-theme=\"light\">")
    );
    let json = browser
        .send(
            "POST",
            "/apps/theme",
            &[
                ("Accept", "application/json"),
                ("Origin", ORIGIN),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            Body::from("back=%2F"),
        )
        .await;
    assert_eq!(json.text(), r#"{"theme":"dark"}"#);
    let away = browser
        .post("/apps/theme", &[("back", "//evil.example/")])
        .await;
    assert_eq!(away.location(), "/", "only local pages");

    let style = crate::web::style_url();
    let reply = browser.get(style).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.header("cache-control"),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        browser.get("/apps/assets/other.js").await.status,
        StatusCode::NOT_FOUND
    );

    // Chinese for browsers that prefer it.
    let zh = browser
        .send(
            "GET",
            "/login",
            &[("Accept-Language", "zh-CN,zh;q=0.9")],
            Body::empty(),
        )
        .await;
    assert!(zh.text().contains("<html lang=\"zh-CN\""), "{}", zh.text());
}

#[tokio::test]
async fn the_file_ui_can_be_turned_off() {
    let f = fixture_with(false).await;
    let mut browser = Browser::new(&f.state);
    assert_eq!(
        browser.get("/apps/files/").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        browser.get("/apps/account/").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(browser.get("/login").await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        browser.get("/").await.status,
        StatusCode::NOT_FOUND,
        "no admin UI either"
    );
}
