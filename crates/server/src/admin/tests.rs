//! The admin UI through the router, with a small cookie-keeping client.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
};
use gono_core::{
    RelPath, Username,
    app_passwords::{self, Scope},
    config::DbConfig,
    db::{self, OpenMode},
    meta::MetaStore,
    password,
    storage::DataLayout,
    users::{self, NewUser},
    web_sessions,
};
use gono_nextcloud::chunking::ChunkedUploads;
use http_body_util::BodyExt as _;
use secrecy::{ExposeSecret as _, SecretString};
use tower::ServiceExt as _;
use url::Url;

use super::{Admin, ServerInfo};
use crate::{
    app::{self, AppState},
    auth::Authenticator,
    ratelimit::RateLimiter,
    web::{self, Web},
};

const PREFIX: &str = "/gono-admin";
const ROOT_PASSWORD: &str = "root password";
const ALICE_PASSWORD: &str = "alice password";

struct Fixture {
    _dir: tempfile::TempDir,
    state: AppState,
    layout: DataLayout,
    root: i64,
    alice: i64,
    /// A full-scope app password of `root`.
    root_device: String,
}

async fn add_user(pool: &db::Pool, layout: &DataLayout, name: &str, pw: &str, admin: bool) -> i64 {
    let username = Username::new(name).unwrap();
    let hash = password::hash(&SecretString::from(pw.to_owned())).unwrap();
    users::create(
        pool,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: &hash,
            is_admin: admin,
        },
        |id| layout.create_user(id),
    )
    .await
    .unwrap()
}

async fn fixture() -> Fixture {
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
    let root = add_user(&pool, &layout, "root", ROOT_PASSWORD, true).await;
    let alice = add_user(&pool, &layout, "alice", ALICE_PASSWORD, false).await;
    let (_, device) = app_passwords::create(&pool, root, "laptop", Vec::new(), None)
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
        gono_core::locks::LockStore::new(pool.clone()),
    );
    let limiter = Arc::new(RateLimiter::new());
    let base_url = Url::parse("https://cloud.example.com").unwrap();
    let info = ServerInfo {
        started_at: db::unix_now() - 3600,
        instance_id: dav.fs().instance_id().to_owned(),
        bind: "127.0.0.1:16102".parse().unwrap(),
        trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
        config_path: dir.path().join("config.toml"),
        log: "info → stdout".into(),
        data_dir: layout.root().to_path_buf(),
        db_path: config.path.clone(),
        case_insensitive: Some(false),
        lock_timeout_secs: 3600,
        push: None,
        warnings: vec!["a <b>warning</b>".into()],
    };
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
        admin: Some(Arc::new(Admin::new(PREFIX, info))),
    };
    Fixture {
        _dir: dir,
        state,
        layout,
        root,
        alice,
        root_device: device.expose_secret().to_owned(),
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> &str {
        self.headers
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn has_password_input(&self) -> bool {
        self.body.contains("type=\"password\"")
    }

    /// The first CSRF field of the page.
    fn csrf(&self) -> String {
        let start = self
            .body
            .find("name=\"csrf\" value=\"")
            .expect("csrf field")
            + 19;
        let rest = &self.body[start..];
        rest[..rest.find('"').unwrap()].to_owned()
    }
}

/// A browser: keeps cookies, sends forms.
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

    async fn send(
        &mut self,
        method: &str,
        uri: &str,
        extra: &[(&str, &str)],
        body: String,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(uri);
        if !self.cookies.is_empty() {
            let cookies: Vec<String> = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            request = request.header("Cookie", cookies.join("; "));
        }
        if method == "POST" {
            request = request.header("Content-Type", "application/x-www-form-urlencoded");
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let mut request = request.body(Body::from(body)).unwrap();
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
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    async fn get(&mut self, uri: &str) -> Reply {
        self.send("GET", uri, &[], String::new()).await
    }

    async fn post(&mut self, uri: &str, fields: &[(&str, &str)]) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send("POST", uri, &[], body).await
    }

    async fn sign_in(&mut self, user: &str, password: &str) -> Reply {
        let form = self.get(&format!("{PREFIX}/login")).await;
        let csrf = form.csrf();
        self.post(
            &format!("{PREFIX}/login"),
            &[("csrf", &csrf), ("user", user), ("password", password)],
        )
        .await
    }

    /// Signs in as `root` and returns the session's CSRF token.
    async fn root(&mut self) -> String {
        let reply = self.sign_in("root", ROOT_PASSWORD).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        self.get(&format!("{PREFIX}/")).await.csrf()
    }
}

fn path(rest: &str) -> String {
    format!("{PREFIX}{rest}")
}

#[tokio::test]
async fn only_admins_sign_in_and_only_with_the_web_password() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);

    let anonymous = browser.get(&path("/")).await;
    assert_eq!(anonymous.status, StatusCode::SEE_OTHER);
    assert_eq!(anonymous.location(), path("/login"));
    assert_eq!(
        browser.get(PREFIX).await.location(),
        path("/"),
        "the bare prefix redirects"
    );

    // App passwords are ignored as Basic credentials and refused at the form.
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("root:{}", f.root_device)
        )
    );
    let with_basic = browser
        .send(
            "GET",
            &path("/"),
            &[("Authorization", &basic)],
            String::new(),
        )
        .await;
    assert_eq!(with_basic.location(), path("/login"));
    let device = browser.sign_in("root", &f.root_device).await;
    assert_eq!(device.status, StatusCode::FORBIDDEN);
    assert!(device.body.contains("Wrong username or password"));
    assert!(!browser.cookies.contains_key("gono_session"));

    // A non-admin's correct password does not open the admin UI.
    let alice = browser.sign_in("alice", ALICE_PASSWORD).await;
    assert_eq!(alice.status, StatusCode::FORBIDDEN);
    assert!(
        alice.body.contains("not an administrator"),
        "{}",
        alice.body
    );
    assert!(!browser.cookies.contains_key("gono_session"));

    let root = browser.sign_in("root", ROOT_PASSWORD).await;
    assert_eq!(root.status, StatusCode::SEE_OTHER);
    assert_eq!(root.location(), path("/"));
    let overview = browser.get(&path("/")).await;
    assert_eq!(overview.status, StatusCode::OK);
    assert!(!overview.has_password_input());
    assert!(overview.body.contains("cloud.example.com"));
    assert!(
        overview.body.contains("a &#60;b&#62;warning&#60;/b&#62;"),
        "escaped"
    );

    let csrf = overview.csrf();
    let out = browser.post(&path("/logout"), &[("csrf", &csrf)]).await;
    assert_eq!(out.location(), path("/login"));
    assert_eq!(browser.get(&path("/")).await.location(), path("/login"));
}

#[tokio::test]
async fn non_admin_sessions_are_refused() {
    let f = fixture().await;
    let token = web_sessions::create(&f.state.db, f.alice, db::unix_now())
        .await
        .unwrap();
    let mut browser = Browser::new(&f.state);
    browser
        .cookies
        .insert("gono_session".into(), token.expose_secret().to_owned());
    let page = browser.get(&path("/users")).await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(page.body.contains("Not an administrator"));
    let csrf = page.csrf();
    let out = browser.post(&path("/logout"), &[("csrf", &csrf)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    assert!(
        web_sessions::lookup(&f.state.db, token.expose_secret(), db::unix_now())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn pages_have_unique_ids_and_the_security_headers() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let login = browser.get(&path("/login")).await;
    let mut pages = vec![("/login".to_owned(), login)];
    browser.root().await;
    for page in [
        "/",
        "/users",
        "/new-user",
        "/users/root",
        "/users/alice",
        "/users/alice/delete",
        "/users/nobody",
        "/created",
    ] {
        pages.push((page.to_owned(), browser.get(&path(page)).await));
    }
    for (page, reply) in &pages {
        assert!(
            reply.status.is_success() || reply.status.is_client_error(),
            "{page}: {}",
            reply.status
        );
        let ids = web::element_ids(&reply.body);
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "{page}: duplicate ids in {ids:?}");
        let csp = reply.header("content-security-policy");
        assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("script-src"), "{page}: {csp}");
        assert_eq!(reply.header("x-frame-options"), "DENY", "{page}");
        assert_eq!(reply.header("cache-control"), "no-store", "{page}");
        assert!(!reply.body.contains("<script"), "{page}");
    }
}

#[tokio::test]
async fn forms_need_the_session_csrf_token_and_this_origin() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let fields = [
        ("username", "mallory"),
        ("password", "long enough"),
        ("password_repeat", "long enough"),
    ];
    let missing = browser.post(&path("/users"), &fields).await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN);
    let mut with_token = fields.to_vec();
    with_token.push(("csrf", &csrf));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&with_token)
        .finish();
    let foreign = browser
        .send(
            "POST",
            &path("/users"),
            &[("Origin", "https://evil.example")],
            body,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    let username = Username::new("mallory").unwrap();
    assert!(users::find(&f.state.db, &username).await.unwrap().is_none());
}

#[tokio::test]
async fn accounts_are_created_changed_and_deleted_with_redirects() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let create = |name: &'static str, repeat: &'static str| {
        vec![
            ("csrf", csrf.clone()),
            ("username", name.to_owned()),
            ("display_name", "Carol C.".to_owned()),
            ("password", "carol's password".to_owned()),
            ("password_repeat", repeat.to_owned()),
        ]
    };
    let as_refs = |fields: &[(&'static str, String)]| {
        fields
            .iter()
            .map(|(name, value)| (*name, value.clone()))
            .collect::<Vec<_>>()
    };

    let mismatch = create("carol", "something else");
    let reply = browser
        .post(&path("/users"), &pairs(&as_refs(&mismatch)))
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(reply.body.contains("do not match"));
    assert!(
        reply.body.contains("value=\"carol\""),
        "the form keeps its values"
    );

    let fields = create("carol", "carol's password");
    let created = browser
        .post(&path("/users"), &pairs(&as_refs(&fields)))
        .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
    assert_eq!(created.location(), path("/users/carol?done=created"));
    let page = browser.get(created.location()).await;
    assert!(page.body.contains("User carol was created."));
    let again = browser
        .post(&path("/users"), &pairs(&as_refs(&fields)))
        .await;
    assert_eq!(again.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(again.body.contains("already exists"));
    let carol = users::find(&f.state.db, &Username::new("carol").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(carol.display_name, "Carol C.");
    assert!(!carol.is_admin);
    assert!(f.layout.user_files(carol.id).is_dir());

    // Disabling ends the account's browser sessions.
    let session = web_sessions::create(&f.state.db, carol.id, db::unix_now())
        .await
        .unwrap();
    let disabled = browser
        .post(&path("/users/carol/disable"), &[("csrf", &csrf)])
        .await;
    assert_eq!(disabled.location(), path("/users/carol?done=disabled"));
    assert!(
        !users::get(&f.state.db, &carol.username)
            .await
            .unwrap()
            .enabled
    );
    assert!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM web_sessions WHERE user_id = ?1")
            .bind(carol.id)
            .fetch_one(&f.state.db)
            .await
            .unwrap()
            == 0,
        "{:?}",
        session.expose_secret().len()
    );
    let enabled = browser
        .post(&path("/users/carol/enable"), &[("csrf", &csrf)])
        .await;
    assert_eq!(enabled.location(), path("/users/carol?done=enabled"));

    // Setting the password signs the user out elsewhere.
    let session = web_sessions::create(&f.state.db, carol.id, db::unix_now())
        .await
        .unwrap();
    let short = browser
        .post(
            &path("/users/carol/password"),
            &[
                ("csrf", &csrf),
                ("password", "short"),
                ("password_repeat", "short"),
            ],
        )
        .await;
    assert_eq!(short.status, StatusCode::UNPROCESSABLE_ENTITY);
    let set = browser
        .post(
            &path("/users/carol/password"),
            &[
                ("csrf", &csrf),
                ("password", "a new password"),
                ("password_repeat", "a new password"),
            ],
        )
        .await;
    assert_eq!(set.location(), path("/users/carol?done=password"));
    assert!(
        web_sessions::lookup(&f.state.db, session.expose_secret(), db::unix_now())
            .await
            .unwrap()
            .is_none()
    );
    let (_, hash) = users::credentials(&f.state.db, &carol.username)
        .await
        .unwrap()
        .unwrap();
    assert!(password::verify(&SecretString::from("a new password".to_owned()), &hash).unwrap());

    // Deleting asks first and moves the files away.
    let confirm = browser.get(&path("/users/carol/delete")).await;
    assert_eq!(confirm.status, StatusCode::OK);
    assert!(confirm.body.contains("Delete carol?"));
    let deleted = browser
        .post(&path("/users/carol/delete"), &[("csrf", &csrf)])
        .await;
    assert_eq!(deleted.location(), path("/users?done=deleted"));
    assert!(
        users::find(&f.state.db, &carol.username)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!f.layout.user_files(carol.id).exists());
    assert_eq!(
        std::fs::read_dir(f.layout.deleted_root()).unwrap().count(),
        1
    );
    let list = browser.get(deleted.location()).await;
    assert!(list.body.contains("The user was deleted."));
}

fn pairs<'a>(fields: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    fields
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

#[tokio::test]
async fn admins_cannot_lock_themselves_out() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;
    let disable = browser
        .post(&path("/users/root/disable"), &[("csrf", &csrf)])
        .await;
    assert_eq!(disable.status, StatusCode::CONFLICT);
    assert!(disable.body.contains("signed in with"));
    let delete = browser
        .post(&path("/users/root/delete"), &[("csrf", &csrf)])
        .await;
    assert_eq!(delete.status, StatusCode::CONFLICT);
    let root = users::get(&f.state.db, &Username::new("root").unwrap())
        .await
        .unwrap();
    assert!(root.enabled);
    assert_eq!(root.id, f.root);

    // Two admins disabling each other at the same moment: one of them stays.
    let ops = add_user(&f.state.db, &f.layout, "ops", "ops password", true).await;
    let mut other = Browser::new(&f.state);
    let reply = other.sign_in("ops", "ops password").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let other_csrf = other.get(&path("/")).await.csrf();
    let (ops_url, root_url) = (path("/users/ops/disable"), path("/users/root/disable"));
    let (root_fields, ops_fields) = ([("csrf", csrf.as_str())], [("csrf", other_csrf.as_str())]);
    let (first, second) = tokio::join!(
        browser.post(&ops_url, &root_fields),
        other.post(&root_url, &ops_fields)
    );
    let enabled_admins: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND enabled = 1")
            .fetch_one(&f.state.db)
            .await
            .unwrap();
    assert_eq!(
        enabled_admins, 1,
        "{} / {} (ops = {ops})",
        first.status, second.status
    );
}

#[tokio::test]
async fn app_passwords_are_created_shown_once_and_revoked() {
    let f = fixture().await;
    let mut browser = Browser::new(&f.state);
    let csrf = browser.root().await;

    let nested = browser
        .post(
            &path("/users/alice/app-passwords"),
            &[
                ("csrf", &csrf),
                ("label", "scanner"),
                ("access", "custom"),
                ("mount_1", "/a"),
                ("storage_1", "/x"),
                ("mount_2", "/a/b"),
                ("storage_2", "/y"),
            ],
        )
        .await;
    assert_eq!(nested.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(nested.body.contains("overlap"), "{}", nested.body);
    assert!(
        nested.body.contains("value=\"scanner\""),
        "the form keeps its values"
    );

    let created = browser
        .post(
            &path("/users/alice/app-passwords"),
            &[
                ("csrf", &csrf),
                ("label", "scanner"),
                ("expires_in_days", "30"),
                ("access", "custom"),
                ("mount_1", "/Inbox"),
                ("storage_1", "/Scans/Inbox"),
                ("perm_1", "full"),
                ("mount_2", "/Archive"),
                ("storage_2", "/Scans/Archive"),
                ("perm_2", "view"),
            ],
        )
        .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER, "{}", created.body);
    assert_eq!(created.location(), path("/created"));
    assert!(!created.location().contains('?'), "no secret in the URL");

    let shown = browser.get(&path("/created")).await;
    assert_eq!(shown.status, StatusCode::OK);
    assert_eq!(shown.header("cache-control"), "no-store");
    let start = shown.body.find("<div class=\"secret\">").unwrap() + 20;
    let token = shown.body[start..start + 29].to_owned();
    let device = app_passwords::authenticate(
        &f.state.db,
        "alice",
        &SecretString::from(token.clone()),
        db::unix_now(),
    )
    .await
    .unwrap()
    .expect("the shown token authenticates alice");
    assert_eq!(
        device.scopes,
        [
            Scope {
                mount_path: RelPath::parse("Archive").unwrap(),
                storage_path: RelPath::parse("Scans/Archive").unwrap(),
                permission: gono_core::Permission::View,
            },
            Scope {
                mount_path: RelPath::parse("Inbox").unwrap(),
                storage_path: RelPath::parse("Scans/Inbox").unwrap(),
                permission: gono_core::Permission::Full,
            },
        ]
    );
    let again = browser.get(&path("/created")).await;
    assert_eq!(again.status, StatusCode::GONE);
    assert!(!again.body.contains(&token));

    // Another admin's session never sees it either.
    let listed = app_passwords::list(&f.state.db, f.alice).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].expires_at.is_some());
    let page = browser.get(&path("/users/alice")).await;
    assert!(page.body.contains("scanner"));
    assert!(!page.body.contains(&token));

    let revoke = browser
        .post(
            &path(&format!(
                "/users/alice/app-passwords/{}/delete",
                listed[0].id
            )),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(revoke.location(), path("/users/alice?done=revoked"));
    assert!(
        app_passwords::list(&f.state.db, f.alice)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_admin_ui_is_not_served_when_disabled() {
    let mut f = fixture().await;
    f.state.admin = None;
    let mut browser = Browser::new(&f.state);
    assert_eq!(browser.get(&path("/")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        browser.get(&path("/login")).await.status,
        StatusCode::NOT_FOUND
    );
}
