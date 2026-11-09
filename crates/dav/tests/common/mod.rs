//! Test harness: a real data directory and database behind dav-server's `DavHandler<Ctx>`.

#![allow(dead_code)]

use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use dav_server::{DavHandler, ls::DavLockSystem};
use gono_core::{
    RelPath, Username,
    config::DbConfig,
    db::{self, OpenMode, Pool},
    meta::MetaStore,
    settings,
    storage::DataLayout,
    users::{self, NewUser},
};
use gono_dav::{Ctx, Identity, Mount, PropfindKind, RequestInfo, ScopedFs, metadata::Entry};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};

pub const PROPFIND_ALL_LIVE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <d:prop>
    <d:getetag/><d:getcontentlength/><d:resourcetype/><d:getlastmodified/>
    <oc:fileid/><oc:id/><oc:permissions/><oc:favorite/><oc:size/><nc:has-preview/>
  </d:prop>
</d:propfind>"#;

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub pool: Pool,
    pub layout: DataLayout,
    pub fs: ScopedFs,
    pub handler: DavHandler<Ctx>,
    pub owner: i64,
    pub instance_id: String,
}

pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub outcome: Option<Arc<Entry>>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    #[track_caller]
    pub fn expect(&self, status: u16) -> &Self {
        assert_eq!(self.status.as_u16(), status, "{}", self.text());
        self
    }

    /// Parses a 207 multistatus: href -> (`{ns}name` -> (status, text)).
    #[track_caller]
    pub fn multistatus(&self) -> HashMap<String, HashMap<String, (u16, String)>> {
        self.expect(207);
        let root = xmltree::Element::parse(self.body.as_ref()).expect("multistatus XML");
        let mut responses = HashMap::new();
        for response in root.children.iter().filter_map(|n| n.as_element()) {
            let href = response
                .get_child("href")
                .and_then(|href| href.get_text())
                .unwrap()
                .to_string();
            let href = percent_decode(href.trim_end_matches('/'));
            let mut props = HashMap::new();
            for propstat in response
                .children
                .iter()
                .filter_map(|n| n.as_element())
                .filter(|e| e.name == "propstat")
            {
                let status = propstat
                    .get_child("status")
                    .and_then(|s| s.get_text())
                    .and_then(|s| s.split_whitespace().nth(1).map(str::to_owned))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if let Some(prop) = propstat.get_child("prop") {
                    for element in prop.children.iter().filter_map(|n| n.as_element()) {
                        let key = format!(
                            "{{{}}}{}",
                            element.namespace.clone().unwrap_or_default(),
                            element.name
                        );
                        let text =
                            element
                                .get_text()
                                .map(|t| t.into_owned())
                                .unwrap_or_else(|| {
                                    element
                                        .children
                                        .iter()
                                        .filter_map(|n| n.as_element())
                                        .map(|e| e.name.clone())
                                        .collect::<Vec<_>>()
                                        .join(",")
                                });
                        props.insert(key, (status, text));
                    }
                }
            }
            responses.insert(href, props);
        }
        responses
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

pub fn oc(name: &str) -> String {
    format!("{{http://owncloud.org/ns}}{name}")
}

pub fn nc(name: &str) -> String {
    format!("{{http://nextcloud.org/ns}}{name}")
}

pub fn dav(name: &str) -> String {
    format!("{{DAV:}}{name}")
}

pub fn mount(mount: &str, storage: &str, writable: bool) -> Mount {
    Mount {
        mount_path: RelPath::parse(mount).unwrap(),
        storage_path: RelPath::parse(storage).unwrap(),
        writable,
    }
}

impl Harness {
    pub async fn new() -> Self {
        Self::with_locks(None).await
    }

    pub async fn with_locks(locks: Option<Box<dyn DavLockSystem>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(dir.path().join("data"));
        layout.create().unwrap();
        let config = DbConfig {
            path: dir.path().join("gono-cloud.db"),
            max_connections: 4,
            busy_timeout_secs: 5,
        };
        let pool = db::connect(&config, OpenMode::CreateIfMissing)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let username = Username::new("alice").unwrap();
        let owner = users::create(
            &pool,
            &NewUser {
                username: &username,
                display_name: "Alice",
                password_hash: "x",
                is_admin: false,
            },
            |id| layout.create_user(id),
        )
        .await
        .unwrap();
        let instance_id = settings::instance_id(&pool).await.unwrap();
        let fs = ScopedFs::new(
            layout.clone(),
            MetaStore::new(pool.clone()),
            instance_id.clone(),
        );
        let mut builder = DavHandler::builder().filesystem(Box::new(fs.clone()));
        if let Some(locks) = locks {
            builder = builder.locksystem(locks);
        }
        Self {
            dir,
            pool,
            layout,
            fs,
            handler: builder.build_handler(),
            owner,
            instance_id,
        }
    }

    pub fn identity(&self, mounts: Vec<Mount>) -> Arc<Identity> {
        Arc::new(Identity {
            user_id: self.owner,
            username: Username::new("alice").unwrap(),
            display_name: "Alice".into(),
            app_password_id: 1,
            mounts,
        })
    }

    pub fn full(&self) -> Arc<Identity> {
        self.identity(vec![mount("/", "/", true)])
    }

    pub fn view(&self) -> Arc<Identity> {
        self.identity(vec![mount("/", "/", false)])
    }

    /// Path on disk of a storage path of the test user.
    pub fn disk(&self, rel: &str) -> std::path::PathBuf {
        RelPath::parse(rel)
            .unwrap()
            .to_fs_path(&self.layout.user_files(self.owner))
    }

    pub fn url(rel: &str) -> String {
        format!("/remote.php/dav/files/alice/{rel}")
    }

    pub async fn send(
        &self,
        identity: &Arc<Identity>,
        method: &str,
        rel: &str,
        headers: &[(&str, &str)],
        body: impl Into<Bytes>,
    ) -> Response {
        let body: Bytes = body.into();
        let mut request = Request::builder()
            .method(http::Method::from_bytes(method.as_bytes()).unwrap())
            .uri(Self::url(rel));
        if matches!(method, "PUT" | "PATCH") {
            // As every real client does; dav-server refuses PATCH without it.
            request = request.header("Content-Length", body.len().to_string());
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(Full::new(body.clone())).unwrap();
        let (parts, body_full) = request.into_parts();
        let mut info = RequestInfo::from_parts(&parts);
        if method == "PROPFIND" {
            info.propfind = PropfindKind::of_body(&body);
        }
        let ctx = Ctx::new(identity.clone(), info);
        let request = Request::from_parts(parts, body_full);
        let response = self
            .handler
            .handle_guarded(request, identity.username.to_string(), ctx.clone())
            .await;
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        Response {
            status: parts.status,
            headers: parts.headers,
            body,
            outcome: ctx.outcome(),
        }
    }

    pub async fn put(&self, identity: &Arc<Identity>, rel: &str, body: &str) -> Response {
        self.send(identity, "PUT", rel, &[], body.to_owned()).await
    }

    pub async fn mkcol(&self, identity: &Arc<Identity>, rel: &str) -> Response {
        self.send(identity, "MKCOL", rel, &[], Bytes::new()).await
    }

    pub async fn propfind(&self, identity: &Arc<Identity>, rel: &str, depth: &str) -> Response {
        self.send(
            identity,
            "PROPFIND",
            rel,
            &[("Depth", depth)],
            PROPFIND_ALL_LIVE.to_owned(),
        )
        .await
    }

    /// Props of one entry from a Depth 0 PROPFIND.
    pub async fn props(
        &self,
        identity: &Arc<Identity>,
        rel: &str,
    ) -> HashMap<String, (u16, String)> {
        let response = self.propfind(identity, rel, "0").await;
        let mut all = response.multistatus();
        let href = Self::url(rel).trim_end_matches('/').to_owned();
        all.remove(&href)
            .unwrap_or_else(|| panic!("no entry for {href} in {:?}", all.keys()))
    }

    pub async fn prop(&self, identity: &Arc<Identity>, rel: &str, key: &str) -> Option<String> {
        self.props(identity, rel)
            .await
            .remove(key)
            .filter(|(status, _)| *status == 200)
            .map(|(_, text)| text)
    }

    pub async fn change_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM change_log")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}
