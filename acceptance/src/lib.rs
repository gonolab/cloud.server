//! Black-box HTTP acceptance tests for Gono Cloud.
//!
//! The suite only needs a server URL and credentials, passed through `GONO_ACCEPT_*` environment
//! variables (see `README.md`). Every test that writes data works inside its own randomly named
//! directory and removes it again when it ends, even when it fails.

pub mod dav;
pub mod push;
pub mod raw;
pub mod web;
pub mod xml;

use std::{
    io::Write as _,
    sync::{Arc, Mutex},
    time::Duration,
};

use reqwest::StatusCode;

pub use dav::{Dav, Resp, normalize_etag};
pub use xml::{DAV, NC, OC};

/// A username and password pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cred {
    pub user: String,
    pub password: String,
}

impl Cred {
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Cred {
        Cred {
            user: user.into(),
            password: password.into(),
        }
    }
}

/// Suite configuration read from the environment.
#[derive(Debug, Clone)]
pub struct Config {
    /// Public server origin without trailing slash, e.g. `https://cloud.example.com`.
    pub base_url: String,
    /// Full-scope device credential mounted at `/`.
    pub full: Cred,
    /// Read-only (`view`) app password of the same user, mounted at `/`.
    pub view_password: Option<String>,
    /// App password of the same user with `/acc-view` (view) and `/acc-full` (full) mounts.
    pub scoped_password: Option<String>,
    /// The user's web login password (Login Flow v2, web admin UI).
    pub web_password: Option<String>,
    /// Web admin UI path, e.g. `/apps/manage`.
    pub admin_path: String,
    /// A second, unrelated user with a full-scope device credential.
    pub user2: Option<Cred>,
    /// How long to wait for a notify_push message.
    pub push_timeout: Duration,
}

/// Mount layout expected for `GONO_ACCEPT_SCOPED_PASSWORD`.
pub const SCOPED_VIEW_MOUNT: &str = "acc-view";
pub const SCOPED_VIEW_STORAGE: &str = "acc-scope/view";
pub const SCOPED_FULL_MOUNT: &str = "acc-full";
pub const SCOPED_FULL_STORAGE: &str = "acc-scope/full";

fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

impl Config {
    /// Reads the configuration, or explains which required variable is missing.
    pub fn from_env() -> Result<Config, String> {
        let base_url = env_var("GONO_ACCEPT_BASE_URL")
            .ok_or("GONO_ACCEPT_BASE_URL is not set; the acceptance suite is skipped")?;
        let user = env_var("GONO_ACCEPT_USER").ok_or("GONO_ACCEPT_USER is not set")?;
        let password = env_var("GONO_ACCEPT_PASSWORD").ok_or("GONO_ACCEPT_PASSWORD is not set")?;
        let user2 = match (
            env_var("GONO_ACCEPT_USER2"),
            env_var("GONO_ACCEPT_PASSWORD2"),
        ) {
            (Some(user), Some(password)) => Some(Cred::new(user, password)),
            _ => None,
        };
        let push_timeout = env_var("GONO_ACCEPT_PUSH_TIMEOUT_SECS")
            .map(|value| {
                value
                    .parse::<u64>()
                    .expect("GONO_ACCEPT_PUSH_TIMEOUT_SECS must be a number of seconds")
            })
            .unwrap_or(20);
        let admin_path = env_var("GONO_ACCEPT_ADMIN_PATH").unwrap_or_else(|| "/apps/manage".into());
        Ok(Config {
            base_url: base_url.trim_end_matches('/').to_owned(),
            full: Cred::new(user, password),
            view_password: env_var("GONO_ACCEPT_VIEW_PASSWORD"),
            scoped_password: env_var("GONO_ACCEPT_SCOPED_PASSWORD"),
            web_password: env_var("GONO_ACCEPT_WEB_PASSWORD"),
            admin_path: format!("/{}", admin_path.trim_matches('/')),
            user2,
            push_timeout: Duration::from_secs(push_timeout),
        })
    }
}

/// Prints a skip notice for the current test. The line goes straight to the process stderr so
/// that libtest's output capture does not hide it.
pub fn skip(reason: &str) {
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("<test>");
    let _ = writeln!(std::io::stderr().lock(), "SKIP {name}: {reason}");
}

/// Prints a non-fatal warning for the current test, bypassing output capture.
pub fn warn(message: &str) {
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("<test>");
    let _ = writeln!(std::io::stderr().lock(), "WARN {name}: {message}");
}

/// Returns early from a test (after printing a skip notice) when the option is `None`.
#[macro_export]
macro_rules! require {
    ($option:expr, $reason:expr) => {
        match $option {
            Some(value) => value,
            None => {
                $crate::skip($reason);
                return;
            }
        }
    };
}

/// Builds the shared HTTP client: no redirects, generous timeout.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(120))
        .user_agent("gono-acceptance (Nextcloud-compatible test client)")
        .build()
        .expect("build HTTP client")
}

/// Per-test context: configuration, clients, and a private working directory.
pub struct Ctx {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    /// The test's working directory relative to the user's files root, e.g. `acc-put-1a2b3c4d`.
    pub dir: String,
    cleanup: Arc<Mutex<Vec<(Cred, String)>>>,
}

impl Ctx {
    /// Loads the configuration and creates the test's working directory. Returns `None` (after
    /// printing a skip notice) when the suite is not configured.
    pub async fn new() -> Option<Ctx> {
        let ctx = Ctx::bare()?;
        let dav = ctx.dav();
        dav.create_dir(&ctx.dir).await;
        ctx.cleanup_later(&ctx.cfg.full, &ctx.dir.clone());
        Some(ctx)
    }

    /// Like [`Ctx::new`] but without creating a working directory.
    pub fn bare() -> Option<Ctx> {
        let cfg = match Config::from_env() {
            Ok(cfg) => cfg,
            Err(reason) => {
                skip(&reason);
                return None;
            }
        };
        Some(Ctx {
            cfg: Arc::new(cfg),
            http: http_client(),
            dir: unique_name("acc"),
            cleanup: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.cfg.base_url
    }

    /// `{base}{path}` for a server-relative path.
    pub fn url(&self, path: &str) -> String {
        format!("{}/{}", self.cfg.base_url, path.trim_start_matches('/'))
    }

    /// WebDAV client for the full-scope credential.
    pub fn dav(&self) -> Dav {
        self.dav_as(&self.cfg.full)
    }

    pub fn dav_as(&self, cred: &Cred) -> Dav {
        Dav::new(self.http.clone(), &self.cfg.base_url, cred.clone())
    }

    /// `<dir>/<rel>`: a path inside the test's working directory.
    pub fn path(&self, rel: &str) -> String {
        if rel.is_empty() {
            self.dir.clone()
        } else {
            format!("{}/{}", self.dir, rel.trim_start_matches('/'))
        }
    }

    pub fn view(&self) -> Option<Cred> {
        self.cfg
            .view_password
            .as_ref()
            .map(|password| Cred::new(&self.cfg.full.user, password))
    }

    pub fn scoped(&self) -> Option<Cred> {
        self.cfg
            .scoped_password
            .as_ref()
            .map(|password| Cred::new(&self.cfg.full.user, password))
    }

    pub fn web(&self) -> Option<Cred> {
        self.cfg
            .web_password
            .as_ref()
            .map(|password| Cred::new(&self.cfg.full.user, password))
    }

    pub fn user2(&self) -> Option<Cred> {
        self.cfg.user2.clone()
    }

    /// Registers a path (relative to `cred`'s files root) to delete when the test ends.
    pub fn cleanup_later(&self, cred: &Cred, rel: &str) {
        self.cleanup
            .lock()
            .expect("cleanup list")
            .push((cred.clone(), rel.to_owned()));
    }

    /// GET an OCS endpoint the way the Nextcloud clients do (JSON, `OCS-APIRequest`).
    pub async fn ocs(&self, method: &str, path: &str, cred: Option<&Cred>) -> Resp {
        let separator = if path.contains('?') { '&' } else { '?' };
        let url = self.url(&format!("{path}{separator}format=json"));
        let mut request = self
            .http
            .request(dav::method(method), url)
            .header("OCS-APIRequest", "true")
            .header("Accept", "application/json");
        if let Some(cred) = cred {
            request = request.basic_auth(&cred.user, Some(&cred.password));
        }
        dav::send(&self.http, request).await
    }

    /// The public capabilities document (`ocs.data.capabilities`).
    pub async fn capabilities(&self) -> serde_json::Value {
        let response = self
            .ocs("GET", "/ocs/v2.php/cloud/capabilities", None)
            .await;
        response.expect(&[200]);
        response.json()["ocs"]["data"]["capabilities"].clone()
    }

    /// The notify_push WebSocket URL advertised in the capabilities.
    pub async fn push_websocket_url(&self) -> String {
        let capabilities = self.capabilities().await;
        capabilities["notify_push"]["endpoints"]["websocket"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "capabilities do not advertise notify_push.endpoints.websocket: {capabilities}"
                )
            })
            .to_owned()
    }

    /// Detects whether the server's storage distinguishes `Name` from `name`.
    pub async fn storage_is_case_sensitive(&self) -> bool {
        let dav = self.dav();
        dav.write(&self.path("CaseProbe.txt"), "upper").await;
        let lower = dav.get(&self.path("caseprobe.txt")).await;
        match lower.code() {
            404 => true,
            200 => false,
            _ => panic!("unexpected case probe response\n{}", lower.describe()),
        }
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        let mut entries = std::mem::take(&mut *self.cleanup.lock().expect("cleanup list"));
        if entries.is_empty() {
            return;
        }
        entries.reverse();
        let base_url = self.cfg.base_url.clone();
        // Drop runs inside the async test runtime (possibly while unwinding), so the cleanup
        // requests use a blocking client on a separate thread.
        let worker = std::thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("build cleanup client");
            for (cred, rel) in entries {
                let dav = Dav::new(reqwest::Client::new(), &base_url, cred.clone());
                let url = dav.url(&rel);
                let result = client
                    .delete(&url)
                    .basic_auth(&cred.user, Some(&cred.password))
                    .send();
                match result {
                    Ok(response)
                        if response.status().is_success()
                            || response.status() == StatusCode::NOT_FOUND => {}
                    Ok(response) => warn(&format!("cleanup DELETE {url} -> {}", response.status())),
                    Err(err) => warn(&format!("cleanup DELETE {url} failed: {err}")),
                }
            }
        });
        let _ = worker.join();
    }
}

/// A unique, readable name such as `acc-put-get-roundtrip-1a2b3c4d`.
pub fn unique_name(prefix: &str) -> String {
    let thread = std::thread::current();
    let test: String = thread
        .name()
        .unwrap_or("test")
        .rsplit("::")
        .next()
        .unwrap_or("test")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(40)
        .collect();
    let random = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{test}-{}", &random[..8])
}

/// A random token without a test name (for upload ids and similar).
pub fn random_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
