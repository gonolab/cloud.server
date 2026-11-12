//! The configuration file.
//!
//! The configuration is a TOML file (see `config.example.toml` in the repository root). Loading
//! happens in three steps, all performed by [`Config::load`]:
//!
//! 1. **Parse.** Every table uses `deny_unknown_fields`, so a misspelled key is an error instead
//!    of a silently ignored setting.
//! 2. **Resolve paths.** Relative paths are resolved against the directory that contains the
//!    config file, so the result does not depend on the working directory of the process.
//! 3. **Validate.** [`Config::validate`] checks values that the type system cannot express
//!    (loopback-only bind address, the shape of `base_url`, non-zero intervals, ...) and reports
//!    every problem at once.

use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, de::Error as _};
use url::Url;

use crate::error::{ConfigError, ValidationIssue};

/// Default listen address. Loopback only: a reverse proxy terminates HTTPS in front of us.
pub const DEFAULT_BIND: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 16102);

/// Root of the configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[server]`: listener and public origin.
    pub server: ServerConfig,
    /// `[storage]`: where user files live.
    pub storage: StorageConfig,
    /// `[db]`: the SQLite metadata database.
    pub db: DbConfig,
    /// `[webdav]`: WebDAV protocol limits.
    #[serde(default)]
    pub webdav: WebdavConfig,
    /// `[logging]`: log level and destination.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// `[notify_push]`: real-time change notifications.
    #[serde(default)]
    pub notify_push: NotifyPushConfig,
    /// `[admin]`: the web admin UI.
    #[serde(default)]
    pub admin: AdminConfig,
    /// `[files_ui]`: the web file UI.
    #[serde(default)]
    pub files_ui: FilesUiConfig,
}

/// `[server]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address of the plain-HTTP listener, `IP:port`.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,

    /// Allows `bind` to be a non-loopback address, for example inside a container where the
    /// reverse proxy runs in another network namespace.
    #[serde(default)]
    pub allow_non_loopback_bind: bool,

    /// Public origin of the server as clients see it, for example `https://cloud.example.com`.
    ///
    /// Used to build absolute URLs (Login Flow v2, capabilities, `Location` headers). It is
    /// never inferred from request headers.
    pub base_url: Url,

    /// Reverse proxies whose forwarding headers (`X-Forwarded-For`, `Forwarded`) are trusted.
    ///
    /// Each entry is an IP address or a CIDR block. Requests from any other peer are attributed
    /// to the peer address and their forwarding headers are ignored.
    #[serde(default, deserialize_with = "deserialize_networks")]
    pub trusted_proxies: Vec<IpNet>,
}

/// `[storage]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Directory that holds user files. It belongs to the server; changes made behind its back
    /// are only picked up by `gono-cloud rescan`.
    pub data_dir: PathBuf,
}

/// `[db]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbConfig {
    /// Path of the SQLite database file.
    pub path: PathBuf,

    /// Upper bound of the connection pool.
    #[serde(default = "default_db_max_connections")]
    pub max_connections: u32,

    /// How long a connection waits for a competing writer before giving up, in seconds.
    #[serde(default = "default_db_busy_timeout_secs")]
    pub busy_timeout_secs: u64,
}

/// Highest accepted value of `db.max_connections`. SQLite serializes writers anyway; a large
/// pool only adds contention.
pub const MAX_DB_CONNECTIONS: u32 = 64;

/// `[webdav]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebdavConfig {
    /// Longest lifetime of a WebDAV lock, in seconds. Requests for longer locks, including
    /// `Timeout: Infinite`, are clamped to it, so locks of vanished clients always expire.
    pub max_lock_timeout_secs: u64,
}

impl Default for WebdavConfig {
    fn default() -> Self {
        Self {
            max_lock_timeout_secs: 3600,
        }
    }
}

/// Highest accepted value of `webdav.max_lock_timeout_secs` (one week).
pub const MAX_LOCK_TIMEOUT_SECS: u64 = 7 * 24 * 3600;

/// `[logging]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum level of Gono Cloud's own log events. Dependencies log at `warn` and above.
    pub level: LogLevel,

    /// Log file to append to. When unset, `serve` logs to stdout.
    pub file: Option<PathBuf>,
}

/// Log level accepted by `logging.level`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Normal operational messages.
    #[default]
    Info,
    /// Verbose diagnostics.
    Debug,
    /// Everything.
    Trace,
}

impl LogLevel {
    /// Name as used in `tracing` filter directives.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// `[notify_push]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyPushConfig {
    /// Advertise and serve the notify_push WebSocket endpoint.
    pub enabled: bool,

    /// Interval between WebSocket pings, in seconds. A connection that has sent nothing (not
    /// even the pong) by the next ping is closed, and every ping also re-checks that the
    /// connection's app password is still valid.
    pub ping_interval_secs: u64,

    /// Time a freshly opened WebSocket has to authenticate, in seconds.
    pub auth_timeout_secs: u64,

    /// Lifetime of a pre-auth token handed out by the pre-auth endpoint, in seconds.
    pub pre_auth_ttl_secs: u64,

    /// Debounce interval of change notifications, in seconds: two notifications of the same
    /// kind on one connection are at least this far apart, every change in between is merged
    /// into the next one, and no change waits longer than this before it is announced.
    pub debounce_secs: u64,

    /// Maximum number of concurrent WebSocket connections per user.
    pub max_connections_per_user: u32,
}

impl Default for NotifyPushConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ping_interval_secs: 30,
            auth_timeout_secs: 15,
            pre_auth_ttl_secs: 15,
            debounce_secs: 5,
            max_connections_per_user: 64,
        }
    }
}

/// `[admin]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Serve the web admin UI. Admins sign in with their web login password; app passwords
    /// cannot access it.
    pub enabled: bool,

    /// URL path of the admin UI, for example `/apps/manage`.
    pub path: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: DEFAULT_ADMIN_PATH.to_owned(),
        }
    }
}

/// `[files_ui]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesUiConfig {
    /// Serve the web file UI at `/apps/files/`, with the sign-in page at `/login` and the
    /// account page at `/apps/account/`. Users sign in with their web login password; app
    /// passwords cannot access it.
    pub enabled: bool,
}

impl Default for FilesUiConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Default of `admin.path`, next to the web file UI (`/apps/files/`) and the account page
/// (`/apps/account/`).
pub const DEFAULT_ADMIN_PATH: &str = "/apps/manage";

/// First path segments the server uses itself; `admin.path` must not start with one of them,
/// except that it may be [`DEFAULT_ADMIN_PATH`].
const RESERVED_SEGMENTS: &[&str] = &[
    "204",
    "apps",
    "healthz",
    "index.php",
    "login",
    "ocs",
    "push",
    "remote.php",
    "status.php",
];

/// `admin.path` is `/` followed by one or more segments of unreserved URL characters, without a
/// trailing slash, and outside the paths the server serves itself. The default lies below
/// `/apps`, which is otherwise reserved: the server serves nothing else under `/apps/manage`.
fn check_admin_path(path: &str) -> Result<(), String> {
    if path == DEFAULT_ADMIN_PATH {
        return Ok(());
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err("must start with '/'".to_owned());
    };
    if rest.is_empty() || rest.ends_with('/') {
        return Err("must name a path below '/' without a trailing slash".to_owned());
    }
    for segment in rest.split('/') {
        let valid = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        if !valid {
            return Err(format!(
                "segment {segment:?} must consist of letters, digits, '-', '.', '_' and '~'"
            ));
        }
    }
    let first = rest.split('/').next().unwrap_or_default();
    if RESERVED_SEGMENTS
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(first))
    {
        return Err(format!("/{first} is used by the server itself"));
    }
    Ok(())
}

const fn default_bind() -> SocketAddr {
    DEFAULT_BIND
}

const fn default_db_max_connections() -> u32 {
    8
}

const fn default_db_busy_timeout_secs() -> u64 {
    5
}

/// Accepts both bare IP addresses (`"10.0.0.1"`, treated as a single host) and CIDR blocks
/// (`"10.0.0.0/8"`).
fn deserialize_networks<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<IpNet>, D::Error> {
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|entry| parse_network(entry).map_err(D::Error::custom))
        .collect()
}

/// Parses an IP address or CIDR block. A bare address becomes a host-sized network (`/32` or
/// `/128`).
pub fn parse_network(entry: &str) -> Result<IpNet, String> {
    let entry = entry.trim();
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    entry
        .parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| format!("{entry:?} is neither an IP address nor a CIDR block"))
}

impl Config {
    /// Reads, parses and validates the config file at `path`.
    ///
    /// Relative paths inside the file are resolved against the directory containing it.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let read_error = |source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        };
        let raw = fs::read_to_string(path).map_err(read_error)?;
        let mut config = Self::from_toml(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;

        let absolute = std::path::absolute(path).map_err(read_error)?;
        if let Some(base_dir) = absolute.parent() {
            config.resolve_relative_paths(base_dir);
        }

        config.validate()?;
        Ok(config)
    }

    /// Parses a config document without resolving paths or validating values.
    ///
    /// Prefer [`Config::load`]; this exists for tests and tooling.
    pub fn from_toml(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }

    /// Makes every relative path absolute by joining it onto `base_dir`.
    ///
    /// Empty paths are left alone so that [`Config::validate`] can reject them.
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        let resolve = |path: &mut PathBuf| {
            if !path.as_os_str().is_empty() && path.is_relative() {
                *path = base_dir.join(&*path);
            }
        };
        resolve(&mut self.storage.data_dir);
        resolve(&mut self.db.path);
        if let Some(file) = self.logging.file.as_mut() {
            resolve(file);
        }
    }

    /// Checks every value that parsing alone cannot guarantee.
    ///
    /// All problems are collected and returned together in [`ConfigError::Invalid`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut issues = Vec::new();
        let mut reject = |key: &'static str, message: String| {
            issues.push(ValidationIssue { key, message });
        };

        // [server]
        let server = &self.server;
        if !server.bind.ip().is_loopback() && !server.allow_non_loopback_bind {
            reject(
                "server.bind",
                format!(
                    "{} is not a loopback address; Gono Cloud serves plain HTTP and expects a \
                     reverse proxy in front of it. Bind to 127.0.0.1 or ::1, or set \
                     server.allow_non_loopback_bind = true if the proxy cannot reach loopback",
                    server.bind.ip()
                ),
            );
        }
        if let Err(message) = check_base_url(&server.base_url) {
            reject("server.base_url", message);
        }
        for net in &server.trusted_proxies {
            if *net != net.trunc() {
                reject(
                    "server.trusted_proxies",
                    format!("{net} has host bits set; did you mean {}?", net.trunc()),
                );
            }
        }

        // [storage]
        if self.storage.data_dir.as_os_str().is_empty() {
            reject("storage.data_dir", "must not be empty".to_owned());
        }

        // [db]
        if self.db.path.as_os_str().is_empty() {
            reject("db.path", "must not be empty".to_owned());
        }
        if !(1..=MAX_DB_CONNECTIONS).contains(&self.db.max_connections) {
            reject(
                "db.max_connections",
                format!("must be between 1 and {MAX_DB_CONNECTIONS}"),
            );
        }
        if self.db.busy_timeout_secs == 0 {
            reject("db.busy_timeout_secs", "must be greater than 0".to_owned());
        }

        // [webdav]
        if !(1..=MAX_LOCK_TIMEOUT_SECS).contains(&self.webdav.max_lock_timeout_secs) {
            reject(
                "webdav.max_lock_timeout_secs",
                format!("must be between 1 and {MAX_LOCK_TIMEOUT_SECS} (one week)"),
            );
        }

        // [logging]
        if self
            .logging
            .file
            .as_ref()
            .is_some_and(|file| file.as_os_str().is_empty())
        {
            reject(
                "logging.file",
                "must not be empty; remove the key to log to stdout".to_owned(),
            );
        }

        // [notify_push]
        let push = &self.notify_push;
        for (key, value) in [
            ("notify_push.ping_interval_secs", push.ping_interval_secs),
            ("notify_push.auth_timeout_secs", push.auth_timeout_secs),
            ("notify_push.pre_auth_ttl_secs", push.pre_auth_ttl_secs),
            ("notify_push.debounce_secs", push.debounce_secs),
            (
                "notify_push.max_connections_per_user",
                u64::from(push.max_connections_per_user),
            ),
        ] {
            if value == 0 {
                reject(key, "must be greater than 0".to_owned());
            }
        }

        // [admin]
        if let Err(message) = check_admin_path(&self.admin.path) {
            reject("admin.path", message);
        }

        if issues.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(issues))
        }
    }

    /// Settings that are valid but probably not what the operator wants in production.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let url = &self.server.base_url;
        if url.scheme() == "http" && !is_local_host(url) {
            warnings.push(format!(
                "server.base_url {url} uses plain http; passwords and app passwords will cross \
                 the network unencrypted"
            ));
        }
        if !self.server.bind.ip().is_loopback() {
            warnings.push(format!(
                "server.bind {} is reachable from outside this host; make sure only the reverse \
                 proxy can connect to it",
                self.server.bind
            ));
        }
        warnings
    }
}

/// `base_url` must be a bare origin: `http(s)://host[:port]` with an optional trailing slash.
fn check_base_url(url: &Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme must be http or https, got {:?}",
            url.scheme()
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("must include a host".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials".to_owned());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not contain a query string or fragment".to_owned());
    }
    if url.path() != "/" {
        return Err(format!(
            "must not contain a path (got {:?}); serving under a sub-path is not supported",
            url.path()
        ));
    }
    Ok(())
}

fn is_local_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [server]
        base_url = "https://cloud.example.com"

        [storage]
        data_dir = "data"

        [db]
        path = "gono-cloud.db"
    "#;

    fn parse(raw: &str) -> Config {
        Config::from_toml(raw).expect("config should parse")
    }

    /// Parses `MINIMAL` with `extra` appended to the `[server]` table.
    fn with_server(extra: &str) -> Config {
        parse(&MINIMAL.replace("[server]\n", &format!("[server]\n{extra}\n")))
    }

    fn issue_keys(config: &Config) -> Vec<&'static str> {
        match config.validate() {
            Ok(()) => Vec::new(),
            Err(ConfigError::Invalid(issues)) => issues.into_iter().map(|i| i.key).collect(),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let config = parse(MINIMAL);
        config.validate().expect("minimal config should be valid");

        assert_eq!(config.server.bind, "127.0.0.1:16102".parse().unwrap());
        assert!(!config.server.allow_non_loopback_bind);
        assert!(config.server.trusted_proxies.is_empty());
        assert_eq!(config.db.max_connections, 8);
        assert_eq!(config.db.busy_timeout_secs, 5);
        assert_eq!(config.webdav.max_lock_timeout_secs, 3600);
        assert_eq!(config.logging.level, LogLevel::Info);
        assert_eq!(config.logging.file, None, "logs go to stdout by default");
        assert!(config.notify_push.enabled);
        assert!(config.admin.enabled);
        assert!(config.files_ui.enabled);
        assert_eq!(config.admin.path, "/apps/manage");
        assert!(config.warnings().is_empty());
    }

    #[test]
    fn required_keys_are_required() {
        for (table, key) in [
            ("server", "base_url"),
            ("storage", "data_dir"),
            ("db", "path"),
        ] {
            let raw: String = MINIMAL
                .lines()
                .filter(|line| !line.trim_start().starts_with(key))
                .collect::<Vec<_>>()
                .join("\n");
            let err = Config::from_toml(&raw).expect_err(key).to_string();
            assert!(err.contains(key), "[{table}] {key}: {err}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        for raw in [
            format!("{MINIMAL}\nunknown = 1"),
            MINIMAL.replace("[server]\n", "[server]\nbase_ulr = \"x\"\n"),
            format!("{MINIMAL}\n[logging]\nloglevel = \"info\""),
            format!("{MINIMAL}\n[notify_push]\npath = \"/push\""),
            format!("{MINIMAL}\n[sync]\nretention_days = 30"),
        ] {
            let err = Config::from_toml(&raw).expect_err(&raw).to_string();
            assert!(err.contains("unknown"), "{err}");
        }
    }

    #[test]
    fn bind_must_be_loopback_unless_allowed() {
        let public = MINIMAL.replace("[server]\n", "[server]\nbind = \"0.0.0.0:16102\"\n");
        assert_eq!(issue_keys(&parse(&public)), ["server.bind"]);

        let allowed = public.replace("[server]\n", "[server]\nallow_non_loopback_bind = true\n");
        let config = parse(&allowed);
        assert!(issue_keys(&config).is_empty());
        assert_eq!(config.warnings().len(), 1);

        for loopback in ["127.0.0.1:8080", "[::1]:8080", "127.0.0.2:0"] {
            let config = with_server(&format!("bind = \"{loopback}\""));
            assert!(issue_keys(&config).is_empty(), "{loopback}");
        }
    }

    #[test]
    fn bind_must_be_a_socket_address() {
        for bind in ["localhost:16102", "127.0.0.1", "16102"] {
            let raw = MINIMAL.replace("[server]\n", &format!("[server]\nbind = \"{bind}\"\n"));
            assert!(Config::from_toml(&raw).is_err(), "{bind}");
        }
    }

    #[test]
    fn base_url_must_be_a_bare_http_origin() {
        for good in [
            "https://cloud.example.com",
            "https://cloud.example.com/",
            "https://cloud.example.com:8443",
            "http://127.0.0.1:16102",
            "http://[::1]:16102",
        ] {
            let config = parse(&MINIMAL.replace("https://cloud.example.com", good));
            assert!(issue_keys(&config).is_empty(), "{good}");
        }

        for bad in [
            "ftp://cloud.example.com",
            "https://cloud.example.com/nextcloud",
            "https://cloud.example.com/?a=b",
            "https://cloud.example.com/#top",
            "https://user:secret@cloud.example.com",
            "file:///srv/cloud",
        ] {
            let config = parse(&MINIMAL.replace("https://cloud.example.com", bad));
            assert_eq!(issue_keys(&config), ["server.base_url"], "{bad}");
        }

        for unparsable in ["cloud.example.com", "", "https://"] {
            let raw = MINIMAL.replace("https://cloud.example.com", unparsable);
            assert!(Config::from_toml(&raw).is_err(), "{unparsable:?}");
        }
    }

    #[test]
    fn plain_http_on_a_public_host_warns() {
        let config = parse(&MINIMAL.replace("https://", "http://"));
        assert!(issue_keys(&config).is_empty());
        assert_eq!(config.warnings().len(), 1);

        let local = parse(&MINIMAL.replace("https://cloud.example.com", "http://localhost:16102"));
        assert!(local.warnings().is_empty());
    }

    #[test]
    fn trusted_proxies_accept_addresses_and_cidr_blocks() {
        let config =
            with_server(r#"trusted_proxies = ["127.0.0.1", "::1", "10.0.0.0/8", "fd00::/8"]"#);
        assert!(issue_keys(&config).is_empty());
        let proxies: Vec<String> = config
            .server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            proxies,
            ["127.0.0.1/32", "::1/128", "10.0.0.0/8", "fd00::/8"]
        );
    }

    #[test]
    fn trusted_proxies_reject_garbage() {
        for bad in ["proxy.local", "10.0.0.0/33", "300.1.1.1", "10.0.0.0/"] {
            let raw = MINIMAL.replace(
                "[server]\n",
                &format!("[server]\ntrusted_proxies = [\"{bad}\"]\n"),
            );
            let err = Config::from_toml(&raw).expect_err(bad).to_string();
            assert!(err.contains("trusted_proxies"), "{bad}: {err}");
        }
    }

    #[test]
    fn trusted_proxies_reject_host_bits() {
        let config = with_server(r#"trusted_proxies = ["10.1.2.3/8"]"#);
        match config.validate() {
            Err(ConfigError::Invalid(issues)) => {
                assert_eq!(issues.len(), 1);
                assert_eq!(issues[0].key, "server.trusted_proxies");
                assert!(issues[0].message.contains("10.0.0.0/8"));
            }
            other => panic!("expected an invalid config, got {other:?}"),
        }
    }

    #[test]
    fn intervals_must_be_positive() {
        let raw = format!(
            "{MINIMAL}
            [notify_push]
            ping_interval_secs = 0
            auth_timeout_secs = 0
            pre_auth_ttl_secs = 0
            debounce_secs = 0
            max_connections_per_user = 0
            "
        )
        .replace(
            "path = \"gono-cloud.db\"",
            "path = \"gono-cloud.db\"\nbusy_timeout_secs = 0",
        );
        assert_eq!(
            issue_keys(&parse(&raw)),
            [
                "db.busy_timeout_secs",
                "notify_push.ping_interval_secs",
                "notify_push.auth_timeout_secs",
                "notify_push.pre_auth_ttl_secs",
                "notify_push.debounce_secs",
                "notify_push.max_connections_per_user",
            ]
        );
    }

    #[test]
    fn negative_intervals_do_not_parse() {
        let raw = format!("{MINIMAL}\n[notify_push]\nping_interval_secs = -1");
        assert!(Config::from_toml(&raw).is_err());
    }

    #[test]
    fn db_pool_size_is_bounded() {
        for (value, ok) in [(0, false), (1, true), (64, true), (65, false)] {
            let raw = MINIMAL.replace(
                "path = \"gono-cloud.db\"",
                &format!("path = \"gono-cloud.db\"\nmax_connections = {value}"),
            );
            assert_eq!(issue_keys(&parse(&raw)).is_empty(), ok, "{value}");
        }
    }

    #[test]
    fn empty_paths_are_rejected() {
        let raw = MINIMAL
            .replace("data_dir = \"data\"", "data_dir = \"\"")
            .replace("path = \"gono-cloud.db\"", "path = \"\"");
        let raw = format!("{raw}\n[logging]\nfile = \"\"");
        let mut config = parse(&raw);
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));
        assert_eq!(
            issue_keys(&config),
            ["storage.data_dir", "db.path", "logging.file"]
        );
    }

    #[test]
    fn admin_path_is_validated() {
        for good in [
            "/apps/manage",
            "/gono-admin",
            "/admin",
            "/ops/admin",
            "/a.b_c~d",
        ] {
            let raw = format!("{MINIMAL}\n[admin]\npath = \"{good}\"");
            assert!(issue_keys(&parse(&raw)).is_empty(), "{good}");
        }
        for bad in [
            "",
            "/",
            "admin",
            "/admin/",
            "/a//b",
            "/a b",
            "/%2e",
            "/../x",
            "/ocs",
            "/push/x",
            "/remote.php",
            "/Index.php",
            "/login",
            // Only the default itself may lie below /apps.
            "/apps",
            "/apps/files",
            "/apps/assets",
            "/apps/manage/x",
            "/Apps/manage",
        ] {
            let raw = format!("{MINIMAL}\n[admin]\npath = \"{bad}\"");
            assert_eq!(issue_keys(&parse(&raw)), ["admin.path"], "{bad:?}");
        }
    }

    #[test]
    fn lock_timeout_is_bounded() {
        for (value, ok) in [(0, false), (1, true), (604_800, true), (604_801, false)] {
            let raw = format!("{MINIMAL}\n[webdav]\nmax_lock_timeout_secs = {value}");
            assert_eq!(issue_keys(&parse(&raw)).is_empty(), ok, "{value}");
        }
    }

    #[test]
    fn logging_level_is_restricted() {
        let ok = parse(&format!("{MINIMAL}\n[logging]\nlevel = \"debug\""));
        assert_eq!(ok.logging.level, LogLevel::Debug);

        for bad in ["verbose", "WARN", "warning", "info,sqlx=debug"] {
            let raw = format!("{MINIMAL}\n[logging]\nlevel = \"{bad}\"");
            assert!(Config::from_toml(&raw).is_err(), "{bad}");
        }
    }

    #[test]
    fn relative_paths_resolve_against_the_config_directory() {
        let raw = format!(
            "{}\n[logging]\nfile = \"logs/gono-cloud.log\"",
            MINIMAL.replace(
                "path = \"gono-cloud.db\"",
                "path = \"/var/lib/gono/gono.db\""
            )
        );
        let mut config = parse(&raw);
        config.resolve_relative_paths(Path::new("/etc/gono-cloud"));

        assert_eq!(config.storage.data_dir, Path::new("/etc/gono-cloud/data"));
        assert_eq!(config.db.path, Path::new("/var/lib/gono/gono.db"));
        assert_eq!(
            config.logging.file.as_deref(),
            Some(Path::new("/etc/gono-cloud/logs/gono-cloud.log"))
        );
    }

    #[test]
    fn load_reports_all_issues_with_the_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            MINIMAL
                .replace("[server]\n", "[server]\nbind = \"0.0.0.0:1\"\n")
                .replace("https://cloud.example.com", "https://cloud.example.com/sub"),
        )
        .unwrap();

        let err = Config::load(&path).expect_err("config should be rejected");
        let message = err.to_string();
        assert!(message.contains("server.bind"), "{message}");
        assert!(message.contains("server.base_url"), "{message}");
    }

    #[test]
    fn load_resolves_paths_next_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, MINIMAL).unwrap();

        let config = Config::load(&path).expect("config should load");
        let base = std::path::absolute(dir.path()).unwrap();
        assert_eq!(config.storage.data_dir, base.join("data"));
        assert_eq!(config.db.path, base.join("gono-cloud.db"));
    }

    #[test]
    fn load_reports_missing_files() {
        let err = Config::load(Path::new("/nonexistent/gono-cloud/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
    }

    #[test]
    fn example_config_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../config.example.toml");
        let config = Config::load(&path).expect("config.example.toml should be valid");
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
    }
}
