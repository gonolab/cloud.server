//! Templates of the admin UI (`crates/server/bin/templates/admin/`) and the values they show.
//!
//! Everything a template prints is prepared here as text, so the templates only lay values
//! out; askama escapes every value. Element ids are fixed per page (see the uniqueness test).

use askama::Template;
use gono_server_core::{app_passwords::Scope, db};

use crate::{
    commands::output::format_time,
    web::{Chrome, page},
};

page!(
    LoginPage<'_>,
    NotAdminPage<'_>,
    MessagePage,
    OverviewPage,
    UsersPage,
    NewUserPage,
    UserPage,
    CreatedPage,
    DeletePage,
);

/// What every page of the signed-in admin UI shows around its content.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The admin path, for example `/gono-admin`.
    pub prefix: String,
    /// Highlight "Overview" in the navigation.
    pub on_overview: bool,
    /// Highlight "Users" in the navigation.
    pub on_users: bool,
    /// CSRF token of the session, for every form.
    pub csrf: String,
    /// Server version.
    pub version: &'static str,
    /// Implemented Nextcloud protocol version.
    pub nextcloud: String,
    /// Instance id.
    pub instance_id: String,
}

/// `admin/login.html`.
#[derive(Template)]
#[template(path = "admin/login.html")]
pub struct LoginPage<'a> {
    pub chrome: Chrome,
    pub prefix: &'a str,
    pub csrf: &'a str,
    pub user: &'a str,
    pub error: Option<&'a str>,
}

/// `admin/not_admin.html`: signed in, but not as an admin.
#[derive(Template)]
#[template(path = "admin/not_admin.html")]
pub struct NotAdminPage<'a> {
    pub chrome: Chrome,
    pub prefix: &'a str,
    pub csrf: &'a str,
    pub username: &'a str,
}

/// `admin/message.html`.
#[derive(Template)]
#[template(path = "admin/message.html")]
pub struct MessagePage {
    pub chrome: Chrome,
    pub frame: Frame,
    pub heading: String,
    pub lead: String,
    pub link_href: String,
    pub link_label: String,
}

/// One label and value of a facts list.
#[derive(Debug, Clone)]
pub struct Fact {
    pub label: &'static str,
    pub value: String,
    pub mono: bool,
}

/// One row of the overview's feature list.
#[derive(Debug, Clone)]
pub struct Feature {
    pub name: &'static str,
    pub detail: String,
    pub on: bool,
}

/// `admin/overview.html`.
#[derive(Template)]
#[template(path = "admin/overview.html")]
pub struct OverviewPage {
    pub chrome: Chrome,
    pub frame: Frame,
    pub host: String,
    pub uptime: String,
    pub warnings: Vec<String>,
    pub stats: gono_server_core::stats::Overview,
    pub users_note: String,
    pub storage_number: String,
    pub storage_unit: String,
    /// Used and total bytes of the data directory's file system.
    pub disk: Option<(u64, u64)>,
    pub disk_note: String,
    /// Open push connections and connected users, when notify_push is on.
    pub push_live: Option<(usize, usize)>,
    pub server_facts: Vec<Fact>,
    pub server_address: String,
    pub webdav_url: String,
    pub websocket: Option<String>,
    pub data_dir: String,
    pub case_insensitive: Option<bool>,
    pub storage_used: String,
    pub free_of_total: String,
    pub db_path: String,
    pub db_size: String,
    pub features: Vec<Feature>,
}

/// One row of the user list.
#[derive(Debug, Clone)]
pub struct UserRow {
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    pub enabled: bool,
    pub app_passwords: i64,
    pub storage: String,
    pub created: String,
}

/// `admin/users.html`.
#[derive(Template)]
#[template(path = "admin/users.html")]
pub struct UsersPage {
    pub chrome: Chrome,
    pub frame: Frame,
    pub notice: Option<String>,
    pub summary: String,
    pub users: Vec<UserRow>,
}

/// `admin/new_user.html`.
#[derive(Template)]
#[template(path = "admin/new_user.html")]
pub struct NewUserPage {
    pub chrome: Chrome,
    pub frame: Frame,
    pub error: Option<String>,
    pub username: String,
    pub display_name: String,
    pub admin: bool,
}

/// A user as the detail page shows it.
#[derive(Debug, Clone)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    pub enabled: bool,
    pub created: String,
    pub updated: String,
    pub storage: String,
}

/// One mount of an app password, as text.
#[derive(Debug, Clone)]
pub struct ScopeChip {
    pub mount: String,
    pub storage: String,
    pub permission: &'static str,
}

impl ScopeChip {
    pub fn new(scope: &Scope) -> Self {
        Self {
            mount: scope.mount_path.to_string(),
            storage: scope.storage_path.to_string(),
            permission: scope.permission.as_str(),
        }
    }
}

/// One row of a user's app passwords.
#[derive(Debug, Clone)]
pub struct AppPasswordRow {
    pub id: i64,
    pub label: String,
    pub created: String,
    pub scopes: Vec<ScopeChip>,
    pub last_used: String,
    pub expiry: String,
}

/// One mount row of the new app password form, as entered.
#[derive(Debug, Clone, Default)]
pub struct MountInput {
    pub mount: String,
    pub storage: String,
    pub permission: String,
}

/// The new app password form, as entered (kept when the form is shown again with an error).
#[derive(Debug, Clone)]
pub struct AppPasswordForm {
    pub label: String,
    pub expires_in_days: String,
    pub access: String,
    pub mounts: Vec<MountInput>,
}

/// Number of mount rows of the new app password form.
pub const MOUNT_ROWS: usize = 3;

impl Default for AppPasswordForm {
    fn default() -> Self {
        Self {
            label: String::new(),
            expires_in_days: String::new(),
            access: "full".to_owned(),
            mounts: vec![MountInput::default(); MOUNT_ROWS],
        }
    }
}

/// `admin/user.html`.
#[derive(Template)]
#[template(path = "admin/user.html")]
pub struct UserPage {
    pub chrome: Chrome,
    pub frame: Frame,
    /// `<prefix>/users/<username>`.
    pub base: String,
    pub notice: Option<String>,
    pub error: Option<String>,
    pub user: UserView,
    /// The page shows the signed-in admin's own account.
    pub is_self: bool,
    pub app_passwords: Vec<AppPasswordRow>,
    pub form: AppPasswordForm,
}

/// `admin/created.html`: the one-time display of a new app password.
#[derive(Template)]
#[template(path = "admin/created.html")]
pub struct CreatedPage {
    pub chrome: Chrome,
    pub frame: Frame,
    pub username: String,
    pub label: String,
    pub token: String,
    pub scopes: Vec<ScopeChip>,
    pub expiry: String,
    pub server: String,
}

/// `admin/delete.html`.
#[derive(Template)]
#[template(path = "admin/delete.html")]
pub struct DeletePage {
    pub chrome: Chrome,
    pub frame: Frame,
    pub base: String,
    pub username: String,
    pub app_passwords: i64,
    pub error: Option<String>,
}

/// `1.4 GB`-style sizes (binary multiples, as Nextcloud shows them).
pub fn format_bytes(bytes: u64) -> String {
    let (number, unit) = split_bytes(bytes);
    format!("{number} {unit}")
}

/// The number and unit of [`format_bytes`].
pub fn split_bytes(bytes: u64) -> (String, &'static str) {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut unit = 0;
    let mut whole = bytes;
    while whole >= 1024 && unit + 1 < UNITS.len() {
        whole /= 1024;
        unit += 1;
    }
    if unit == 0 {
        return (bytes.to_string(), UNITS[0]);
    }
    // One decimal from integer arithmetic: tenths of the unit, rounded down.
    let scale = 1u128 << (10 * unit);
    let tenths = u128::from(bytes) * 10 / scale;
    let text = if tenths >= 1000 {
        (tenths / 10).to_string()
    } else {
        format!("{}.{}", tenths / 10, tenths % 10)
    };
    (text, UNITS[unit])
}

/// `just now`, `5 min ago`, `3 h ago`, `2 days ago`, or the date for anything older than a
/// month.
pub fn ago(now: i64, then: i64) -> String {
    let seconds = (now - then).max(0);
    match seconds {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} min ago", seconds / 60),
        3600..86_400 => format!("{} h ago", seconds / 3600),
        86_400..2_592_000 => {
            let days = seconds / 86_400;
            format!("{days} {} ago", if days == 1 { "day" } else { "days" })
        }
        _ => date(then),
    }
}

/// `YYYY-MM-DD` of UNIX seconds (UTC).
pub fn date(secs: i64) -> String {
    format_time(secs).chars().take(10).collect()
}

/// `YYYY-MM-DD HH:MM UTC` of UNIX seconds.
pub fn time(secs: i64) -> String {
    format_time(secs)
}

/// `3 days 4 hours`, `5 hours 2 minutes`, `12 minutes`.
pub fn duration(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let plural = |n: i64, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
    );
    if days > 0 {
        format!("{} {}", plural(days, "day"), plural(hours, "hour"))
    } else if hours > 0 {
        format!("{} {}", plural(hours, "hour"), plural(minutes, "minute"))
    } else {
        plural(minutes, "minute")
    }
}

/// The expiry of an app password, as the list shows it.
pub fn expiry(expires_at: Option<i64>, now: i64) -> String {
    match expires_at {
        None => "No expiry".to_owned(),
        Some(at) if at <= now => format!("Expired {}", date(at)),
        Some(at) => format!("Expires {}", date(at)),
    }
}

/// The current time, UNIX seconds.
pub fn now() -> i64 {
    db::unix_now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_503_238_553), "1.3 GB");
        assert_eq!(format_bytes(5 * (1 << 40)), "5.0 TB");
        assert_eq!(split_bytes(99 * (1 << 30)), ("99.0".to_owned(), "GB"));
        assert_eq!(split_bytes(999 * (1 << 30)), ("999".to_owned(), "GB"));
        assert_eq!(split_bytes(1023 * (1 << 20) + 1), ("1023".to_owned(), "MB"));
    }

    #[test]
    fn times() {
        assert_eq!(ago(1000, 990), "just now");
        assert_eq!(ago(10_000, 10_000 - 300), "5 min ago");
        assert_eq!(ago(100_000, 100_000 - 7200), "2 h ago");
        assert_eq!(ago(1_000_000, 1_000_000 - 86_400), "1 day ago");
        assert_eq!(ago(100_000_000, 0), "1970-01-01");
        assert_eq!(duration(3 * 86_400 + 4 * 3600 + 59), "3 days 4 hours");
        assert_eq!(duration(3600 + 120), "1 hour 2 minutes");
        assert_eq!(duration(59), "0 minutes");
        assert_eq!(expiry(None, 0), "No expiry");
        assert_eq!(expiry(Some(0), 1), "Expired 1970-01-01");
    }
}
