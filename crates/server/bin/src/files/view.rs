//! Templates of the web file UI (`crates/server/bin/templates/files/`) and the values they show.
//!
//! Everything a template prints is prepared here as text; askama escapes every value. URLs of
//! files are built from their client paths with every byte outside the RFC 3986 unreserved
//! set percent-encoded, so no name can break out of an attribute or form a scheme.

use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use gono_server_core::RelPath;

use crate::{
    i18n::{Lang, Text, fill},
    web::{Chrome, page},
};

/// Where the file UI lives (no trailing slash).
pub const PREFIX: &str = "/apps/files";

/// Percent-encodes everything but RFC 3986 unreserved characters.
pub fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Encodes a query parameter value.
pub fn encode_query(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// The page of client path `rel`: folders end with `/`.
pub fn url(rel: &RelPath, dir: bool) -> String {
    let mut out = format!("{PREFIX}/");
    for (index, segment) in rel.segments().enumerate() {
        if index > 0 {
            out.push('/');
        }
        out.push_str(&encode_segment(segment));
    }
    if dir && !rel.is_root() {
        out.push('/');
    }
    out
}

/// The display path of a folder: `/` for the root.
pub fn display_path(rel: &RelPath) -> String {
    format!("/{}", rel.as_str())
}

/// UNIX seconds of a time.
pub fn unix(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A modification time for a list: relative words for today and yesterday, the date alone
/// for other years. UTC; the script shows it in the browser's time zone. Returns the text and
/// the ISO 8601 value for `<time datetime>`.
pub fn when(lang: Lang, now: i64, secs: i64) -> (String, String) {
    let t = lang.t();
    let (y, mo, d, h, mi, s) = civil(secs);
    let iso = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z");
    let (ny, _, _, _, _, _) = civil(now);
    let day = secs.div_euclid(86_400);
    let today = now.div_euclid(86_400);
    let text = if day == today {
        match lang {
            Lang::En => format!("{}, {h:02}:{mi:02}", t.today),
            Lang::Zh => format!("{} {h:02}:{mi:02}", t.today),
        }
    } else if day + 1 == today {
        match lang {
            Lang::En => format!("{}, {h:02}:{mi:02}", t.yesterday),
            Lang::Zh => format!("{} {h:02}:{mi:02}", t.yesterday),
        }
    } else if y == ny {
        match lang {
            Lang::En => format!("{} {d}, {h:02}:{mi:02}", MONTHS[(mo - 1) as usize]),
            Lang::Zh => format!("{mo}月{d}日 {h:02}:{mi:02}"),
        }
    } else {
        match lang {
            Lang::En => format!("{} {d}, {y}", MONTHS[(mo - 1) as usize]),
            Lang::Zh => format!("{y}年{mo}月{d}日"),
        }
    };
    (text, iso)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Year, month, day, hour, minute and second of UNIX seconds (UTC).
fn civil(secs: i64) -> (i64, u32, u32, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
    )
}

/// The lowercase extension of a file name, if it has a short one.
pub fn extension(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty()
        && (1..=5).contains(&ext.len())
        && ext.bytes().all(|b| b.is_ascii_alphanumeric()))
    .then(|| ext.to_ascii_lowercase())
}

/// The CSS class and label of a file's kind badge.
pub fn kind(name: &str, is_dir: bool) -> (&'static str, String) {
    if is_dir {
        return ("kind--dir", String::new());
    }
    let Some(ext) = extension(name) else {
        return ("", "FILE".to_owned());
    };
    let class = match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "avif" | "heic" | "heif" | "bmp" | "tif"
        | "tiff" | "svg" | "ico" | "raw" | "cr2" | "cr3" | "nef" | "dng" | "arw" => "kind--image",
        "mp4" | "m4v" | "mov" | "mkv" | "webm" | "avi" | "wmv" | "flv" | "3gp" | "ogv" => {
            "kind--video"
        }
        "mp3" | "m4a" | "aac" | "flac" | "wav" | "ogg" | "oga" | "opus" | "wma" | "aiff" => {
            "kind--audio"
        }
        "pdf" | "doc" | "docx" | "odt" | "rtf" | "xls" | "xlsx" | "ods" | "csv" | "ppt"
        | "pptx" | "odp" | "pages" | "numbers" | "key" | "epub" => "kind--doc",
        "txt" | "md" | "log" | "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "conf"
        | "cfg" | "html" | "htm" | "css" | "js" | "ts" | "rs" | "py" | "go" | "java" | "c"
        | "h" | "cpp" | "sh" => "kind--text",
        "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "7z" | "rar" | "dmg" | "iso" => {
            "kind--archive"
        }
        _ => "",
    };
    let label: String = ext.chars().take(4).collect::<String>().to_ascii_uppercase();
    (class, label)
}

/// How a file can be shown in the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preview {
    /// An `<img>` of the file, served inline with this type.
    Image(&'static str),
    /// A `<video>`.
    Video(&'static str),
    /// An `<audio>`.
    Audio(&'static str),
    /// Its text, escaped, in a `<pre>`.
    Text,
    /// Never opened in the browser: it could run scripts as part of the site.
    Blocked,
    /// No preview.
    None,
}

impl Preview {
    /// The preview of a file named `name`.
    pub fn of(name: &str) -> Self {
        let Some(ext) = extension(name) else {
            return Self::None;
        };
        match ext.as_str() {
            "png" => Self::Image("image/png"),
            "jpg" | "jpeg" => Self::Image("image/jpeg"),
            "gif" => Self::Image("image/gif"),
            "webp" => Self::Image("image/webp"),
            "avif" => Self::Image("image/avif"),
            "bmp" => Self::Image("image/bmp"),
            "mp4" | "m4v" => Self::Video("video/mp4"),
            "webm" => Self::Video("video/webm"),
            "mov" => Self::Video("video/quicktime"),
            "ogv" => Self::Video("video/ogg"),
            "mp3" => Self::Audio("audio/mpeg"),
            "m4a" => Self::Audio("audio/mp4"),
            "aac" => Self::Audio("audio/aac"),
            "ogg" | "oga" | "opus" => Self::Audio("audio/ogg"),
            "wav" => Self::Audio("audio/wav"),
            "flac" => Self::Audio("audio/flac"),
            "txt" | "md" | "log" | "json" | "xml" | "yaml" | "yml" | "toml" | "ini" | "conf"
            | "cfg" | "csv" | "tsv" | "css" | "js" | "mjs" | "ts" | "rs" | "py" | "go" | "java"
            | "kt" | "swift" | "c" | "h" | "cpp" | "hpp" | "cs" | "rb" | "php" | "pl" | "sh"
            | "bash" | "zsh" | "sql" | "srt" | "vtt" | "tex" | "rst" | "env" | "gitignore"
            | "html" | "htm" | "svg" => Self::Text,
            "pdf" | "xhtml" | "xht" | "mht" | "mhtml" => Self::Blocked,
            _ => Self::None,
        }
    }

    /// The type to serve the file inline with, for images, video and audio.
    pub fn inline_type(self) -> Option<&'static str> {
        match self {
            Self::Image(kind) | Self::Video(kind) | Self::Audio(kind) => Some(kind),
            _ => None,
        }
    }
}

/// One link of the breadcrumb.
#[derive(Debug, Clone)]
pub struct Crumb {
    pub name: String,
    pub href: String,
}

/// The breadcrumb of folder `rel`: the root and every ancestor, without `rel` itself.
pub fn crumbs(t: &Text, rel: &RelPath) -> Vec<Crumb> {
    let mut out = vec![Crumb {
        name: t.all_files.to_owned(),
        href: url(&RelPath::root(), true),
    }];
    let mut path = RelPath::root();
    let segments: Vec<&str> = rel.segments().collect();
    for segment in segments.iter().take(segments.len().saturating_sub(1)) {
        path = path.join(segment);
        out.push(Crumb {
            name: (*segment).to_owned(),
            href: url(&path, true),
        });
    }
    out
}

/// The name shown for folder `rel`.
pub fn folder_name(t: &Text, rel: &RelPath) -> String {
    rel.file_name()
        .map_or_else(|| t.all_files.to_owned(), str::to_owned)
}

/// One row of a listing.
#[derive(Debug, Clone)]
pub struct Row {
    /// File or folder name.
    pub name: String,
    /// The name, encoded for a query parameter (`item=`).
    pub item: String,
    pub is_dir: bool,
    /// Page of the entry.
    pub href: String,
    /// URL of the folder that holds it (forms post there).
    pub parent_href: String,
    pub kind_class: &'static str,
    pub kind_label: String,
    pub size: String,
    pub modified: String,
    pub modified_iso: String,
    pub favorite: bool,
    /// Download link (a `.zip` for folders).
    pub download_href: String,
    /// The folder that holds it, for search results and favorites.
    pub location: Option<Crumb>,
}

/// A sort tab.
#[derive(Debug, Clone)]
pub struct Tab {
    pub label: &'static str,
    pub href: String,
    pub current: bool,
    /// The order the current tab sorts in (`asc` or `desc`).
    pub descending: bool,
}

/// Previous and next page links.
#[derive(Debug, Clone)]
pub struct Pager {
    pub label: String,
    pub prev: Option<String>,
    pub next: Option<String>,
}

/// The storage card: what the user stores, and the free space of the server.
#[derive(Debug, Clone)]
pub struct Usage {
    pub used: String,
    pub free: Option<String>,
}

/// What a listing page lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Folder,
    Search,
    Favorites,
}

/// `files/browse.html`: a folder, search results or the favorites.
#[derive(Template)]
#[template(path = "files/browse.html")]
pub struct BrowsePage {
    pub chrome: Chrome,
    pub mode: Mode,
    pub title: String,
    pub heading: String,
    pub sub: String,
    pub crumbs: Vec<Crumb>,
    /// URL of the folder (forms post there).
    pub dir_href: String,
    pub tabs: Vec<Tab>,
    pub rows: Vec<Row>,
    pub empty: Option<(String, String)>,
    pub notice: Option<String>,
    pub error: Option<String>,
    pub pager: Option<Pager>,
    pub usage: Usage,
    /// Name of the current folder, for the drop hint.
    pub folder: String,
}

impl BrowsePage {
    /// Whether the page lists a folder (with upload, selection and sorting).
    pub fn is_folder(&self) -> bool {
        self.mode == Mode::Folder
    }
}

/// `files/file.html`: one file with its preview.
#[derive(Template)]
#[template(path = "files/file.html")]
pub struct FilePage {
    pub chrome: Chrome,
    pub crumbs: Vec<Crumb>,
    pub row: Row,
    pub kind: String,
    pub preview: Preview,
    /// URL of the inline content, for images, video and audio.
    pub raw_href: String,
    /// The beginning of a text file.
    pub text: Option<String>,
    pub truncated: bool,
    pub notice: Option<String>,
    pub error: Option<String>,
}

impl FilePage {
    pub fn image(&self) -> bool {
        matches!(self.preview, Preview::Image(_))
    }
    pub fn video(&self) -> bool {
        matches!(self.preview, Preview::Video(_))
    }
    pub fn audio(&self) -> bool {
        matches!(self.preview, Preview::Audio(_))
    }
    pub fn blocked(&self) -> bool {
        matches!(self.preview, Preview::Blocked)
    }
}

/// `files/form.html`: new folder, upload, rename and delete.
#[derive(Template)]
#[template(path = "files/form.html")]
pub struct FormPage {
    pub chrome: Chrome,
    pub crumbs: Vec<Crumb>,
    /// `mkdir`, `upload`, `rename` or `delete`.
    pub action: &'static str,
    pub title: String,
    pub lead: Option<String>,
    pub note: Option<String>,
    /// The folder the form posts to.
    pub dir_href: String,
    pub items: Vec<String>,
    /// The value of the name field.
    pub name: String,
    pub error: Option<String>,
}

/// One folder a move can go to.
#[derive(Debug, Clone)]
pub struct Choice {
    pub name: String,
    pub path: String,
}

/// `files/move.html`: choose where to move entries.
#[derive(Template)]
#[template(path = "files/move.html")]
pub struct MovePage {
    pub chrome: Chrome,
    pub crumbs: Vec<Crumb>,
    pub title: String,
    pub dir_href: String,
    pub items: Vec<String>,
    /// The folder shown (`/a/b`).
    pub at: String,
    pub at_label: String,
    pub up: Option<String>,
    pub choices: Vec<Choice>,
    pub error: Option<String>,
}

page!(BrowsePage, FilePage, FormPage, MovePage);

/// "N items" in the page's language.
pub fn count_items(t: &Text, count: usize) -> String {
    if count == 1 {
        t.one_item.to_owned()
    } else {
        fill(t.items, &[&count.to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_encode_every_reserved_byte() {
        let rel = RelPath::parse("a b/\"x\"<y>?#%/Über").unwrap();
        assert_eq!(
            url(&rel, true),
            "/apps/files/a%20b/%22x%22%3Cy%3E%3F%23%25/%C3%9Cber/"
        );
        assert_eq!(url(&RelPath::root(), true), "/apps/files/");
        assert_eq!(
            url(&RelPath::parse("f.txt").unwrap(), false),
            "/apps/files/f.txt"
        );
    }

    #[test]
    fn kinds_and_previews_follow_the_extension() {
        assert_eq!(kind("a.JPG", false), ("kind--image", "JPG".to_owned()));
        assert_eq!(kind("archive.tar.gz", false).0, "kind--archive");
        assert_eq!(kind(".bashrc", false), ("", "FILE".to_owned()));
        assert_eq!(kind("dir", true).0, "kind--dir");
        assert_eq!(Preview::of("x.png").inline_type(), Some("image/png"));
        assert_eq!(Preview::of("page.html"), Preview::Text, "source, escaped");
        assert_eq!(
            Preview::of("x.svg"),
            Preview::Text,
            "never as an image of the site"
        );
        assert_eq!(Preview::of("x.pdf"), Preview::Blocked);
        assert_eq!(Preview::of("x.html").inline_type(), None);
        assert_eq!(Preview::of("README"), Preview::None);
    }

    #[test]
    fn times_are_relative_near_now() {
        let now = 1_700_000_000; // 2023-11-14 22:13:20 UTC
        assert_eq!(when(Lang::En, now, now - 60).0, "Today, 22:12");
        assert_eq!(when(Lang::Zh, now, now - 86_400).0, "昨天 22:13");
        assert_eq!(when(Lang::En, now, now - 30 * 86_400).0, "Oct 15, 22:13");
        assert_eq!(when(Lang::En, now, now - 400 * 86_400).0, "Oct 10, 2022");
        assert_eq!(when(Lang::Zh, now, now - 400 * 86_400).0, "2022年10月10日");
        assert_eq!(when(Lang::En, now, now).1, "2023-11-14T22:13:20Z");
    }
}
