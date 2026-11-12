//! The web file UI under `/apps/files/`, when `files_ui.enabled` (the default).
//!
//! Every URL below `/apps/files/` names a file or folder of the signed-in user: folders end
//! with `/`. What happens there depends on the method and the query:
//!
//! | Request | Answer |
//! |---|---|
//! | `GET <folder>/` | The folder (`?sort=name\|modified\|size`, `?order=asc\|desc`, `?page=`). |
//! | `GET <folder>/?q=<text>` | Search by name below the folder. |
//! | `GET /apps/files/?view=favorites` | The favorites. |
//! | `GET <folder>/?action=mkdir\|upload\|rename\|move\|delete&item=<name>` | The form of an action (the pages that work without scripts). |
//! | `GET <file>` | The file with its preview. |
//! | `GET <file>?download` | The file as an attachment; `GET <folder>/?download`: a `.zip`. |
//! | `GET <file>?raw` | Images, video and audio inline, for the preview. |
//! | `POST <folder>/` | The forms: `action` = `mkdir`, `rename`, `move`, `delete`, `zip` or `favorite`, with the entries in `item`. |
//! | `POST <folder>/?upload` | Form upload (see [`upload`]). |
//! | `PUT`, `MKCOL`, `POST\|PUT\|DELETE ...?chunked=` | Uploads of the script (see [`upload`]). |
//!
//! # Security
//!
//! - **Sessions only.** Pages need a live browser session of an enabled account (web login
//!   password, see [`crate::web`]); app passwords never get in, and the WebDAV routes keep
//!   accepting app passwords only. Without a session, pages redirect to `/login`.
//! - **One code path.** Every operation is a request to the same `DavService` as the sync
//!   clients' (see [`ops`]), with an [`Identity`] of the user's whole storage: the access
//!   that granting a device through Login Flow gives as well.
//! - **CSRF.** Forms carry the session's token, script requests send it in `X-Gono-CSRF`
//!   (a header no other site can set without a CORS preflight, which the server never
//!   answers), and both must come from this origin. `GET` never changes anything.
//! - **User content never runs as part of the site.** Downloads are attachments; previews are
//!   served inline only for images, video and audio, with a type the server picks from the
//!   name; text is shown escaped inside the page. All of it carries
//!   `Content-Security-Policy: default-src 'none'; sandbox` and `nosniff`.
//! - **Bounded work.** At most two `.zip` downloads per user and eight in all, each of at
//!   most [`MAX_ZIP_ENTRIES`] entries; search looks at a bounded number of rows; listings are
//!   paged.

pub mod account;
mod ops;
mod upload;
mod view;
mod zip;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use gono_server_core::{RelPath, path::normalize_segment, web_sessions::SessionUser};
use gono_server_dav::{Identity, metadata::Entry};
use tokio::sync::mpsc;

use self::{
    ops::{OpError, dav, dav_path},
    view::{
        BrowsePage, Choice, Crumb, FilePage, FormPage, Mode, MovePage, PREFIX, Pager, Preview, Row,
        Tab, Usage, count_items, crumbs, display_path, encode_query, folder_name, kind, unix, url,
        when,
    },
    zip::ZipWriter,
};
use crate::{
    app::{AppState, percent_decode},
    i18n::{Lang, Text, fill},
    web::{self, Chrome, Message, Nav},
};

/// Entries per listing page.
const PAGE_SIZE: usize = 500;

/// Search results shown at most.
const SEARCH_LIMIT: usize = 200;

/// Entries in one `.zip` at most.
pub const MAX_ZIP_ENTRIES: i64 = 100_000;

/// Concurrent `.zip` downloads per user and in all.
const ZIPS_PER_USER: usize = 2;
const ZIPS_TOTAL: usize = 8;

/// Text previews show at most this many bytes.
const TEXT_PREVIEW_BYTES: usize = 256 * 1024;

/// Largest form body (the entries of a selection).
const MAX_FORM_BYTES: usize = 512 * 1024;

/// The file UI's state.
#[derive(Debug, Default)]
pub struct Files {
    /// Running `.zip` downloads per user.
    zips: Mutex<HashMap<i64, usize>>,
    /// New app passwords of the account page, waiting to be shown once.
    created: account::CreatedStore,
}

/// A running `.zip` download; frees its place when dropped.
struct ZipPermit {
    files: Arc<Files>,
    user: i64,
}

impl Drop for ZipPermit {
    fn drop(&mut self) {
        let mut zips = self.files.zips.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = zips.get_mut(&self.user) {
            *count -= 1;
            if *count == 0 {
                zips.remove(&self.user);
            }
        }
    }
}

impl Files {
    /// The file UI.
    pub fn new() -> Self {
        Self::default()
    }

    fn zip_permit(self: &Arc<Self>, user: i64) -> Option<ZipPermit> {
        let mut zips = self.zips.lock().unwrap_or_else(|e| e.into_inner());
        let total: usize = zips.values().sum();
        let mine = zips.get(&user).copied().unwrap_or(0);
        if total >= ZIPS_TOTAL || mine >= ZIPS_PER_USER {
            return None;
        }
        *zips.entry(user).or_insert(0) += 1;
        Some(ZipPermit {
            files: self.clone(),
            user,
        })
    }
}

/// The routes of the file UI and the account page.
pub fn routes() -> Router<AppState> {
    use self::account::ACCOUNT;
    let files = Router::new()
        .route("/apps/files/", any(handle))
        .route("/apps/files/{*path}", any(handle))
        // Uploads stream; forms limit their bodies themselves.
        .layer(DefaultBodyLimit::disable());
    Router::new()
        .merge(files)
        .route(PREFIX, get(to_home))
        .route("/index.php/apps/files", get(nextcloud_link))
        .route("/index.php/apps/files/", get(nextcloud_link))
        .route(ACCOUNT, get(account::to_page))
        .route(&format!("{ACCOUNT}/"), get(account::show))
        .route(
            &format!("{ACCOUNT}/display-name"),
            post(account::set_display_name),
        )
        .route(&format!("{ACCOUNT}/password"), post(account::set_password))
        .route(
            &format!("{ACCOUNT}/app-passwords"),
            post(account::create_app_password),
        )
        .route(
            &format!("{ACCOUNT}/app-passwords/{{id}}/delete"),
            post(account::revoke_app_password),
        )
        .route(&format!("{ACCOUNT}/created"), get(account::created))
}

async fn to_home() -> Response {
    web::see_other("/apps/files/", &[])
}

/// `/index.php/apps/files/?dir=/a/b`: Nextcloud's web UI address, as the apps link to it.
async fn nextcloud_link(uri: Uri) -> Response {
    let dir = uri.query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "dir")
            .map(|(_, value)| value.into_owned())
    });
    let rel = dir
        .and_then(|dir| RelPath::parse(&dir).ok())
        .unwrap_or_else(RelPath::root);
    web::see_other(&url(&rel, true), &[])
}

// ---------------------------------------------------------------------------------------------
// Sessions and targets
// ---------------------------------------------------------------------------------------------

/// A signed-in user of the file UI.
struct Visitor {
    user: SessionUser,
    token: String,
    identity: Arc<Identity>,
    chrome: Chrome,
}

impl Visitor {
    fn t(&self) -> &'static Text {
        self.chrome.t
    }

    fn lang(&self) -> Lang {
        self.chrome.lang
    }

    /// The frame of a page, with `nav` current.
    fn chrome(&self, nav: Nav) -> Chrome {
        let mut chrome = self.chrome.clone();
        chrome.nav = nav;
        chrome
    }
}

/// The signed-in user of the request, or `None`.
async fn visitor(state: &AppState, headers: &HeaderMap, uri: &Uri) -> Option<Visitor> {
    let (user, token) = state.web.session(headers).await?;
    let csrf = state.web.session_csrf(&token);
    let mut chrome = Chrome::for_request(headers).signed_in(&user, &csrf);
    chrome.files = true;
    chrome.logout = "/logout".to_owned();
    chrome.here = uri
        .path_and_query()
        .map_or_else(|| "/apps/files/".to_owned(), |pq| pq.as_str().to_owned());
    if user.is_admin
        && let Some(admin) = &state.admin
    {
        chrome.admin = Some(admin.prefix().to_owned());
    }
    let identity = Identity::for_web_session(
        user.user_id,
        user.username.clone(),
        user.display_name.clone(),
    );
    Some(Visitor {
        user,
        token,
        identity,
        chrome,
    })
}

/// The client path a request URL names, and whether it ends with `/`.
fn target(uri: &Uri) -> Option<(RelPath, bool)> {
    let rest = uri.path().strip_prefix(PREFIX)?;
    if !gono_server_dav::service::path_is_clean(rest) {
        return None;
    }
    let decoded: Vec<Vec<u8>> = rest
        .split('/')
        .map(|segment| percent_decode(segment.as_bytes()))
        .collect();
    let rel = RelPath::from_raw_segments(decoded.iter().map(Vec::as_slice)).ok()?;
    Some((rel, rest.ends_with('/') || rest.is_empty()))
}

/// The query parameters the file UI uses.
#[derive(Debug, Default)]
struct Params {
    view: String,
    q: Option<String>,
    sort: String,
    order: String,
    page: usize,
    action: String,
    items: Vec<String>,
    download: bool,
    raw: bool,
    upload: bool,
    done: String,
    error: String,
    n: usize,
    failed: usize,
    of: usize,
    skipped: usize,
    name: String,
    chunked: upload::Chunked,
    has_chunked: bool,
}

impl Params {
    fn parse(query: Option<&str>) -> Self {
        let mut params = Self {
            page: 1,
            ..Self::default()
        };
        let Some(query) = query else {
            return params;
        };
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let value = value.into_owned();
            match key.as_ref() {
                "view" => params.view = value,
                "q" => params.q = Some(value),
                "sort" => params.sort = value,
                "order" => params.order = value,
                "page" => params.page = value.parse().unwrap_or(1).max(1),
                "action" => params.action = value,
                "item" => params.items.push(value),
                "download" => params.download = true,
                "raw" => params.raw = true,
                "upload" => params.upload = true,
                "done" => params.done = value,
                "error" => params.error = value,
                "n" => params.n = value.parse().unwrap_or(0),
                "f" => params.failed = value.parse().unwrap_or(0),
                "of" => params.of = value.parse().unwrap_or(0),
                "skipped" => params.skipped = value.parse().unwrap_or(0),
                "name" => params.name = value,
                "chunked" => {
                    params.has_chunked = true;
                    params.chunked.step = value;
                }
                "id" => params.chunked.id = value,
                "total" => params.chunked.total = value.parse().ok(),
                "start" => params.chunked.start = value.parse().ok(),
                "end" => params.chunked.end = value.parse().ok(),
                _ => {}
            }
        }
        params
    }
}

/// A page with a heading and a text in the file UI.
fn message(visitor: &Visitor, status: StatusCode, heading: &str, lead: &str) -> Response {
    let t = visitor.t();
    let mut page = Message::new(visitor.chrome(Nav::Files), heading, heading, lead);
    page.link = Some(("/apps/files/".to_owned(), t.back_to_files.to_owned()));
    page.respond(status)
}

fn not_found(visitor: &Visitor) -> Response {
    let t = visitor.t();
    message(
        visitor,
        StatusCode::NOT_FOUND,
        t.not_found,
        t.not_found_lead,
    )
}

fn internal(visitor: &Visitor, what: &str, err: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %err, "web file UI: {what}");
    let t = visitor.t();
    message(
        visitor,
        StatusCode::INTERNAL_SERVER_ERROR,
        t.error,
        t.error_lead,
    )
}

/// The refusal of a request that did not come from this site's pages.
fn blocked(visitor: &Visitor, lead: fn(&Text) -> &'static str) -> Response {
    let t = visitor.t();
    message(visitor, StatusCode::FORBIDDEN, t.request_blocked, lead(t))
}

// ---------------------------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------------------------

/// Every request below `/apps/files/`.
async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let Some(files) = state.files.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let uri = request.uri().clone();
    let method = request.method().clone();
    let Some(visitor) = visitor(&state, request.headers(), &uri).await else {
        if method == Method::GET || method == Method::HEAD {
            let here = uri
                .path_and_query()
                .map_or("/apps/files/", |pq| pq.as_str());
            return web::see_other(&format!("/login?next={}", encode_query(here)), &[]);
        }
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some((rel, slash)) = target(&uri) else {
        return not_found(&visitor);
    };
    let params = Params::parse(uri.query());
    match method.as_str() {
        "GET" | "HEAD" => get_page(&state, &files, &visitor, rel, slash, params, request).await,
        "POST" | "PUT" | "MKCOL" | "DELETE" => {
            if !state.web.same_origin(request.headers()) {
                return blocked(&visitor, |t| t.from_other_site);
            }
            if method == Method::POST && !params.has_chunked {
                return post_form(&state, &files, &visitor, rel, params, request).await;
            }
            script(&state, &visitor, rel, params, request).await
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// The requests of the script (see [`upload`]): the CSRF token is in `X-Gono-CSRF`.
async fn script(
    state: &AppState,
    visitor: &Visitor,
    rel: RelPath,
    params: Params,
    request: Request,
) -> Response {
    let token = request
        .headers()
        .get("x-gono-csrf")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !state.web.check_session_csrf(&visitor.token, token) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let method = request.method().as_str().to_owned();
    let (parts, body) = request.into_parts();
    if params.has_chunked {
        return upload::chunked(
            state,
            &visitor.identity,
            &rel,
            &method,
            &params.chunked,
            &parts.headers,
            body,
        )
        .await;
    }
    match method.as_str() {
        "PUT" if !rel.is_root() => {
            upload::put(state, &visitor.identity, &rel, &parts.headers, body).await
        }
        "MKCOL" if !rel.is_root() => upload::mkcol(state, &visitor.identity, &rel).await,
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

// ---------------------------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------------------------

async fn get_page(
    state: &AppState,
    files: &Arc<Files>,
    visitor: &Visitor,
    rel: RelPath,
    slash: bool,
    params: Params,
    request: Request,
) -> Response {
    let fs = state.dav.fs();
    let entry = match fs.stat(visitor.identity.clone(), &rel).await {
        Ok(entry) => entry,
        Err(_) => return not_found(visitor),
    };
    if params.download {
        return if entry.is_dir() {
            zip_download(state, files, visitor, &rel, None).await
        } else {
            download(
                state,
                visitor,
                &rel,
                request.headers(),
                request.method(),
                false,
            )
            .await
        };
    }
    if params.raw {
        if entry.is_dir() {
            return not_found(visitor);
        }
        return download(
            state,
            visitor,
            &rel,
            request.headers(),
            request.method(),
            true,
        )
        .await;
    }
    if entry.is_dir() {
        if !slash {
            return web::see_other(&with_query(&url(&rel, true), request.uri()), &[]);
        }
        if let Some(q) = &params.q {
            return search_page(state, visitor, &rel, q).await;
        }
        if params.view == "favorites" {
            return favorites_page(state, visitor).await;
        }
        match params.action.as_str() {
            "mkdir" | "upload" | "rename" | "delete" => {
                let items = params.items.clone();
                return form_page(visitor, &rel, &params.action, items, None);
            }
            "move" => return move_page(state, visitor, &rel, params.items, &rel, None).await,
            _ => {}
        }
        folder_page(state, visitor, &rel, &params).await
    } else {
        if slash {
            return web::see_other(&url(&rel, false), &[]);
        }
        file_page(state, visitor, &rel, &entry, &params).await
    }
}

fn with_query(path: &str, uri: &Uri) -> String {
    match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    }
}

/// The flash messages a redirect asked for.
fn flashes(t: &Text, params: &Params) -> (Option<String>, Option<String>) {
    let n = params.n.to_string();
    let name = params.name.as_str();
    let notice = match params.done.as_str() {
        "created" => Some(fill(t.notice_created, &[name])),
        "uploaded" if params.n == 1 => Some(t.notice_uploaded_one.to_owned()),
        "uploaded" => Some(fill(t.notice_uploaded, &[&n])),
        "renamed" => Some(fill(t.notice_renamed, &[name])),
        "moved" if params.n == 1 => Some(t.notice_moved_one.to_owned()),
        "moved" => Some(fill(t.notice_moved, &[&n])),
        "deleted" if params.n == 1 => Some(t.notice_deleted_one.to_owned()),
        "deleted" => Some(fill(t.notice_deleted, &[&n])),
        "favorite" => Some(t.notice_favorited.to_owned()),
        "unfavorite" => Some(t.notice_unfavorited.to_owned()),
        "none" => Some(t.notice_nothing_selected.to_owned()),
        _ => None,
    };
    let notice = match (notice, params.done.as_str(), params.skipped) {
        (_, "uploaded", skipped) if skipped > 0 && params.n == 0 => {
            Some(fill(t.notice_skipped, &[&skipped.to_string()]))
        }
        (Some(text), "uploaded", skipped) if skipped > 0 => Some(format!(
            "{text} {}",
            fill(t.notice_skipped, &[&skipped.to_string()])
        )),
        (notice, _, _) => notice,
    };
    let error = match params.error.as_str() {
        "partial" => Some(fill(
            t.err_partial,
            &[&params.failed.to_string(), &params.of.to_string()],
        )),
        "busy" => Some(t.err_busy.to_owned()),
        "too-big" => Some(t.err_too_big.to_owned()),
        code => OpError::from_code(code).map(|err| err.message(t).to_owned()),
    };
    (notice, error)
}

/// The storage card.
async fn usage(state: &AppState, visitor: &Visitor) -> Usage {
    let t = visitor.t();
    let used = state
        .dav
        .fs()
        .usage(visitor.user.user_id)
        .await
        .map_or(0, |(used, _)| used);
    let data_dir = state.dav.fs().layout().root().to_path_buf();
    let disk = tokio::task::spawn_blocking(move || gono_server_dav::fs::disk_space(&data_dir))
        .await
        .ok()
        .flatten();
    Usage {
        used: fill(t.used, &[&crate::admin::format_bytes(used)]),
        free: disk.map(|(free, _)| fill(t.free_on_server, &[&crate::admin::format_bytes(free)])),
    }
}

/// What a listing row shows about an entry.
#[derive(Debug, Clone, Copy)]
struct Meta {
    is_dir: bool,
    /// UNIX seconds.
    modified: i64,
    size: u64,
    favorite: bool,
}

impl Meta {
    fn of(entry: &Entry) -> Self {
        Self {
            is_dir: entry.is_dir(),
            modified: unix(entry.modified),
            size: entry.size,
            favorite: entry.favorite,
        }
    }

    fn of_row(file: &gono_server_core::meta::FileRow) -> Self {
        Self {
            is_dir: file.is_dir,
            modified: file.mtime_ns.div_euclid(1_000_000_000),
            size: file.size,
            favorite: file.favorite,
        }
    }
}

/// A listing row for the entry named `name` in folder `parent`.
fn row(visitor: &Visitor, now: i64, parent: &RelPath, name: &str, meta: Meta) -> Row {
    let rel = parent.join(name);
    let is_dir = meta.is_dir;
    let (kind_class, kind_label) = kind(name, is_dir);
    let (modified, modified_iso) = when(visitor.lang(), now, meta.modified);
    let href = url(&rel, is_dir);
    Row {
        name: name.to_owned(),
        item: encode_query(name),
        is_dir,
        download_href: format!("{href}?download"),
        href,
        parent_href: url(parent, true),
        kind_class,
        kind_label,
        size: crate::admin::format_bytes(meta.size),
        modified,
        modified_iso,
        favorite: meta.favorite,
        location: None,
    }
}

/// The order of a listing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Name,
    Modified,
    Size,
}

async fn folder_page(
    state: &AppState,
    visitor: &Visitor,
    rel: &RelPath,
    params: &Params,
) -> Response {
    let t = visitor.t();
    let (_, mut children) = match state.dav.fs().list(visitor.identity.clone(), rel).await {
        Ok(listing) => listing,
        Err(_) => return not_found(visitor),
    };
    let sort = match params.sort.as_str() {
        "modified" => Sort::Modified,
        "size" => Sort::Size,
        _ => Sort::Name,
    };
    // Names ascend by default; times and sizes show the newest and largest first.
    let descending = match params.order.as_str() {
        "asc" => false,
        "desc" => true,
        _ => sort != Sort::Name,
    };
    children.sort_by(|(a_name, a), (b_name, b)| {
        let by_kind = b.is_dir().cmp(&a.is_dir());
        let by_name = || {
            a_name
                .to_lowercase()
                .cmp(&b_name.to_lowercase())
                .then_with(|| a_name.cmp(b_name))
        };
        let order = match sort {
            Sort::Name => by_name(),
            Sort::Modified => a.modified.cmp(&b.modified).then_with(by_name),
            Sort::Size => a.size.cmp(&b.size).then_with(by_name),
        };
        by_kind.then(if descending { order.reverse() } else { order })
    });
    let total = children.len();
    let pages = total.div_ceil(PAGE_SIZE).max(1);
    let page = params.page.min(pages);
    let now = gono_server_core::db::unix_now();
    let rows: Vec<Row> = children
        .iter()
        .skip((page - 1) * PAGE_SIZE)
        .take(PAGE_SIZE)
        .map(|(name, entry)| row(visitor, now, rel, name, Meta::of(entry)))
        .collect();
    let dir_href = url(rel, true);
    let tab = |label, key: &str, this: Sort| {
        let current = sort == this;
        // The current tab switches the order; another tab starts with its default.
        let order = if current {
            if descending { "asc" } else { "desc" }
        } else if this == Sort::Name {
            "asc"
        } else {
            "desc"
        };
        Tab {
            label,
            href: format!("{dir_href}?sort={key}&order={order}"),
            current,
            descending,
        }
    };
    let tabs = vec![
        tab(t.name, "name", Sort::Name),
        tab(t.modified, "modified", Sort::Modified),
        tab(t.size, "size", Sort::Size),
    ];
    let pager = (pages > 1).then(|| {
        let link = |page: usize| {
            format!(
                "{dir_href}?sort={}&order={}&page={page}",
                encode_query(&params.sort),
                if descending { "desc" } else { "asc" }
            )
        };
        Pager {
            label: fill(t.page_of, &[&page.to_string(), &pages.to_string()]),
            prev: (page > 1).then(|| link(page - 1)),
            next: (page < pages).then(|| link(page + 1)),
        }
    });
    let (notice, error) = flashes(t, params);
    let name = folder_name(t, rel);
    let page = BrowsePage {
        chrome: visitor.chrome(Nav::Files),
        mode: Mode::Folder,
        title: name.clone(),
        heading: name.clone(),
        sub: count_items(t, total),
        // The root needs no breadcrumb: its heading says where it is.
        crumbs: if rel.is_root() {
            Vec::new()
        } else {
            crumbs(t, rel)
        },
        dir_href,
        tabs,
        empty: rows
            .is_empty()
            .then(|| (t.empty_folder.to_owned(), t.empty_folder_hint.to_owned())),
        rows,
        notice,
        error,
        pager,
        usage: usage(state, visitor).await,
        folder: name,
    };
    web::render(StatusCode::OK, &page)
}

/// Search below folder `rel`.
async fn search_page(state: &AppState, visitor: &Visitor, rel: &RelPath, q: &str) -> Response {
    let t = visitor.t();
    let q = q.trim();
    let mut chrome = visitor.chrome(Nav::Files);
    chrome.query = q.to_owned();
    let mut sub = if rel.is_root() {
        String::new()
    } else {
        fill(t.search_in, &[&display_path(rel)])
    };
    let mut rows = Vec::new();
    let mut limited = false;
    if q.chars().count() >= 2 {
        let found = match state
            .dav
            .fs()
            .meta()
            .search_names(visitor.user.user_id, rel, q, SEARCH_LIMIT + 1)
            .await
        {
            Ok(found) => found,
            Err(err) => return internal(visitor, "search", &err),
        };
        limited = found.len() > SEARCH_LIMIT;
        let now = gono_server_core::db::unix_now();
        for file in found.into_iter().take(SEARCH_LIMIT) {
            let Some(name) = file.rel_path.file_name().map(str::to_owned) else {
                continue;
            };
            let parent = file.rel_path.parent().unwrap_or_else(RelPath::root);
            // The row comes from the metadata, as the search does; the file page looks again.
            let mut row = row(visitor, now, &parent, &name, Meta::of_row(&file));
            row.location = Some(Crumb {
                name: display_path(&parent),
                href: url(&parent, true),
            });
            rows.push(row);
        }
    }
    if limited {
        let note = fill(t.search_limited, &[&SEARCH_LIMIT.to_string()]);
        sub = if sub.is_empty() {
            note
        } else {
            format!("{sub} · {note}")
        };
    }
    let empty = rows.is_empty().then(|| {
        if q.chars().count() < 2 {
            (t.search_too_short.to_owned(), String::new())
        } else {
            (t.no_results.to_owned(), String::new())
        }
    });
    let heading = fill(t.search_results, &[q]);
    let page = BrowsePage {
        chrome,
        mode: Mode::Search,
        title: t.search_title.to_owned(),
        heading,
        sub,
        crumbs: crumbs(t, &rel.join("x")),
        dir_href: url(rel, true),
        tabs: Vec::new(),
        empty,
        rows,
        notice: None,
        error: None,
        pager: None,
        usage: usage(state, visitor).await,
        folder: folder_name(t, rel),
    };
    web::render(StatusCode::OK, &page)
}

/// Every favorite of the user.
async fn favorites_page(state: &AppState, visitor: &Visitor) -> Response {
    let t = visitor.t();
    let favorites = match state
        .dav
        .fs()
        .meta()
        .favorites(visitor.user.user_id, &RelPath::root(), false)
        .await
    {
        Ok(favorites) => favorites,
        Err(err) => return internal(visitor, "favorites", &err),
    };
    let now = gono_server_core::db::unix_now();
    let mut rows = Vec::new();
    for file in favorites {
        // Look each one up again, so that the list shows what is really there.
        let Ok(entry) = state
            .dav
            .fs()
            .stat(visitor.identity.clone(), &file.rel_path)
            .await
        else {
            continue;
        };
        let Some(name) = file.rel_path.file_name().map(str::to_owned) else {
            continue;
        };
        let parent = file.rel_path.parent().unwrap_or_else(RelPath::root);
        let mut row = row(visitor, now, &parent, &name, Meta::of(&entry));
        row.location = Some(Crumb {
            name: display_path(&parent),
            href: url(&parent, true),
        });
        rows.push(row);
    }
    let count = rows.len();
    let page = BrowsePage {
        chrome: visitor.chrome(Nav::Favorites),
        mode: Mode::Favorites,
        title: t.favorites.to_owned(),
        heading: t.favorites.to_owned(),
        sub: count_items(t, count),
        crumbs: Vec::new(),
        dir_href: url(&RelPath::root(), true),
        tabs: Vec::new(),
        empty: rows
            .is_empty()
            .then(|| (t.no_favorites.to_owned(), t.no_favorites_hint.to_owned())),
        rows,
        notice: None,
        error: None,
        pager: None,
        usage: usage(state, visitor).await,
        folder: t.all_files.to_owned(),
    };
    web::render(StatusCode::OK, &page)
}

/// The first bytes of a file, as text; `None` for binary files.
async fn text_preview(
    state: &AppState,
    visitor: &Visitor,
    rel: &RelPath,
) -> Option<(String, bool)> {
    let mut file = state
        .dav
        .fs()
        .open_file(visitor.identity.clone(), rel)
        .await
        .ok()?;
    let mut data = Vec::new();
    while data.len() < TEXT_PREVIEW_BYTES {
        let chunk = file
            .read_bytes(TEXT_PREVIEW_BYTES - data.len())
            .await
            .ok()?;
        if chunk.is_empty() {
            break;
        }
        data.extend_from_slice(&chunk);
    }
    let truncated = data.len() >= TEXT_PREVIEW_BYTES
        && !file
            .read_bytes(1)
            .await
            .ok()
            .is_none_or(|more| more.is_empty());
    if data.contains(&0) {
        return None;
    }
    Some((String::from_utf8_lossy(&data).into_owned(), truncated))
}

async fn file_page(
    state: &AppState,
    visitor: &Visitor,
    rel: &RelPath,
    entry: &Entry,
    params: &Params,
) -> Response {
    let t = visitor.t();
    let name = rel.file_name().unwrap_or_default().to_owned();
    let parent = rel.parent().unwrap_or_else(RelPath::root);
    let now = gono_server_core::db::unix_now();
    let row = row(visitor, now, &parent, &name, Meta::of(entry));
    let preview = Preview::of(&name);
    let (text, truncated) = if preview == Preview::Text {
        match text_preview(state, visitor, rel).await {
            Some((text, truncated)) => (Some(text), truncated),
            None => (None, false),
        }
    } else {
        (None, false)
    };
    let (notice, error) = flashes(t, params);
    let crumbs = crumbs(t, rel);
    let page = FilePage {
        chrome: visitor.chrome(Nav::Files),
        crumbs,
        kind: row.kind_label.clone(),
        raw_href: format!("{}?raw", row.href),
        row,
        preview: if preview == Preview::Text && text.is_none() {
            Preview::None
        } else {
            preview
        },
        text,
        truncated,
        notice,
        error,
    };
    web::render(StatusCode::OK, &page)
}

/// The form pages: new folder, upload, rename, delete.
fn form_page(
    visitor: &Visitor,
    dir: &RelPath,
    action: &str,
    items: Vec<String>,
    error: Option<String>,
) -> Response {
    let t = visitor.t();
    let first = items.first().cloned().unwrap_or_default();
    let (action, title, lead, note): (&'static str, String, Option<String>, Option<String>) =
        match action {
            "mkdir" => ("mkdir", t.new_folder.to_owned(), None, None),
            "upload" => ("upload", t.upload_files.to_owned(), None, None),
            "rename" if items.len() == 1 => ("rename", fill(t.rename_title, &[&first]), None, None),
            "delete" if !items.is_empty() => {
                let title = if items.len() == 1 {
                    fill(t.delete_title, &[&first])
                } else {
                    fill(t.delete_items_title, &[&items.len().to_string()])
                };
                (
                    "delete",
                    title,
                    Some(t.delete_lead.to_owned()),
                    Some(t.delete_folder_note.to_owned()),
                )
            }
            _ => {
                return web::see_other(&format!("{}?done=none", url(dir, true)), &[]);
            }
        };
    let page = FormPage {
        chrome: visitor.chrome(Nav::Files),
        crumbs: crumbs(t, &dir.join("x")),
        action,
        title,
        lead,
        note,
        dir_href: url(dir, true),
        name: if action == "rename" {
            first
        } else {
            String::new()
        },
        items,
        error,
    };
    web::render(
        if page.error.is_some() {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            StatusCode::OK
        },
        &page,
    )
}

/// The move page: the folders inside `at`, where `items` of folder `dir` can go.
async fn move_page(
    state: &AppState,
    visitor: &Visitor,
    dir: &RelPath,
    items: Vec<String>,
    at: &RelPath,
    error: Option<String>,
) -> Response {
    let t = visitor.t();
    if items.is_empty() {
        return web::see_other(&format!("{}?done=none", url(dir, true)), &[]);
    }
    let Ok((_, children)) = state.dav.fs().list(visitor.identity.clone(), at).await else {
        return Box::pin(move_page(
            state,
            visitor,
            dir,
            items,
            &RelPath::root(),
            error,
        ))
        .await;
    };
    let moving: Vec<RelPath> = items.iter().map(|item| dir.join(item)).collect();
    let mut choices: Vec<Choice> = children
        .iter()
        .filter(|(_, entry)| entry.is_dir())
        .map(|(name, _)| at.join(name))
        // A folder cannot go into itself.
        .filter(|path| !moving.iter().any(|moved| path.starts_with(moved)))
        .map(|path| Choice {
            name: path.file_name().unwrap_or_default().to_owned(),
            path: display_path(&path),
        })
        .collect();
    choices.sort_by_key(|choice| choice.name.to_lowercase());
    let title = if items.len() == 1 {
        fill(t.move_title, &[&items[0]])
    } else {
        fill(t.move_items_title, &[&items.len().to_string()])
    };
    let page = MovePage {
        chrome: visitor.chrome(Nav::Files),
        crumbs: crumbs(t, &dir.join("x")),
        title,
        dir_href: url(dir, true),
        items,
        at: display_path(at),
        at_label: fill(t.current_folder, &[&display_path(at)]),
        up: at.parent().map(|parent| display_path(&parent)),
        choices,
        error,
    };
    web::render(StatusCode::OK, &page)
}

// ---------------------------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------------------------

/// Adds the headers of user content (see the module documentation).
fn sandbox(headers: &mut HeaderMap) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// A file through a WebDAV `GET` (ranges and conditional requests included): as an
/// attachment, or inline for the preview of images, video and audio.
async fn download(
    state: &AppState,
    visitor: &Visitor,
    rel: &RelPath,
    headers: &HeaderMap,
    method: &Method,
    inline: bool,
) -> Response {
    let name = rel.file_name().unwrap_or_default();
    let inline_type = if inline {
        match Preview::of(name).inline_type() {
            Some(kind) => Some(kind),
            None => return not_found(visitor),
        }
    } else {
        None
    };
    let passed: Vec<_> = [
        header::RANGE,
        header::IF_RANGE,
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_MATCH,
    ]
    .into_iter()
    .filter_map(|name| headers.get(&name).map(|value| (name, value.clone())))
    .collect();
    let response = dav(
        state,
        &visitor.identity,
        method.as_str(),
        &dav_path(rel, false),
        &passed,
        Body::empty(),
    )
    .await;
    let mut response = response.map(Body::new);
    if let Some(kind) = inline_type {
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline"),
        );
    }
    sandbox(response.headers_mut());
    response
}

/// Streams a `.zip` of folder `dir`, or of `items` inside it.
async fn zip_download(
    state: &AppState,
    files: &Arc<Files>,
    visitor: &Visitor,
    dir: &RelPath,
    items: Option<Vec<String>>,
) -> Response {
    let back = |code: &str| web::see_other(&format!("{}?error={code}", url(dir, true)), &[]);
    let fs = state.dav.fs().clone();
    let identity = visitor.identity.clone();
    // What goes into the archive: (name in the archive, path).
    let roots: Vec<(String, RelPath)> = match &items {
        Some(items) => items
            .iter()
            .filter_map(|item| normalize_segment(item.as_bytes()).ok())
            .map(|name| (name.clone(), dir.join(&name)))
            .collect(),
        None => vec![(folder_name(visitor.t(), dir), dir.clone())],
    };
    if roots.is_empty() {
        return web::see_other(&format!("{}?done=none", url(dir, true)), &[]);
    }
    // Count before sending anything: afterwards the status cannot change any more.
    let mut count = 0;
    for (_, path) in &roots {
        count += 1;
        match fs.meta().count_below(visitor.user.user_id, path).await {
            Ok(below) => count += below,
            Err(err) => return internal(visitor, "zip count", &err),
        }
    }
    if count > MAX_ZIP_ENTRIES {
        return back("too-big");
    }
    let Some(permit) = files.zip_permit(visitor.user.user_id) else {
        return back("busy");
    };
    let archive_name = format!(
        "{}.zip",
        match (&items, dir.file_name()) {
            (None, _) | (_, Some(_)) => folder_name(visitor.t(), dir),
            (Some(_), None) => "Files".to_owned(),
        }
    );
    let (sender, receiver) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(err) = write_zip(&fs, identity, roots, &sender).await {
            tracing::warn!(error = %err, "web file UI: zip download ended early");
            let _ = sender.send(Err(err)).await;
        }
    });
    let body = Body::from_stream(futures_util::stream::unfold(
        receiver,
        |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) },
    ));
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        gono_server_dav::service::attachment(archive_name.as_bytes()),
    );
    sandbox(headers);
    response
}

/// Sends the archive of `roots` to `sender`, walking folders depth first.
async fn write_zip(
    fs: &gono_server_dav::ScopedFs,
    identity: Arc<Identity>,
    roots: Vec<(String, RelPath)>,
    sender: &mpsc::Sender<Result<Bytes, std::io::Error>>,
) -> std::io::Result<()> {
    let send = |bytes: Vec<u8>| async move {
        sender
            .send(Ok(Bytes::from(bytes)))
            .await
            .map_err(|_| std::io::Error::other("the client went away"))
    };
    let mut zip = ZipWriter::new();
    let mut entries = 0i64;
    // (name in the archive, path), last one first.
    let mut stack: Vec<(String, RelPath)> = roots.into_iter().rev().collect();
    while let Some((name, path)) = stack.pop() {
        entries += 1;
        if entries > MAX_ZIP_ENTRIES {
            return Err(std::io::Error::other("too many entries"));
        }
        let Ok(entry) = fs.stat(identity.clone(), &path).await else {
            // Gone in the meantime.
            continue;
        };
        let mtime = unix(entry.modified);
        if entry.is_dir() {
            send(zip.dir(&format!("{name}/"), mtime)).await?;
            let Ok((_, mut children)) = fs.list(identity.clone(), &path).await else {
                continue;
            };
            children.sort_by(|a, b| b.0.cmp(&a.0));
            for (child, _) in children {
                stack.push((format!("{name}/{child}"), path.join(&child)));
            }
            continue;
        }
        let Ok(mut file) = fs.open_file(identity.clone(), &path).await else {
            continue;
        };
        send(zip.begin_file(&name, mtime, entry.size)).await?;
        let mut crc = crc32fast::Hasher::new();
        let mut size = 0u64;
        loop {
            let chunk = file
                .read_bytes(256 * 1024)
                .await
                .map_err(|err| std::io::Error::other(format!("{err:?}")))?;
            if chunk.is_empty() {
                break;
            }
            crc.update(&chunk);
            size += chunk.len() as u64;
            sender
                .send(Ok(chunk))
                .await
                .map_err(|_| std::io::Error::other("the client went away"))?;
        }
        send(zip.end_file(crc.finalize(), size)?).await?;
    }
    send(zip.finish()).await
}

// ---------------------------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------------------------

/// The fields of a form post.
#[derive(Debug, Default)]
struct FormFields {
    csrf: String,
    action: String,
    name: String,
    items: Vec<String>,
    value: String,
    at: String,
    go: Option<String>,
    back: String,
    confirm: bool,
}

async fn read_form(request: Request) -> Option<FormFields> {
    let bytes = axum::body::to_bytes(request.into_body(), MAX_FORM_BYTES)
        .await
        .ok()?;
    let mut fields = FormFields::default();
    for (key, value) in url::form_urlencoded::parse(&bytes) {
        let value = value.into_owned();
        match key.as_ref() {
            "csrf" => fields.csrf = value,
            "action" => fields.action = value,
            "name" => fields.name = value,
            "item" => fields.items.push(value),
            "value" => fields.value = value,
            "at" => fields.at = value,
            "go" => fields.go = Some(value),
            "back" => fields.back = value,
            "confirm" => fields.confirm = true,
            _ => {}
        }
    }
    Some(fields)
}

/// `303` to folder `dir` with a flash message.
fn done(dir: &RelPath, query: &str) -> Response {
    web::see_other(&format!("{}?{query}", url(dir, true)), &[])
}

async fn post_form(
    state: &AppState,
    files: &Arc<Files>,
    visitor: &Visitor,
    dir: RelPath,
    params: Params,
    request: Request,
) -> Response {
    let t = visitor.t();
    match state.dav.fs().stat(visitor.identity.clone(), &dir).await {
        Ok(entry) if entry.is_dir() => {}
        _ => return not_found(visitor),
    }
    if params.upload {
        let token = visitor.token.clone();
        let web = state.web.clone();
        return match upload::form(state, &visitor.identity, &dir, request, |csrf| {
            web.check_session_csrf(&token, csrf)
        })
        .await
        {
            Ok(outcome) => match outcome.error {
                Some(err) if outcome.uploaded == 0 => done(&dir, &format!("error={}", err.code())),
                Some(err) => done(
                    &dir,
                    &format!("done=uploaded&n={}&error={}", outcome.uploaded, err.code()),
                ),
                None => done(
                    &dir,
                    &format!(
                        "done=uploaded&n={}&skipped={}",
                        outcome.uploaded, outcome.skipped
                    ),
                ),
            },
            Err(StatusCode::FORBIDDEN) => blocked(visitor, |t| t.form_expired),
            Err(status) => message(visitor, status, t.bad_request, t.err_failed),
        };
    }
    let Some(form) = read_form(request).await else {
        return message(
            visitor,
            StatusCode::PAYLOAD_TOO_LARGE,
            t.bad_request,
            t.err_failed,
        );
    };
    if !state.web.check_session_csrf(&visitor.token, &form.csrf) {
        return blocked(visitor, |t| t.form_expired);
    }
    // Entries of this folder only: one segment each.
    let mut items = Vec::new();
    for item in &form.items {
        match normalize_segment(item.as_bytes()) {
            Ok(name) => items.push(name),
            Err(_) => return done(&dir, &format!("error={}", OpError::Name.code())),
        }
    }
    let identity = &visitor.identity;
    match form.action.as_str() {
        "mkdir" => {
            let Ok(name) = normalize_segment(form.name.trim().as_bytes()) else {
                return form_page(
                    visitor,
                    &dir,
                    "mkdir",
                    Vec::new(),
                    Some(t.err_name.to_owned()),
                );
            };
            match ops::mkdir(state, identity, &dir.join(&name)).await {
                Ok(()) => done(&dir, &format!("done=created&name={}", encode_query(&name))),
                Err(err) => form_page(
                    visitor,
                    &dir,
                    "mkdir",
                    Vec::new(),
                    Some(err.message(t).to_owned()),
                ),
            }
        }
        "rename" => {
            let [item] = items.as_slice() else {
                return done(&dir, "done=none");
            };
            let Ok(name) = normalize_segment(form.name.trim().as_bytes()) else {
                return form_page(
                    visitor,
                    &dir,
                    "rename",
                    items.clone(),
                    Some(t.err_name.to_owned()),
                );
            };
            let from = dir.join(item);
            let is_dir = match state.dav.fs().stat(identity.clone(), &from).await {
                Ok(entry) => entry.is_dir(),
                Err(_) => return done(&dir, &format!("error={}", OpError::NotFound.code())),
            };
            match ops::move_to(state, identity, &from, &dir.join(&name), is_dir).await {
                Ok(()) => done(&dir, &format!("done=renamed&name={}", encode_query(&name))),
                Err(err) => form_page(
                    visitor,
                    &dir,
                    "rename",
                    items.clone(),
                    Some(err.message(t).to_owned()),
                ),
            }
        }
        "delete" => {
            if items.is_empty() {
                return done(&dir, "done=none");
            }
            if !form.confirm {
                return form_page(visitor, &dir, "delete", items, None);
            }
            let mut failed = 0;
            let mut first = None;
            for item in &items {
                let path = dir.join(item);
                let result = match state.dav.fs().stat(identity.clone(), &path).await {
                    Ok(entry) => ops::delete(state, identity, &path, entry.is_dir()).await,
                    Err(_) => Err(OpError::NotFound),
                };
                if let Err(err) = result {
                    failed += 1;
                    first.get_or_insert(err);
                }
            }
            finish(&dir, "deleted", items.len(), failed, first)
        }
        "move" => {
            if items.is_empty() {
                return done(&dir, "done=none");
            }
            let at = |value: &str| RelPath::parse(value).unwrap_or_else(|_| RelPath::root());
            if let Some(go) = &form.go {
                return move_page(state, visitor, &dir, items, &at(go), None).await;
            }
            if !form.confirm {
                return move_page(state, visitor, &dir, items, &dir, None).await;
            }
            let to = at(&form.at);
            let mut failed = 0;
            let mut first = None;
            for item in &items {
                let from = dir.join(item);
                let result = match state.dav.fs().stat(identity.clone(), &from).await {
                    Ok(entry) => {
                        ops::move_to(state, identity, &from, &to.join(item), entry.is_dir()).await
                    }
                    Err(_) => Err(OpError::NotFound),
                };
                if let Err(err) = result {
                    failed += 1;
                    first.get_or_insert(err);
                }
            }
            if failed == items.len()
                && let Some(err) = first
            {
                return move_page(
                    state,
                    visitor,
                    &dir,
                    items,
                    &to,
                    Some(err.message(t).to_owned()),
                )
                .await;
            }
            finish(&dir, "moved", items.len(), failed, first)
        }
        "zip" => {
            if items.is_empty() {
                return done(&dir, "done=none");
            }
            zip_download(state, files, visitor, &dir, Some(items)).await
        }
        "favorite" => {
            let [item] = items.as_slice() else {
                return done(&dir, "done=none");
            };
            let on = form.value == "1";
            let path = dir.join(item);
            let result = match state.dav.fs().stat(identity.clone(), &path).await {
                Ok(entry) => match entry.file_id {
                    Some(id) => state
                        .dav
                        .fs()
                        .meta()
                        .set_favorite(id, on)
                        .await
                        .map_err(|err| {
                            tracing::error!(error = %err, "cannot set a favorite");
                            OpError::Failed
                        }),
                    None => Err(OpError::Forbidden),
                },
                Err(_) => Err(OpError::NotFound),
            };
            let back = crate::site::local_path(&form.back)
                .filter(|back| back.starts_with(PREFIX))
                .map(|back| back.split(['?', '#']).next().unwrap_or(back).to_owned());
            let code = match result {
                Ok(()) if on => "done=favorite".to_owned(),
                Ok(()) => "done=unfavorite".to_owned(),
                Err(err) => format!("error={}", err.code()),
            };
            match back {
                // Back to the page the star was on (a file page or the favorites).
                Some(back) => {
                    let separator = if back.contains('?') { '&' } else { '?' };
                    web::see_other(&format!("{back}{separator}{code}"), &[])
                }
                None => done(&dir, &code),
            }
        }
        _ => message(
            visitor,
            StatusCode::BAD_REQUEST,
            t.bad_request,
            t.unknown_action,
        ),
    }
}

/// The redirect after a bulk operation on `total` entries of which `failed` failed.
fn finish(
    dir: &RelPath,
    what: &str,
    total: usize,
    failed: usize,
    first: Option<OpError>,
) -> Response {
    match (failed, first) {
        (0, _) | (_, None) => done(dir, &format!("done={what}&n={total}")),
        (failed, Some(err)) if failed == total => done(dir, &format!("error={}", err.code())),
        (failed, Some(_)) => done(
            dir,
            &format!(
                "done={what}&n={}&error=partial&f={failed}&of={total}",
                total - failed
            ),
        ),
    }
}

#[cfg(test)]
mod tests;
