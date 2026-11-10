//! Chunked upload v2 (`/remote.php/dav/uploads/<user>/<upload id>/...`).
//!
//! Clients upload large files in pieces into an upload session and then ask the server to
//! assemble them at the destination:
//!
//! | Request | Effect |
//! |---|---|
//! | `MKCOL <session>` | Creates the session. `Destination` (the final URL under `/remote.php/dav/files/<user>/`) and `OC-Total-Length` are recorded when sent; older clients send the destination only with the `MOVE`. |
//! | `PUT <session>/<name>` | Stores a chunk (see [chunk names](#chunk-names)). A `Destination` must match the session's. |
//! | `PROPFIND <session>` | Lists the chunks received so far (`Depth: 1`), so that an interrupted upload can resume. |
//! | `MOVE <session>/.file` | Assembles the chunks in order into `Destination`: `201` for a new file, `204` for a replaced one, with `ETag`, `OC-ETag`, `OC-FileId` and `X-OC-MTime`. |
//! | `DELETE <session>` / `DELETE <session>/<name>` | Cancels the upload / drops one chunk. |
//!
//! # Chunk names
//!
//! A session holds chunks of one of two kinds; a chunk of the other kind is refused with `400`:
//!
//! - **Numbers** (1 to 20 decimal digits): the Nextcloud clients number their chunks (chunking
//!   v2 uses 1 to 10000, older clients zero-pad). They are assembled in numeric order; `1` and
//!   `00001` are the same chunk, and the newer one wins.
//! - **Byte ranges** `<start>-<end>` (two such numbers, `end` inclusive): rclone's Nextcloud
//!   backend names its chunks by the bytes they hold, for example
//!   `000000010485760-000000020971519`, and creates the session without a `Destination`. A
//!   chunk must be exactly as long as its range, and at assembly the ranges must cover the file
//!   from byte 0 without gaps or overlaps. A range replaces an older chunk with the same start.
//!
//! # Guarantees
//!
//! - **Scope and locks**: the request namespace is the authenticated user's only (checked by
//!   the router), and the destination must be writable for the app password, exactly like the
//!   target of a PUT ([`ScopedFs::upload_target`]). The destination is checked when the
//!   session is created, with every chunk and again at assembly, together with WebDAV locks
//!   (`If` header tokens, [`locks::write_conflict`]) and `If-Match` / `If-None-Match` against
//!   the file being replaced.
//! - **Length**: the assembled size must equal `OC-Total-Length` (of the `MOVE`, or of the
//!   `MKCOL`); otherwise the `MOVE` fails with `400` and nothing is written (legacy defect 5).
//!   An announced length larger than the free space is refused with `507` up front. Byte-range
//!   chunks are checked against their ranges even without `OC-Total-Length` (rclone sends none),
//!   so a missing or truncated chunk in the middle cannot produce a file with a hole. A session
//!   without any chunk is assembled only when a length of 0 was announced: Nextcloud Android
//!   never sends `OC-Total-Length`, and a `MOVE` of an empty session would otherwise replace
//!   the destination with an empty file.
//! - **Atomic and durable**: chunks are written to `tmp/` and synced before they appear in the
//!   session directory. The assembly writes a new file in `tmp/`, syncs it and renames it over
//!   the destination ([`ScopedFs::install_file`], which also syncs the directory), and the
//!   MetaStore records the new version in one transaction: one file id kept on overwrite,
//!   ancestor ETags and sizes, the change log. The assembly runs to completion even if the
//!   client disconnects.
//! - **Concurrency**: requests on one session are serialized where it matters (installing a
//!   chunk, assembling, cancelling); chunk bodies are received in parallel.
//! - **Cleanup**: sessions expire [`uploads::SESSION_TTL_SECS`] after their last chunk. A
//!   background task calls [`ChunkedUploads::purge`]; requests never clean up.
//!
//! Chunks live in [`DataLayout::upload_session_dir`], named exactly as the client sent them,
//! so that a resuming client finds its own names in the listing.

mod propfind;

use std::{
    collections::HashMap,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use dav_server::fs::FsError;
use gono_server_core::{
    db::{self, Pool},
    locks::LockStore,
    storage::{DataLayout, create_private_dir_all, upload_session_dir_name},
    uploads::{self, UploadSession},
};
use gono_server_dav::{
    Ctx, DavBody, Identity, OcInfo, RequestInfo, ScopedFs,
    fs::free_space,
    locks,
    resolve::{self, Location},
    service::parse_destination,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body::Body;
use http_body_util::{BodyExt as _, Empty, Full};
use rand::RngExt as _;
use tokio::io::AsyncWriteExt as _;

/// Prefix of the upload namespace (followed by the username).
pub const UPLOADS_ROOT: &str = "/remote.php/dav/uploads/";

/// Most chunks one session may hold (Nextcloud's limit for chunking v2).
pub const MAX_CHUNKS: usize = 10_000;

/// Longest accepted upload id, in bytes.
const MAX_UPLOAD_ID_BYTES: usize = 255;

/// Longest accepted chunk number or byte offset, in digits.
const MAX_CHUNK_NAME_DIGITS: usize = 20;

/// Name of the virtual file whose `MOVE` assembles the upload.
const ASSEMBLE: &str = ".file";

/// Orphaned session directories (no session row) younger than this are left alone: a `MKCOL`
/// may be creating one right now.
const ORPHAN_GRACE: Duration = Duration::from_secs(60 * 60);

/// The chunked upload endpoint. Cheap to clone.
#[derive(Clone)]
pub struct ChunkedUploads {
    inner: Arc<Inner>,
}

/// One mutex per session that a request is working on, keyed by owner and upload id.
type Busy = Mutex<HashMap<(i64, String), Arc<tokio::sync::Mutex<()>>>>;

struct Inner {
    fs: ScopedFs,
    locks: LockStore,
    busy: Busy,
}

impl std::fmt::Debug for ChunkedUploads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkedUploads").finish_non_exhaustive()
    }
}

/// What a path in the upload namespace names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// `/remote.php/dav/uploads/<user>/`.
    Root,
    /// An upload session.
    Session(String),
    /// A chunk, or `.file`, of a session.
    Chunk(String, String),
}

/// A response that ends request handling early.
type Reject = Box<Response<DavBody>>;

fn empty(status: StatusCode) -> Response<DavBody> {
    let mut response = Response::new(Empty::new().map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

fn xml(status: StatusCode, body: String) -> Response<DavBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

/// An error in the format Nextcloud (SabreDAV) uses; the desktop client shows `s:message`.
fn error(status: StatusCode, message: &str) -> Reject {
    let exception = match status {
        StatusCode::BAD_REQUEST => "BadRequest",
        StatusCode::FORBIDDEN => "Forbidden",
        StatusCode::NOT_FOUND => "NotFound",
        StatusCode::METHOD_NOT_ALLOWED => "MethodNotAllowed",
        StatusCode::CONFLICT => "Conflict",
        StatusCode::PRECONDITION_FAILED => "PreconditionFailed",
        StatusCode::LOCKED => "Locked",
        StatusCode::INSUFFICIENT_STORAGE => "InsufficientStorage",
        _ => "ServiceUnavailable",
    };
    let message = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    Box::new(xml(
        status,
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error xmlns:d=\"DAV:\" \
             xmlns:s=\"http://sabredav.org/ns\"><s:exception>Sabre\\DAV\\Exception\\{exception}\
             </s:exception><s:message>{message}</s:message></d:error>\n"
        ),
    ))
}

fn internal(context: &str, err: &dyn std::fmt::Debug) -> Reject {
    tracing::error!(error = ?err, "chunked upload: {context}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

fn fs_error(err: FsError, context: &str) -> Reject {
    match err {
        FsError::Forbidden => error(StatusCode::FORBIDDEN, "Not allowed to write there"),
        FsError::NotFound => error(StatusCode::CONFLICT, "The parent folder does not exist"),
        FsError::Exists => error(StatusCode::CONFLICT, "A folder exists at the destination"),
        FsError::InsufficientStorage => {
            error(StatusCode::INSUFFICIENT_STORAGE, "Insufficient storage")
        }
        other => internal(context, &other),
    }
}

/// What a chunk name says about the chunk's place in the file (see "Chunk names" in the
/// module documentation).
///
/// The derived order is the assembly order within one session, which holds one kind only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ChunkName {
    /// A chunk number.
    Number(u64),
    /// The bytes `start..=end` of the file.
    Range { start: u64, end: u64 },
}

impl ChunkName {
    /// Parses a number of 1 to 20 decimal digits, or two of them joined by `-` with the end not
    /// before the start.
    fn parse(name: &str) -> Option<Self> {
        fn number(digits: &str) -> Option<u64> {
            if digits.is_empty()
                || digits.len() > MAX_CHUNK_NAME_DIGITS
                || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            digits.parse().ok()
        }
        match name.split_once('-') {
            None => number(name).map(Self::Number),
            Some((start, end)) => {
                let (start, end) = (number(start)?, number(end)?);
                (start <= end).then_some(Self::Range { start, end })
            }
        }
    }

    /// The chunk's place in the file: chunks of the same place replace each other (`1` and
    /// `00001`, or two ranges with the same start).
    fn position(self) -> u64 {
        match self {
            Self::Number(number) => number,
            Self::Range { start, .. } => start,
        }
    }

    /// Whether `other` is of the same kind (number or byte range).
    fn same_kind(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Number(_), Self::Number(_)) | (Self::Range { .. }, Self::Range { .. })
        )
    }

    /// The exact length of a byte-range chunk.
    fn range_len(self) -> Option<u64> {
        match self {
            Self::Number(_) => None,
            Self::Range { start, end } => Some((end - start).saturating_add(1)),
        }
    }
}

/// A stored chunk: its parsed name, file name, length and modification time.
type StoredChunk = (ChunkName, String, u64, SystemTime);

/// Checks that `chunks` (in assembly order) can be assembled: all of one kind, and byte ranges
/// as long as their ranges and covering the file from byte 0 without gaps or overlaps.
fn check_assembly(chunks: &[StoredChunk]) -> Result<(), String> {
    let Some((first, ..)) = chunks.first() else {
        return Ok(());
    };
    let mut next = 0;
    for (chunk, name, size, _) in chunks {
        if !chunk.same_kind(*first) {
            return Err("The upload mixes numbered chunks and byte ranges".to_owned());
        }
        if let ChunkName::Range { start, end } = *chunk {
            if start != next {
                return Err(format!(
                    "Chunk {name} starts at byte {start}, expected {next}"
                ));
            }
            if Some(*size) != chunk.range_len() {
                return Err(format!("Chunk {name} holds {size} bytes"));
            }
            next = end.saturating_add(1);
        }
    }
    Ok(())
}

fn valid_upload_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_UPLOAD_ID_BYTES
        && id != "."
        && id != ".."
        && !id.chars().any(|c| c.is_control() || c == '/')
}

fn percent_decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode(segment: &str) -> String {
    segment
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Parses the request path for `username`.
fn parse_target(path: &str, username: &str) -> Result<Target, Reject> {
    let rest = path
        .strip_prefix(UPLOADS_ROOT)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "Not an upload path"))?;
    let segments: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
    let decoded: Vec<String> = segments
        .iter()
        .map(|segment| percent_decode(segment))
        .collect::<Option<_>>()
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Invalid upload path"))?;
    if decoded.first().map(String::as_str) != Some(username) {
        return Err(error(StatusCode::FORBIDDEN, "Not your upload namespace"));
    }
    match &decoded[1..] {
        [] => Ok(Target::Root),
        [id] if valid_upload_id(id) => Ok(Target::Session(id.clone())),
        [id, chunk] if valid_upload_id(id) && !chunk.is_empty() => {
            Ok(Target::Chunk(id.clone(), chunk.clone()))
        }
        _ => Err(error(StatusCode::NOT_FOUND, "No such upload path")),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
}

/// `OC-Total-Length`, if sent. A value that is not a non-negative integer is a `400`.
fn total_length(headers: &HeaderMap) -> Result<Option<u64>, Reject> {
    match headers.get("oc-total-length") {
        None => Ok(None),
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(Some)
            .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Invalid OC-Total-Length")),
    }
}

/// `X-OC-MTime` (UNIX seconds, a fraction truncated), if sent and positive.
fn oc_mtime(headers: &HeaderMap) -> Option<i64> {
    header_str(headers, "x-oc-mtime")
        .and_then(gono_server_dav::ctx::oc_time_seconds)
        .filter(|&mtime| mtime > 0)
}

/// Whether `If-Match` / `If-None-Match` allow replacing `current`.
fn preconditions_hold(headers: &HeaderMap, current: Option<&str>) -> bool {
    let tags = |name: &str| -> Option<Vec<String>> {
        let value = header_str(headers, name)?;
        Some(
            value
                .split(',')
                .map(|tag| tag.trim().trim_start_matches("W/").to_owned())
                .collect(),
        )
    };
    let matches = |list: &[String]| {
        list.iter()
            .any(|tag| tag == "*" && current.is_some() || Some(tag.as_str()) == current)
    };
    if let Some(list) = tags("if-match")
        && !matches(&list)
    {
        return false;
    }
    if let Some(list) = tags("if-none-match")
        && matches(&list)
    {
        return false;
    }
    true
}

/// Lists the chunks of a session directory in assembly order.
fn list_chunks(dir: &Path) -> io::Result<Vec<StoredChunk>> {
    let mut chunks = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(chunks),
        Err(err) => return Err(err),
    };
    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let (true, Some(chunk)) = (meta.is_file(), ChunkName::parse(&name)) {
            chunks.push((
                chunk,
                name,
                meta.len(),
                meta.modified().unwrap_or(UNIX_EPOCH),
            ));
        }
    }
    chunks.sort();
    Ok(chunks)
}

async fn blocking<T, F>(f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(io::Error::other)?
}

/// A private file in `tmp/`.
fn temp_file(tmp_dir: &Path, suffix: &str) -> io::Result<(PathBuf, std::fs::File)> {
    let path = tmp_dir.join(format!("{:032x}.{suffix}", rand::rng().random::<u128>()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(&path)?;
    Ok((path, file))
}

impl ChunkedUploads {
    /// Creates the endpoint over the file system of the WebDAV service and its lock store.
    pub fn new(fs: ScopedFs, locks: LockStore) -> Self {
        Self {
            inner: Arc::new(Inner {
                fs,
                locks,
                busy: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn fs(&self) -> &ScopedFs {
        &self.inner.fs
    }

    fn layout(&self) -> &DataLayout {
        self.inner.fs.layout()
    }

    fn pool(&self) -> &Pool {
        self.inner.fs.meta().pool()
    }

    /// Serializes work on one session.
    async fn lock_session(&self, owner: i64, upload_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let mutex = {
            let mut busy = self
                .inner
                .busy
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            busy.retain(|_, mutex| Arc::strong_count(mutex) > 1);
            busy.entry((owner, upload_id.to_owned()))
                .or_default()
                .clone()
        };
        mutex.lock_owned().await
    }

    async fn session(&self, owner: i64, upload_id: &str) -> Result<UploadSession, Reject> {
        uploads::get(self.pool(), owner, upload_id, db::unix_now())
            .await
            .map_err(|err| internal("load session", &err))?
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Upload session not found"))
    }

    /// Resolves a `Destination` header to a location the identity may write.
    fn destination(ctx: &Ctx, value: &str) -> Result<Location, Reject> {
        let path = parse_destination(ctx.identity(), value).map_err(|status| {
            error(
                status,
                if status == StatusCode::FORBIDDEN {
                    "Destination outside your files"
                } else {
                    "Invalid Destination"
                },
            )
        })?;
        ScopedFs::upload_target(ctx, &path).map_err(|err| match err {
            FsError::NotFound | FsError::Forbidden => error(
                StatusCode::FORBIDDEN,
                "Not allowed to write the destination",
            ),
            other => fs_error(other, "resolve destination"),
        })
    }

    /// Refuses the request with `423` if a lock it does not hold covers `location`.
    async fn check_lock(
        &self,
        ctx: &Ctx,
        location: &Location,
        headers: &HeaderMap,
    ) -> Result<(), Reject> {
        let Some(storage) = location.storage() else {
            return Ok(());
        };
        let identity = ctx.identity();
        let tokens = locks::submitted_tokens(headers);
        match locks::write_conflict(
            &self.inner.locks,
            identity.user_id,
            storage,
            identity.username.as_str(),
            &tokens,
        )
        .await
        {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(error(StatusCode::LOCKED, "The destination is locked")),
            Err(err) => Err(internal("check locks", &err)),
        }
    }

    /// Handles one request of `identity` in its upload namespace.
    pub async fn handle<B>(&self, identity: Arc<Identity>, request: Request<B>) -> Response<DavBody>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let (parts, body) = request.into_parts();
        let target = match parse_target(parts.uri.path(), identity.username.as_str()) {
            Ok(target) => target,
            Err(response) => return *response,
        };
        let mut info = RequestInfo::new(Method::PUT);
        // The creation time of an assembled file comes with the final `MOVE`.
        info.oc_ctime = gono_server_dav::ctx::oc_ctime(&parts.headers);
        let ctx = Ctx::new(identity, info);
        let result = match (parts.method.as_str(), &target) {
            ("MKCOL", Target::Session(id)) => self.create(&ctx, id, &parts.headers).await,
            ("PUT", Target::Chunk(id, name)) => {
                self.put_chunk(&ctx, id, name, &parts.headers, body).await
            }
            ("MOVE", Target::Chunk(id, name)) if name == ASSEMBLE => {
                self.assemble(&ctx, id, &parts.headers).await
            }
            ("DELETE", Target::Session(id)) => self.cancel(&ctx, id).await,
            ("DELETE", Target::Chunk(id, name)) => self.delete_chunk(&ctx, id, name).await,
            ("PROPFIND", _) => self.propfind(&ctx, &target, &parts.headers, body).await,
            ("OPTIONS", _) => {
                let mut response = empty(StatusCode::OK);
                response.headers_mut().insert(
                    header::ALLOW,
                    HeaderValue::from_static("OPTIONS, PROPFIND, MKCOL, PUT, MOVE, DELETE"),
                );
                response
                    .headers_mut()
                    .insert("dav", HeaderValue::from_static("1"));
                Ok(response)
            }
            ("MKCOL", Target::Root) => Err(error(
                StatusCode::METHOD_NOT_ALLOWED,
                "The upload namespace exists",
            )),
            _ => Err(error(
                StatusCode::METHOD_NOT_ALLOWED,
                "Not supported in the upload namespace",
            )),
        };
        result.unwrap_or_else(|response| *response)
    }

    /// `MKCOL <session>`.
    async fn create(
        &self,
        ctx: &Ctx,
        upload_id: &str,
        headers: &HeaderMap,
    ) -> Result<Response<DavBody>, Reject> {
        let location = match header_str(headers, "destination") {
            Some(value) => Some(Self::destination(ctx, value)?),
            None => None,
        };
        let total = total_length(headers)?;
        if let Some(total) = total {
            let uploads = self.layout().uploads_root();
            let free = blocking(move || Ok(free_space(&uploads)))
                .await
                .map_err(|err| internal("free space", &err))?;
            if free.is_some_and(|free| free < total) {
                return Err(error(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Not enough free space for the announced upload",
                ));
            }
        }
        if let Some(location) = &location {
            self.check_lock(ctx, location, headers).await?;
        }

        let owner = ctx.identity().user_id;
        let created = uploads::create(
            self.pool(),
            owner,
            upload_id,
            location.as_ref().and_then(Location::storage),
            total,
            db::unix_now(),
        )
        .await
        .map_err(|err| internal("create session", &err))?;
        if !created {
            return Err(error(
                StatusCode::METHOD_NOT_ALLOWED,
                "The upload session exists already",
            ));
        }
        let dir = self.layout().upload_session_dir(owner, upload_id);
        if let Err(err) = blocking(move || {
            // A directory left over by an expired session with the same id is stale.
            if dir.exists() {
                std::fs::remove_dir_all(&dir)?;
            }
            create_private_dir_all(&dir).map_err(io::Error::other)
        })
        .await
        {
            let _ = uploads::delete(self.pool(), owner, upload_id).await;
            return Err(internal("create session directory", &err));
        }
        Ok(empty(StatusCode::CREATED))
    }

    /// `PUT <session>/<name>`.
    async fn put_chunk<B>(
        &self,
        ctx: &Ctx,
        upload_id: &str,
        name: &str,
        headers: &HeaderMap,
        body: B,
    ) -> Result<Response<DavBody>, Reject>
    where
        B: Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let Some(chunk) = ChunkName::parse(name) else {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "Chunk names must be decimal numbers or byte ranges (<start>-<end>)",
            ));
        };
        let identity = ctx.identity();
        let owner = identity.user_id;
        let session = self.session(owner, upload_id).await?;
        let named = match header_str(headers, "destination") {
            Some(value) => Some(Self::destination(ctx, value)?),
            None => None,
        };
        if let (Some(target), Some(named)) = (&session.target, &named)
            && Some(target) != named.storage()
        {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "Destination does not match the upload session",
            ));
        }
        let location = match (&session.target, named) {
            (Some(target), _) => Some(
                resolve::writable_location(identity, target)
                    .ok_or_else(|| error(StatusCode::FORBIDDEN, "Not allowed to write there"))?,
            ),
            (None, named) => named,
        };
        if let Some(location) = &location {
            self.check_lock(ctx, location, headers).await?;
        }

        let length = header_str(headers, header::CONTENT_LENGTH.as_str())
            .and_then(|value| value.parse::<u64>().ok());
        if let (Some(expected), Some(length)) = (chunk.range_len(), length)
            && expected != length
        {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "The chunk length does not match its byte range",
            ));
        }
        let dir = self.layout().upload_session_dir(owner, upload_id);
        if let (Some(total), Some(length)) = (session.total_size, length) {
            let listing_dir = dir.clone();
            let chunks = blocking(move || list_chunks(&listing_dir))
                .await
                .map_err(|err| internal("list chunks", &err))?;
            let others: u64 = chunks
                .iter()
                .filter(|(other, _, _, _)| other.position() != chunk.position())
                .map(|(_, _, size, _)| size)
                .sum();
            if others.saturating_add(length) > total {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "The chunks exceed OC-Total-Length",
                ));
            }
        }
        let tmp_dir = self.layout().tmp_dir();
        if let Some(length) = length {
            let tmp = tmp_dir.clone();
            let free = blocking(move || Ok(free_space(&tmp)))
                .await
                .map_err(|err| internal("free space", &err))?;
            if free.is_some_and(|free| free < length) {
                return Err(error(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Insufficient storage",
                ));
            }
        }

        // Receive the body without holding the session lock; chunks may arrive in parallel.
        let (temp, file) = blocking(move || temp_file(&tmp_dir, "chunk"))
            .await
            .map_err(|err| internal("create chunk file", &err))?;
        let received = receive(body, tokio::fs::File::from_std(file), length).await;
        let written = match received {
            // Without a Content-Length the length of a byte range is known only now.
            Ok(written)
                if chunk
                    .range_len()
                    .is_some_and(|expected| expected != written) =>
            {
                let _ = tokio::fs::remove_file(&temp).await;
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "The chunk length does not match its byte range",
                ));
            }
            Ok(written) => written,
            Err(reason) => {
                let _ = tokio::fs::remove_file(&temp).await;
                return Err(match reason {
                    Receive::Short => error(StatusCode::BAD_REQUEST, "Incomplete chunk"),
                    Receive::Io(err) if err.kind() == io::ErrorKind::StorageFull => {
                        error(StatusCode::INSUFFICIENT_STORAGE, "Insufficient storage")
                    }
                    Receive::Io(err) => internal("write chunk", &err),
                });
            }
        };

        // The session may have been assembled or cancelled while the body arrived.
        let _guard = self.lock_session(owner, upload_id).await;
        let still_there = uploads::touch(self.pool(), owner, upload_id, db::unix_now()).await;
        if !matches!(still_there, Ok(true)) {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(match still_there {
                Err(err) => internal("touch session", &err),
                Ok(_) => error(StatusCode::NOT_FOUND, "Upload session not found"),
            });
        }
        let chunk_name = name.to_owned();
        let installed = blocking(move || {
            create_private_dir_all(&dir).map_err(io::Error::other)?;
            let chunks = list_chunks(&dir)?;
            if chunks
                .iter()
                .any(|(other, _, _, _)| !other.same_kind(chunk))
            {
                std::fs::remove_file(&temp)?;
                return Ok(Install::MixedKinds);
            }
            let replaced = chunks.iter().any(|(_, other, _, _)| *other == chunk_name);
            if !replaced && chunks.len() >= MAX_CHUNKS {
                std::fs::remove_file(&temp)?;
                return Ok(Install::TooMany);
            }
            // "1" and "00001" are the same chunk, as are two ranges with the same start: the
            // newer one wins.
            for (other, other_name, _, _) in &chunks {
                if other.position() == chunk.position() && *other_name != chunk_name {
                    std::fs::remove_file(dir.join(other_name))?;
                }
            }
            std::fs::rename(&temp, dir.join(&chunk_name)).inspect_err(|_| {
                let _ = std::fs::remove_file(&temp);
            })?;
            Ok(Install::Stored { replaced })
        })
        .await
        .map_err(|err| internal("store chunk", &err))?;
        match installed {
            Install::TooMany => Err(error(StatusCode::BAD_REQUEST, "Too many chunks")),
            Install::MixedKinds => Err(error(
                StatusCode::BAD_REQUEST,
                "An upload cannot mix numbered chunks and byte ranges",
            )),
            Install::Stored { replaced } => {
                tracing::debug!(
                    upload = upload_id,
                    chunk = %name,
                    bytes = written,
                    "chunk stored"
                );
                Ok(empty(if replaced {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::CREATED
                }))
            }
        }
    }

    /// `MOVE <session>/.file`.
    async fn assemble(
        &self,
        ctx: &Ctx,
        upload_id: &str,
        headers: &HeaderMap,
    ) -> Result<Response<DavBody>, Reject> {
        let owner = ctx.identity().user_id;
        let _guard = self.lock_session(owner, upload_id).await;
        let session = self.session(owner, upload_id).await?;
        let destination = header_str(headers, "destination")
            .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Destination header missing"))?;
        let location = Self::destination(ctx, destination)?;
        if session
            .target
            .as_ref()
            .is_some_and(|target| Some(target) != location.storage())
        {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "Destination does not match the upload session",
            ));
        }
        let announced = total_length(headers)?;
        if let (Some(created), Some(moved)) = (session.total_size, announced)
            && created != moved
        {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "OC-Total-Length differs from the one of the upload session",
            ));
        }
        let expected = announced.or(session.total_size);
        self.check_lock(ctx, &location, headers).await?;
        let current = self
            .fs()
            .current(ctx, &location)
            .await
            .map_err(|err| fs_error(err, "look up destination"))?;
        if current.as_ref().is_some_and(|entry| entry.is_dir()) {
            return Err(error(
                StatusCode::CONFLICT,
                "A folder exists at the destination",
            ));
        }
        let current_etag = current.as_ref().map(|entry| format!("\"{}\"", entry.etag));
        if !preconditions_hold(headers, current_etag.as_deref()) {
            return Err(error(
                StatusCode::PRECONDITION_FAILED,
                "The destination has changed",
            ));
        }

        let dir = self.layout().upload_session_dir(owner, upload_id);
        let listing_dir = dir.clone();
        let chunks = blocking(move || list_chunks(&listing_dir))
            .await
            .map_err(|err| internal("list chunks", &err))?;
        if let Err(message) = check_assembly(&chunks) {
            tracing::info!(
                upload = upload_id,
                reason = %message,
                "refusing to assemble a chunked upload"
            );
            return Err(error(StatusCode::BAD_REQUEST, &message));
        }
        let size: u64 = chunks.iter().map(|(_, _, size, _)| size).sum();
        if chunks.is_empty() && expected != Some(0) {
            tracing::info!(
                upload = upload_id,
                "refusing to assemble a chunked upload without chunks"
            );
            return Err(error(
                StatusCode::BAD_REQUEST,
                "The upload session has no chunks",
            ));
        }
        if let Some(expected) = expected
            && expected != size
        {
            tracing::info!(
                upload = upload_id,
                expected,
                size,
                "refusing to assemble an incomplete chunked upload"
            );
            return Err(error(
                StatusCode::BAD_REQUEST,
                &format!("The chunks sum up to {size} bytes, but OC-Total-Length is {expected}"),
            ));
        }
        let tmp_dir = self.layout().tmp_dir();
        let tmp = tmp_dir.clone();
        let free = blocking(move || Ok(free_space(&tmp)))
            .await
            .map_err(|err| internal("free space", &err))?;
        if free.is_some_and(|free| free < size) {
            return Err(error(
                StatusCode::INSUFFICIENT_STORAGE,
                "Insufficient storage",
            ));
        }

        // Assemble and install in a task of its own, so that a client that disconnects cannot
        // stop it between the rename and the metadata update.
        let mtime = oc_mtime(headers);
        let fs = self.fs().clone();
        let task_ctx = ctx.clone();
        let names: Vec<String> = chunks.into_iter().map(|(_, name, _, _)| name).collect();
        let source_dir = dir.clone();
        let installed = tokio::spawn(async move {
            let temp = blocking(move || {
                let (temp, mut file) = temp_file(&tmp_dir, "assembly")?;
                let result = (|| {
                    for name in &names {
                        let mut chunk = std::fs::File::open(source_dir.join(name))?;
                        io::copy(&mut chunk, &mut file)?;
                    }
                    file.flush()?;
                    file.sync_all()?;
                    if let Some(mtime) = mtime {
                        let seconds = u64::try_from(mtime).unwrap_or(0);
                        file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds))?;
                    }
                    Ok(())
                })();
                match result {
                    Ok(()) => Ok(temp),
                    Err(err) => {
                        let _ = std::fs::remove_file(&temp);
                        Err(err)
                    }
                }
            })
            .await
            .map_err(|err| match err.kind() {
                io::ErrorKind::StorageFull => FsError::InsufficientStorage,
                _ => {
                    tracing::error!(error = %err, "chunked upload: assembly failed");
                    FsError::GeneralFailure
                }
            })?;
            let installed = fs.install_file(&task_ctx, location, temp.clone()).await;
            if installed.is_err() {
                let _ = tokio::fs::remove_file(&temp).await;
            }
            installed
        })
        .await
        .map_err(|err| internal("assembly task", &err))?;
        let (entry, replaced) = installed.map_err(|err| fs_error(err, "install upload"))?;

        // The upload is done; a failure to clean up only leaves work for the background task.
        if let Err(err) = uploads::delete(self.pool(), owner, upload_id).await {
            tracing::warn!(error = %err, "cannot delete a finished upload session");
        }
        if let Err(err) = blocking(move || std::fs::remove_dir_all(&dir)).await {
            tracing::warn!(error = %err, "cannot remove the chunks of a finished upload");
        }

        let mut response = empty(if replaced {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        });
        let info = OcInfo::for_entry(&entry, self.fs().instance_id(), mtime.is_some());
        if let Ok(etag) = HeaderValue::from_str(&info.etag) {
            response.headers_mut().insert(header::ETAG, etag);
        }
        response.extensions_mut().insert(info);
        Ok(response)
    }

    /// `DELETE <session>`.
    async fn cancel(&self, ctx: &Ctx, upload_id: &str) -> Result<Response<DavBody>, Reject> {
        let owner = ctx.identity().user_id;
        let _guard = self.lock_session(owner, upload_id).await;
        let deleted = uploads::delete(self.pool(), owner, upload_id)
            .await
            .map_err(|err| internal("delete session", &err))?;
        if !deleted {
            return Err(error(StatusCode::NOT_FOUND, "Upload session not found"));
        }
        let dir = self.layout().upload_session_dir(owner, upload_id);
        if let Err(err) = blocking(move || match std::fs::remove_dir_all(&dir) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        })
        .await
        {
            tracing::warn!(error = %err, "cannot remove the chunks of a cancelled upload");
        }
        Ok(empty(StatusCode::NO_CONTENT))
    }

    /// `DELETE <session>/<name>`.
    async fn delete_chunk(
        &self,
        ctx: &Ctx,
        upload_id: &str,
        name: &str,
    ) -> Result<Response<DavBody>, Reject> {
        if ChunkName::parse(name).is_none() {
            return Err(error(StatusCode::NOT_FOUND, "No such chunk"));
        }
        let owner = ctx.identity().user_id;
        let _guard = self.lock_session(owner, upload_id).await;
        self.session(owner, upload_id).await?;
        let path = self
            .layout()
            .upload_session_dir(owner, upload_id)
            .join(name);
        match blocking(move || std::fs::remove_file(path)).await {
            Ok(()) => Ok(empty(StatusCode::NO_CONTENT)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                Err(error(StatusCode::NOT_FOUND, "No such chunk"))
            }
            Err(err) => Err(internal("delete chunk", &err)),
        }
    }

    /// `PROPFIND` anywhere in the namespace (see [`propfind`]).
    async fn propfind<B>(
        &self,
        ctx: &Ctx,
        target: &Target,
        headers: &HeaderMap,
        body: B,
    ) -> Result<Response<DavBody>, Reject>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let depth = match header_str(headers, "depth") {
            Some("0") => 0,
            // `infinity` like Nextcloud (and the files namespace): as `1`.
            Some("1") | None => 1,
            Some(depth) if depth.eq_ignore_ascii_case("infinity") => 1,
            _ => {
                return Err(Box::new(xml(
                    StatusCode::FORBIDDEN,
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error xmlns:d=\"DAV:\">\
                     <d:propfind-finite-depth/></d:error>\n"
                        .to_owned(),
                )));
            }
        };
        let body = http_body_util::Limited::new(body, 64 * 1024)
            .collect()
            .await
            .map_err(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "PROPFIND body too large"))?
            .to_bytes();
        let requested = propfind::requested(&body)
            .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Invalid PROPFIND body"))?;

        let identity = ctx.identity();
        let owner = identity.user_id;
        let base = format!("{UPLOADS_ROOT}{}/", encode(identity.username.as_str()));
        let now = db::unix_now();
        let session_item = |session: &UploadSession| propfind::Item {
            href: format!("{base}{}/", encode(&session.upload_id)),
            collection: true,
            size: 0,
            modified: UNIX_EPOCH
                + Duration::from_secs(u64::try_from(session.updated_at).unwrap_or(0)),
            etag: format!("{:x}-{:x}", session.created_at, session.updated_at),
        };
        let mut items = Vec::new();
        match target {
            Target::Root => {
                items.push(propfind::Item {
                    href: base.clone(),
                    collection: true,
                    size: 0,
                    modified: SystemTime::now(),
                    etag: format!("{now:x}"),
                });
                if depth == 1 {
                    let sessions = uploads::list(self.pool(), owner, now)
                        .await
                        .map_err(|err| internal("list sessions", &err))?;
                    items.extend(sessions.iter().map(session_item));
                }
            }
            Target::Session(id) | Target::Chunk(id, _) => {
                let session = self.session(owner, id).await?;
                let dir = self.layout().upload_session_dir(owner, id);
                let chunks = blocking(move || list_chunks(&dir))
                    .await
                    .map_err(|err| internal("list chunks", &err))?;
                let chunk_item = |(_, name, size, modified): &StoredChunk| {
                    let seconds = modified
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |elapsed| elapsed.as_nanos());
                    propfind::Item {
                        href: format!("{base}{}/{}", encode(id), encode(name)),
                        collection: false,
                        size: *size,
                        modified: *modified,
                        etag: format!("{seconds:x}-{size:x}"),
                    }
                };
                match target {
                    Target::Chunk(_, name) => {
                        let chunk = chunks
                            .iter()
                            .find(|(_, other, _, _)| other == name)
                            .ok_or_else(|| error(StatusCode::NOT_FOUND, "No such chunk"))?;
                        items.push(chunk_item(chunk));
                    }
                    _ => {
                        items.push(session_item(&session));
                        if depth == 1 {
                            items.extend(chunks.iter().map(chunk_item));
                        }
                    }
                }
            }
        }
        Ok(xml(
            StatusCode::MULTI_STATUS,
            propfind::render(&items, &requested),
        ))
    }

    /// Removes expired sessions with their chunks, and chunk directories that belong to no
    /// session (left behind by a crash or by deleted users). Called by a background task;
    /// returns the number of directories removed.
    pub async fn purge(&self) -> gono_server_core::Result<usize> {
        let expired = uploads::purge_expired(self.pool(), db::unix_now()).await?;
        let mut removed = 0;
        for (owner, upload_id) in &expired {
            let dir = self.layout().upload_session_dir(*owner, upload_id);
            match blocking(move || std::fs::remove_dir_all(dir)).await {
                Ok(()) => removed += 1,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => tracing::warn!(error = %err, "cannot remove an expired upload"),
            }
        }

        let live: Vec<(i64, String)> = uploads::all_ids(self.pool()).await?;
        let known: std::collections::HashSet<(String, String)> = live
            .into_iter()
            .map(|(owner, id)| (owner.to_string(), upload_session_dir_name(&id)))
            .collect();
        let root = self.layout().uploads_root();
        let orphans = blocking(move || {
            let mut removed = 0;
            let now = SystemTime::now();
            for user in std::fs::read_dir(&root)? {
                let user = user?;
                let Some(owner) = user.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if !user.file_type()?.is_dir() {
                    continue;
                }
                for session in std::fs::read_dir(user.path())? {
                    let session = session?;
                    let Some(name) = session.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    let old = session
                        .metadata()?
                        .modified()
                        .ok()
                        .and_then(|modified| now.duration_since(modified).ok())
                        .is_some_and(|age| age > ORPHAN_GRACE);
                    if old && !known.contains(&(owner.clone(), name)) {
                        let path = session.path();
                        let result = if session.file_type()?.is_dir() {
                            std::fs::remove_dir_all(&path)
                        } else {
                            std::fs::remove_file(&path)
                        };
                        match result {
                            Ok(()) => removed += 1,
                            Err(err) => tracing::warn!(
                                path = %path.display(),
                                error = %err,
                                "cannot remove an orphaned upload"
                            ),
                        }
                    }
                }
            }
            Ok(removed)
        })
        .await
        .map_err(|source| gono_server_core::Error::Io {
            path: self.layout().uploads_root(),
            source,
        })?;
        Ok(removed + orphans)
    }
}

/// What became of a received chunk when it was moved into its session.
enum Install {
    /// Stored; `replaced` if a chunk of the same name was there before.
    Stored { replaced: bool },
    /// Refused: the session holds [`MAX_CHUNKS`] chunks already.
    TooMany,
    /// Refused: the session holds chunks of the other kind (numbers or byte ranges).
    MixedKinds,
}

/// Why a chunk body was not stored.
enum Receive {
    /// The body ended before `Content-Length` bytes (or carried more).
    Short,
    /// Writing failed.
    Io(io::Error),
}

/// Writes a request body to `file` and syncs it. Returns the number of bytes written.
async fn receive<B>(
    mut body: B,
    mut file: tokio::fs::File,
    length: Option<u64>,
) -> Result<u64, Receive>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut written: u64 = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| Receive::Short)?;
        if let Ok(data) = frame.into_data() {
            written += u64::try_from(data.len()).unwrap_or(u64::MAX);
            if length.is_some_and(|length| written > length) {
                return Err(Receive::Short);
            }
            file.write_all(&data).await.map_err(Receive::Io)?;
        }
    }
    if length.is_some_and(|length| written != length) {
        return Err(Receive::Short);
    }
    file.flush().await.map_err(Receive::Io)?;
    file.sync_all().await.map_err(Receive::Io)?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_name_the_root_sessions_and_chunks() {
        let parse = |path: &str| parse_target(path, "alice").map_err(|r| r.status());
        assert_eq!(parse("/remote.php/dav/uploads/alice"), Ok(Target::Root));
        assert_eq!(parse("/remote.php/dav/uploads/alice/"), Ok(Target::Root));
        assert_eq!(
            parse("/remote.php/dav/uploads/alice/up%20load/"),
            Ok(Target::Session("up load".into()))
        );
        assert_eq!(
            parse("/remote.php/dav/uploads/alice/x/00001"),
            Ok(Target::Chunk("x".into(), "00001".into()))
        );
        assert_eq!(
            parse("/remote.php/dav/uploads/bob/x"),
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            parse("/remote.php/dav/uploads/alice/x/1/2"),
            Err(StatusCode::NOT_FOUND)
        );
        assert_eq!(
            parse("/remote.php/dav/uploads/alice/%2e%2e"),
            Err(StatusCode::NOT_FOUND)
        );
        assert_eq!(
            parse("/remote.php/dav/uploads/alice/a%2Fb"),
            Err(StatusCode::NOT_FOUND)
        );
    }

    #[test]
    fn chunk_names_are_numbers_or_byte_ranges() {
        assert_eq!(ChunkName::parse("00001"), Some(ChunkName::Number(1)));
        assert_eq!(ChunkName::parse("10000"), Some(ChunkName::Number(10_000)));
        assert_eq!(ChunkName::parse("0"), Some(ChunkName::Number(0)));
        // rclone: byte offsets zero-padded to 15 digits, the end inclusive.
        assert_eq!(
            ChunkName::parse("000000010485760-000000020971519"),
            Some(ChunkName::Range {
                start: 10_485_760,
                end: 20_971_519
            })
        );
        assert_eq!(
            ChunkName::parse("5-5"),
            Some(ChunkName::Range { start: 5, end: 5 })
        );
        let too_long = "9".repeat(21);
        let too_long_end = format!("0-{too_long}");
        for bad in [
            "",
            "not-a-number",
            "1a",
            "-1",
            "+1",
            "1-",
            "-",
            "1--2",
            "1-2-3",
            "1 -2",
            "5-4",
            ".file",
            "18446744073709551616",
            &too_long,
            &too_long_end,
        ] {
            assert_eq!(ChunkName::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn chunk_names_know_their_place_and_length() {
        assert_eq!(ChunkName::Number(7).position(), 7);
        assert_eq!(ChunkName::Number(7).range_len(), None);
        let range = ChunkName::Range { start: 10, end: 19 };
        assert_eq!(range.position(), 10);
        assert_eq!(range.range_len(), Some(10));
        assert!(range.same_kind(ChunkName::Range { start: 0, end: 0 }));
        assert!(!range.same_kind(ChunkName::Number(10)));
        assert!(ChunkName::Number(1).same_kind(ChunkName::Number(2)));
        // The derived order is the assembly order.
        assert!(ChunkName::Number(2) < ChunkName::Number(10));
        assert!(range < ChunkName::Range { start: 20, end: 20 });
    }

    #[test]
    fn assembly_needs_one_kind_and_ranges_without_gaps() {
        let chunk = |name: &str, size: u64| -> StoredChunk {
            let parsed = ChunkName::parse(name).unwrap_or_else(|| panic!("{name}"));
            (parsed, name.to_owned(), size, UNIX_EPOCH)
        };
        assert_eq!(check_assembly(&[]), Ok(()));
        // Numbered chunks may skip numbers; OC-Total-Length guards their sum.
        assert_eq!(check_assembly(&[chunk("1", 5), chunk("3", 9)]), Ok(()));
        assert_eq!(
            check_assembly(&[chunk("0-4", 5), chunk("5-9", 5), chunk("10-10", 1)]),
            Ok(())
        );
        for (chunks, message) in [
            (
                vec![chunk("0-4", 5), chunk("6-9", 4)],
                "Chunk 6-9 starts at byte 6, expected 5",
            ),
            (
                vec![chunk("5-9", 5)],
                "Chunk 5-9 starts at byte 5, expected 0",
            ),
            (
                vec![chunk("0-4", 5), chunk("3-9", 7)],
                "Chunk 3-9 starts at byte 3, expected 5",
            ),
            (vec![chunk("0-4", 4)], "Chunk 0-4 holds 4 bytes"),
            (
                vec![chunk("1", 5), chunk("0-4", 5)],
                "The upload mixes numbered chunks and byte ranges",
            ),
        ] {
            assert_eq!(check_assembly(&chunks), Err(message.to_owned()));
        }
    }

    #[test]
    fn preconditions_compare_quoted_etags() {
        let headers = |name: &'static str, value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static(value));
            headers
        };
        assert!(preconditions_hold(&HeaderMap::new(), None));
        assert!(preconditions_hold(
            &headers("if-match", "\"a\""),
            Some("\"a\"")
        ));
        assert!(preconditions_hold(
            &headers("if-match", "\"x\", W/\"a\""),
            Some("\"a\"")
        ));
        assert!(!preconditions_hold(
            &headers("if-match", "\"b\""),
            Some("\"a\"")
        ));
        assert!(!preconditions_hold(&headers("if-match", "\"b\""), None));
        assert!(preconditions_hold(&headers("if-match", "*"), Some("\"a\"")));
        assert!(!preconditions_hold(&headers("if-match", "*"), None));
        assert!(!preconditions_hold(
            &headers("if-none-match", "*"),
            Some("\"a\"")
        ));
        assert!(preconditions_hold(&headers("if-none-match", "*"), None));
    }
}
