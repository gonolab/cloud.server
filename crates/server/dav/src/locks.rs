//! `SqliteLs`: the persistent `DavLockSystem` backed by the `locks` table.
//!
//! - Locks are stored by owner and **storage** path, so the same file reached through
//!   different mounts conflicts correctly. dav-server only hands the lock system DAV paths, so
//!   the request's [`Ctx`] (which holds the mounts) is made available to it through a
//!   task-local: [`with_ctx`] runs the request, and [`CtxBody`] keeps it set while a streamed
//!   response body (PROPFIND lock discovery) is produced.
//! - Every lock has an absolute expiry. `Timeout: Infinite`, a missing `Timeout` header and
//!   requests above the configured maximum are clamped to `webdav.max_lock_timeout_secs`.
//! - Expired locks are ignored on read and purged whenever a lock is taken.
//! - Locks survive restarts, so a client holding a token can still refresh or release it.
//! - Read-only scopes cannot lock: the WebDAV service refuses LOCK with 403 before dav-server
//!   sees it (a lock system can only answer "locked").

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use dav_server::{
    davpath::DavPath,
    ls::{DavLock, DavLockSystem, LsFuture},
};
use futures_util::FutureExt as _;
use gono_server_core::{
    RelPath, db,
    locks::{Lock, LockStore},
};
use http_body::{Body, Frame, SizeHint};
use xmltree::{Element, Namespace};

use crate::{
    ctx::Ctx,
    resolve::{self, Location},
};

tokio::task_local! {
    static CURRENT: Ctx;
}

/// Runs `future` (a dav-server call) with `ctx` visible to the lock system.
pub async fn with_ctx<F: Future>(ctx: Ctx, future: F) -> F::Output {
    CURRENT.scope(ctx, future).await
}

fn current() -> Option<Ctx> {
    CURRENT.try_with(Ctx::clone).ok()
}

pin_project_lite::pin_project! {
    /// A response body that keeps the request's [`Ctx`] visible to the lock system while it is
    /// polled.
    pub struct CtxBody<B> {
        ctx: Ctx,
        #[pin]
        inner: B,
    }
}

impl<B> CtxBody<B> {
    /// Wraps `inner`.
    pub fn new(ctx: Ctx, inner: B) -> Self {
        Self { ctx, inner }
    }
}

impl<B: Body> Body for CtxBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let ctx = this.ctx.clone();
        let inner = this.inner;
        CURRENT.sync_scope(ctx, || inner.poll_frame(cx))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The lock system of the single `DavHandler`.
#[derive(Debug, Clone)]
pub struct SqliteLs {
    store: LockStore,
    max_timeout: Duration,
}

/// Where a DAV path is locked: owner and storage path, and how to name it back to the client.
struct Target {
    owner: i64,
    storage: RelPath,
    mount: usize,
    /// The WebDAV root of the request path (`/remote.php/dav/files/<user>` or the alias).
    root: Vec<u8>,
}

impl SqliteLs {
    /// Creates a lock system; lock lifetimes are clamped to `max_timeout`.
    pub fn new(store: LockStore, max_timeout: Duration) -> Box<Self> {
        Box::new(Self { store, max_timeout })
    }

    fn clamp(&self, timeout: Option<Duration>) -> Duration {
        timeout.map_or(self.max_timeout, |timeout| timeout.min(self.max_timeout))
    }

    fn target(ctx: &Ctx, path: &DavPath) -> Option<Target> {
        let identity = ctx.identity();
        let root = resolve::dav_root_len(identity, path.as_bytes())?;
        match resolve::resolve(identity, path).ok()? {
            Location::Storage { mount, storage, .. } => Some(Target {
                owner: identity.user_id,
                storage,
                mount,
                root: path.as_bytes()[..root].to_vec(),
            }),
            Location::Virtual { .. } => None,
        }
    }

    /// Converts a stored lock to dav-server's form, naming its root as seen through the
    /// request's mount (or the mount root when the lock was taken above it).
    fn to_dav(ctx: &Ctx, target: &Target, lock: Lock, now: i64) -> DavLock {
        let identity = ctx.identity();
        let client = resolve::client_for_storage(identity, target.mount, &lock.rel_path)
            .or_else(|| {
                identity
                    .mounts
                    .get(target.mount)
                    .map(|m| m.mount_path.clone())
            })
            .unwrap_or_default();
        let collection = lock.rel_path != target.storage || lock.rel_path.is_root();
        let path = resolve::dav_path(&target.root, &client, collection)
            .or_else(|| DavPath::new("/").ok())
            .expect("\"/\" is a valid DAV path");
        DavLock {
            token: lock.token,
            path: Box::new(path),
            principal: lock.principal,
            owner: lock
                .owner_xml
                .and_then(|xml| Element::parse(xml.as_slice()).ok())
                .map(Box::new),
            timeout_at: None,
            timeout: Some(Duration::from_secs(
                u64::try_from(lock.timeout_at - now).unwrap_or(0),
            )),
            shared: lock.shared,
            deep: lock.deep,
        }
    }

    /// A placeholder conflict for requests the lock system cannot place (no context, virtual
    /// collections, database errors). dav-server only uses it to answer 423.
    fn refusal(path: &DavPath) -> DavLock {
        DavLock {
            token: String::new(),
            path: Box::new(path.clone()),
            principal: None,
            owner: None,
            timeout_at: None,
            timeout: None,
            shared: false,
            deep: false,
        }
    }
}

/// The lock among `covering` (the live locks that apply to a path) that forbids a write, given
/// which locks the request holds: an exclusive lock it does not hold, or, if it holds none of
/// them, a shared one.
fn conflict_among(covering: Vec<Lock>, holds: impl Fn(&Lock) -> bool) -> Option<Lock> {
    let mut holds_one = false;
    let mut first_shared = None;
    for lock in covering {
        if holds(&lock) {
            holds_one = true;
        } else if !lock.shared {
            return Some(lock);
        } else {
            first_shared.get_or_insert(lock);
        }
    }
    if holds_one { None } else { first_shared }
}

/// The lock that keeps `principal`, submitting `tokens`, from writing the file `storage` of
/// `owner`, if any. These are the rules dav-server applies to a PUT (see [`SqliteLs`]'s
/// `check`), for writes that do not go through dav-server, such as the assembly of a chunked
/// upload.
pub async fn write_conflict(
    store: &LockStore,
    owner: i64,
    storage: &RelPath,
    principal: &str,
    tokens: &[String],
) -> gono_server_core::Result<Option<Lock>> {
    let covering = store.covering(owner, storage, db::unix_now()).await?;
    Ok(conflict_among(covering, |lock| {
        tokens.contains(&lock.token) && lock.principal.as_deref() == Some(principal)
    }))
}

/// The state tokens (lock tokens) a request submits in its `If` header (RFC 4918, 10.4):
/// every `<...>` inside a parenthesized list. Entity tags (`[...]`) and resource tags (`<...>`
/// before a list) are skipped.
pub fn submitted_tokens(headers: &http::HeaderMap) -> Vec<String> {
    let mut tokens = Vec::new();
    for value in headers.get_all("if") {
        let Ok(value) = value.to_str() else { continue };
        let mut in_list = false;
        let mut chars = value.chars();
        while let Some(c) = chars.next() {
            match c {
                '(' => in_list = true,
                ')' => in_list = false,
                '[' => {
                    for c in chars.by_ref() {
                        if c == ']' {
                            break;
                        }
                    }
                }
                '<' => {
                    let token: String = chars.by_ref().take_while(|&c| c != '>').collect();
                    if in_list && !token.is_empty() {
                        tokens.push(token);
                    }
                }
                _ => {}
            }
        }
    }
    tokens
}

/// Serializes the client's `<D:owner>` element so that it parses back.
///
/// dav-server renames the element to the `D` prefix without declaring it (the request may have
/// used a default namespace), which would make the stored XML unparsable; the element's own
/// prefix is therefore declared on it before writing.
fn serialize(owner: &Element) -> Option<Vec<u8>> {
    let mut owner = owner.clone();
    let mut namespaces = owner.namespaces.take().unwrap_or_else(Namespace::empty);
    if let (Some(prefix), Some(uri)) = (&owner.prefix, &owner.namespace) {
        namespaces.put(prefix.clone(), uri.clone());
    }
    owner.namespaces = Some(namespaces);
    let mut xml = Vec::new();
    owner.write(&mut xml).ok()?;
    Some(xml)
}

fn log_error(err: &gono_server_core::Error) {
    tracing::error!(error = %err, "lock database query failed");
}

impl DavLockSystem for SqliteLs {
    fn lock(
        &self,
        path: &DavPath,
        principal: Option<&str>,
        owner: Option<&Element>,
        timeout: Option<Duration>,
        shared: bool,
        deep: bool,
    ) -> LsFuture<'_, Result<DavLock, DavLock>> {
        let ctx = current();
        let path = path.clone();
        let principal = principal.map(str::to_owned);
        let owner_xml = owner.and_then(serialize);
        let timeout = self.clamp(timeout);
        async move {
            let ctx = ctx.ok_or_else(|| Self::refusal(&path))?;
            let target = Self::target(&ctx, &path).ok_or_else(|| Self::refusal(&path))?;
            let now = db::unix_now();
            let lock = Lock {
                token: format!("opaquelocktoken:{}", uuid::Uuid::new_v4()),
                owner_id: target.owner,
                rel_path: target.storage.clone(),
                principal,
                owner_xml,
                shared,
                deep,
                created_at: now,
                timeout_at: now
                    .saturating_add(i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX)),
            };
            match self.store.try_lock(lock, now).await {
                Ok(Ok(lock)) => {
                    let mut dav = Self::to_dav(&ctx, &target, lock, now);
                    dav.path = Box::new(path);
                    Ok(dav)
                }
                Ok(Err(conflict)) => Err(Self::to_dav(&ctx, &target, conflict, now)),
                Err(err) => {
                    log_error(&err);
                    Err(Self::refusal(&path))
                }
            }
        }
        .boxed()
    }

    fn unlock(&self, path: &DavPath, token: &str) -> LsFuture<'_, Result<(), ()>> {
        let ctx = current();
        let path = path.clone();
        let token = token.to_owned();
        async move {
            let target = ctx
                .as_ref()
                .and_then(|ctx| Self::target(ctx, &path))
                .ok_or(())?;
            let now = db::unix_now();
            match self
                .store
                .find(target.owner, &target.storage, &token, now)
                .await
            {
                Ok(Some(lock)) => match self.store.remove(&lock.token).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(()),
                    Err(err) => {
                        log_error(&err);
                        Err(())
                    }
                },
                Ok(None) => Err(()),
                Err(err) => {
                    log_error(&err);
                    Err(())
                }
            }
        }
        .boxed()
    }

    fn refresh(
        &self,
        path: &DavPath,
        token: &str,
        timeout: Option<Duration>,
    ) -> LsFuture<'_, Result<DavLock, ()>> {
        let ctx = current();
        let path = path.clone();
        let token = token.to_owned();
        let timeout = self.clamp(timeout);
        async move {
            let ctx = ctx.ok_or(())?;
            let target = Self::target(&ctx, &path).ok_or(())?;
            let now = db::unix_now();
            let mut lock = match self
                .store
                .find(target.owner, &target.storage, &token, now)
                .await
            {
                Ok(Some(lock)) => lock,
                Ok(None) => return Err(()),
                Err(err) => {
                    log_error(&err);
                    return Err(());
                }
            };
            lock.timeout_at =
                now.saturating_add(i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX));
            if let Err(err) = self.store.refresh(&lock.token, lock.timeout_at).await {
                log_error(&err);
                return Err(());
            }
            Ok(Self::to_dav(&ctx, &target, lock, now))
        }
        .boxed()
    }

    fn check(
        &self,
        path: &DavPath,
        principal: Option<&str>,
        ignore_principal: bool,
        deep: bool,
        submitted_tokens: &[String],
    ) -> LsFuture<'_, Result<(), DavLock>> {
        let ctx = current();
        let path = path.clone();
        let principal = principal.map(str::to_owned);
        let tokens = submitted_tokens.to_vec();
        async move {
            let ctx = ctx.ok_or_else(|| Self::refusal(&path))?;
            // Paths outside the identity's mounts hold no locks; the file system refuses
            // whatever the request tries there.
            let Some(target) = Self::target(&ctx, &path) else {
                return Ok(());
            };
            let now = db::unix_now();
            let holds = |lock: &Lock| {
                tokens.contains(&lock.token) && (ignore_principal || principal == lock.principal)
            };

            let covering = self
                .store
                .covering(target.owner, &target.storage, now)
                .await
                .map_err(|err| {
                    log_error(&err);
                    Self::refusal(&path)
                })?;
            if let Some(lock) = conflict_among(covering, holds) {
                return Err(Self::to_dav(&ctx, &target, lock, now));
            }

            if deep {
                let below = self
                    .store
                    .below(target.owner, &target.storage, now)
                    .await
                    .map_err(|err| {
                        log_error(&err);
                        Self::refusal(&path)
                    })?;
                if let Some(lock) = below.into_iter().find(|lock| !holds(lock)) {
                    return Err(Self::to_dav(&ctx, &target, lock, now));
                }
            }
            Ok(())
        }
        .boxed()
    }

    fn discover(&self, path: &DavPath) -> LsFuture<'_, Vec<DavLock>> {
        let ctx = current();
        let path = path.clone();
        async move {
            let Some(ctx) = ctx else { return Vec::new() };
            let Some(target) = Self::target(&ctx, &path) else {
                return Vec::new();
            };
            let now = db::unix_now();
            match self
                .store
                .covering(target.owner, &target.storage, now)
                .await
            {
                Ok(locks) => locks
                    .into_iter()
                    .map(|lock| Self::to_dav(&ctx, &target, lock, now))
                    .collect(),
                Err(err) => {
                    log_error(&err);
                    Vec::new()
                }
            }
        }
        .boxed()
    }

    fn delete(&self, path: &DavPath) -> LsFuture<'_, Result<(), ()>> {
        let ctx = current();
        let path = path.clone();
        async move {
            let target = ctx
                .as_ref()
                .and_then(|ctx| Self::target(ctx, &path))
                .ok_or(())?;
            self.store
                .remove_subtree(target.owner, &target.storage)
                .await
                .map_err(|err| log_error(&err))
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_tokens_come_from_parenthesized_lists() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "if",
            "<http://h/a> (<opaquelocktoken:1> [\"etag\"]) (Not <urn:x>)"
                .parse()
                .unwrap(),
        );
        assert_eq!(submitted_tokens(&headers), ["opaquelocktoken:1", "urn:x"]);
        assert!(submitted_tokens(&http::HeaderMap::new()).is_empty());
    }

    fn lock(token: &str, shared: bool) -> Lock {
        Lock {
            token: token.into(),
            owner_id: 1,
            rel_path: RelPath::root(),
            principal: Some("alice".into()),
            owner_xml: None,
            shared,
            deep: true,
            created_at: 0,
            timeout_at: i64::MAX,
        }
    }

    #[test]
    fn conflicts_follow_the_write_rules() {
        let held = |token: &'static str| move |lock: &Lock| lock.token == token;
        assert_eq!(conflict_among(vec![lock("a", false)], held("a")), None);
        assert_eq!(
            conflict_among(vec![lock("a", false)], held("b")).map(|l| l.token),
            Some("a".to_owned())
        );
        let shared = vec![lock("a", true), lock("b", true)];
        assert_eq!(conflict_among(shared.clone(), held("b")), None);
        assert!(conflict_among(shared, held("c")).is_some());
    }
}
