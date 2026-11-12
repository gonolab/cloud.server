//! [`Hub`]: routes change events to the connections of their owner.
//!
//! # Subscriptions
//!
//! Each user with at least one connection has a broadcast channel. Subscribing and
//! unsubscribing change the user's connection count and create or remove the channel under
//! one lock, so a connection that closes can never remove the channel of a connection that is
//! opening at the same moment (the race of the legacy server, where the last connection to
//! leave could take a new one's channel with it). The connection limit is checked under the
//! same lock.
//!
//! # Event sources
//!
//! Events arrive from two places and are delivered exactly once:
//!
//! - **In process**: the `MetaStore` calls [`ChangeSink::publish`] right after every commit.
//! - **The change log**: [`run_feed`] reads `change_log` rows newer than the hub's watermark
//!   every [`FEED_INTERVAL`], which picks up changes made by other processes (`gono-cloud
//!   rescan` while the server runs).
//!
//! Every event carries its `change_log` id. SQLite has one writer at a time, so ids become
//! visible in increasing order. The hub remembers the ids it delivered in process above the
//! watermark; the feed skips those and advances the watermark, and in-process events at or
//! below the watermark were already delivered by the feed.
//!
//! # Pre-auth tokens
//!
//! [`Hub::issue_pre_auth`] hands out a random single-use token for an authenticated identity;
//! a WebSocket can authenticate with it (empty username) within the configured lifetime.
//! Only digests are kept, and the number of outstanding tokens is bounded per user and in
//! total.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use gono_server_core::{
    config::NotifyPushConfig,
    meta::{ChangeEvent, ChangeSink, MetaStore},
    secret,
};
use gono_server_dav::Identity;
use secrecy::{ExposeSecret as _, SecretString};
use tokio::sync::{broadcast, watch};

use super::outbox::PushEvent;

/// How often [`run_feed`] looks for changes made by other processes.
pub const FEED_INTERVAL: Duration = Duration::from_secs(2);

/// Change log rows read per query by [`run_feed`].
const FEED_PAGE: u32 = 500;

/// Events buffered per user; a connection that falls further behind is told that it missed
/// changes (see [`super::Outbox::missed`]).
const CHANNEL_CAPACITY: usize = 256;

/// In-process event ids remembered above the watermark. Only reached if the feed stalls; the
/// oldest half is then forgotten, which can only cause duplicate notifications.
const MAX_REMEMBERED: usize = 65_536;

/// Outstanding pre-auth tokens per user and in total.
const MAX_PRE_AUTH_PER_USER: usize = 32;
const MAX_PRE_AUTH_TOTAL: usize = 4096;

/// Length of a pre-auth token (about 256 bits).
const PRE_AUTH_CHARS: usize = 43;

/// WebSocket connections that may be waiting for their credentials at the same time.
pub const MAX_HANDSHAKES: usize = 1024;

/// The `[notify_push]` settings as durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushSettings {
    /// Interval between pings; a connection that does not answer by the next ping is closed.
    pub ping_interval: Duration,
    /// Time a new connection has to send its credentials.
    pub auth_timeout: Duration,
    /// Lifetime of a pre-auth token.
    pub pre_auth_ttl: Duration,
    /// Minimum interval between two messages of one kind on one connection.
    pub debounce: Duration,
    /// Connections per user.
    pub max_connections_per_user: usize,
}

impl PushSettings {
    /// Converts the validated configuration (every value is at least 1).
    pub fn from_config(config: &NotifyPushConfig) -> Self {
        Self {
            ping_interval: Duration::from_secs(config.ping_interval_secs),
            auth_timeout: Duration::from_secs(config.auth_timeout_secs),
            pre_auth_ttl: Duration::from_secs(config.pre_auth_ttl_secs),
            debounce: Duration::from_secs(config.debounce_secs),
            max_connections_per_user: usize::try_from(config.max_connections_per_user)
                .unwrap_or(usize::MAX),
        }
    }
}

/// Why [`Hub::subscribe`] refused a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeError {
    /// The user already has `max_connections_per_user` connections.
    TooManyConnections,
}

/// The notify_push hub. See the module documentation.
#[derive(Debug)]
pub struct Hub {
    settings: PushSettings,
    routes: Mutex<Routes>,
    pre_auth: Mutex<HashMap<[u8; 32], PreAuth>>,
    handshakes: AtomicUsize,
    shutdown: watch::Sender<bool>,
}

#[derive(Debug)]
struct Routes {
    users: HashMap<i64, UserChannel>,
    /// Highest change log id delivered by the feed.
    watermark: i64,
    /// Ids above the watermark that were delivered in process.
    delivered: BTreeSet<i64>,
}

#[derive(Debug)]
struct UserChannel {
    sender: broadcast::Sender<PushEvent>,
    connections: usize,
}

#[derive(Debug)]
struct PreAuth {
    identity: Arc<Identity>,
    expires: Instant,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Routes {
    fn route(&self, event: &ChangeEvent) {
        if let Some(channel) = self.users.get(&event.owner_id) {
            // An error only means that every receiver is gone; nothing to deliver to.
            let _ = channel
                .sender
                .send(PushEvent::File(Arc::new(event.clone())));
        }
    }
}

impl Hub {
    /// Creates a hub. `watermark` is the newest change log id at startup: older changes are
    /// never announced.
    pub fn new(settings: PushSettings, watermark: i64) -> Arc<Self> {
        Arc::new(Self {
            settings,
            routes: Mutex::new(Routes {
                users: HashMap::new(),
                watermark,
                delivered: BTreeSet::new(),
            }),
            pre_auth: Mutex::new(HashMap::new()),
            handshakes: AtomicUsize::new(0),
            shutdown: watch::Sender::new(false),
        })
    }

    /// The settings.
    pub fn settings(&self) -> &PushSettings {
        &self.settings
    }

    /// Registers a connection of `user_id` and returns its subscription, or refuses it when
    /// the user is at the connection limit. Dropping the subscription unregisters it.
    pub fn subscribe(self: &Arc<Self>, user_id: i64) -> Result<Subscription, SubscribeError> {
        let mut routes = lock(&self.routes);
        let channel = routes.users.entry(user_id).or_insert_with(|| UserChannel {
            sender: broadcast::Sender::new(CHANNEL_CAPACITY),
            connections: 0,
        });
        if channel.connections >= self.settings.max_connections_per_user {
            if channel.connections == 0 {
                routes.users.remove(&user_id);
            }
            return Err(SubscribeError::TooManyConnections);
        }
        channel.connections += 1;
        let receiver = channel.sender.subscribe();
        Ok(Subscription {
            hub: Arc::clone(self),
            user_id,
            receiver,
        })
    }

    /// Number of connections of `user_id`.
    pub fn connections(&self, user_id: i64) -> usize {
        lock(&self.routes)
            .users
            .get(&user_id)
            .map_or(0, |channel| channel.connections)
    }

    /// Open connections and the number of users they belong to.
    pub fn connection_stats(&self) -> (usize, usize) {
        let routes = lock(&self.routes);
        let connections = routes
            .users
            .values()
            .map(|channel| channel.connections)
            .sum();
        (connections, routes.users.len())
    }

    fn unsubscribe(&self, user_id: i64) {
        let mut routes = lock(&self.routes);
        if let Some(channel) = routes.users.get_mut(&user_id) {
            channel.connections = channel.connections.saturating_sub(1);
            if channel.connections == 0 {
                routes.users.remove(&user_id);
            }
        }
    }

    /// Announces a new activity to the connections of `user_id`.
    pub fn notify_activity(&self, user_id: i64) {
        self.send(user_id, PushEvent::Activity);
    }

    /// Announces a new notification to the connections of `user_id`.
    pub fn notify_notification(&self, user_id: i64) {
        self.send(user_id, PushEvent::Notification);
    }

    fn send(&self, user_id: i64, event: PushEvent) {
        if let Some(channel) = lock(&self.routes).users.get(&user_id) {
            let _ = channel.sender.send(event);
        }
    }

    /// The newest change log id the feed has handled.
    pub fn watermark(&self) -> i64 {
        lock(&self.routes).watermark
    }

    /// Delivers change log rows read by the feed, oldest first, skipping those already
    /// delivered in process.
    pub fn ingest_logged(&self, events: &[ChangeEvent]) {
        let mut routes = lock(&self.routes);
        for event in events {
            if event.id <= routes.watermark {
                continue;
            }
            if !routes.delivered.remove(&event.id) {
                routes.route(event);
            }
            routes.watermark = event.id;
        }
        let above = routes.watermark.saturating_add(1);
        routes.delivered = routes.delivered.split_off(&above);
    }

    /// Hands out a pre-auth token for `identity`, or `None` when too many are outstanding.
    pub fn issue_pre_auth(&self, identity: Arc<Identity>) -> Option<SecretString> {
        let now = Instant::now();
        let mut tokens = lock(&self.pre_auth);
        tokens.retain(|_, entry| entry.expires > now);
        let own = tokens
            .values()
            .filter(|entry| entry.identity.user_id == identity.user_id)
            .count();
        if own >= MAX_PRE_AUTH_PER_USER || tokens.len() >= MAX_PRE_AUTH_TOTAL {
            return None;
        }
        let token = secret::random_token(PRE_AUTH_CHARS);
        tokens.insert(
            secret::digest(token.expose_secret()),
            PreAuth {
                identity,
                expires: now + self.settings.pre_auth_ttl,
            },
        );
        Some(token)
    }

    /// Redeems a pre-auth token. Every token works once and only before it expires.
    pub fn redeem_pre_auth(&self, token: &str) -> Option<Arc<Identity>> {
        let entry = lock(&self.pre_auth).remove(&secret::digest(token))?;
        (entry.expires > Instant::now()).then_some(entry.identity)
    }

    /// Reserves a slot for a connection that has not authenticated yet, or `None` when
    /// [`MAX_HANDSHAKES`] are already waiting.
    pub fn begin_handshake(self: &Arc<Self>) -> Option<Handshake> {
        let previous = self.handshakes.fetch_add(1, Ordering::AcqRel);
        if previous >= MAX_HANDSHAKES {
            self.handshakes.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Handshake {
            hub: Arc::clone(self),
        })
    }

    /// Tells every connection and the feed to stop.
    pub fn shut_down(&self) {
        self.shutdown.send_replace(true);
    }

    /// Resolves once [`Hub::shut_down`] was called.
    pub async fn stopped(&self) {
        let mut receiver = self.shutdown.subscribe();
        // An error means the sender is gone, which happens only when the hub is dropped.
        let _ = receiver.wait_for(|stopped| *stopped).await;
    }
}

impl ChangeSink for Hub {
    fn publish(&self, event: &ChangeEvent) {
        let mut routes = lock(&self.routes);
        if event.id <= routes.watermark {
            // The feed has delivered it already.
            return;
        }
        routes.delivered.insert(event.id);
        if routes.delivered.len() > MAX_REMEMBERED {
            let keep_from = routes
                .delivered
                .iter()
                .nth(MAX_REMEMBERED / 2)
                .copied()
                .unwrap_or(i64::MAX);
            routes.delivered = routes.delivered.split_off(&keep_from);
        }
        routes.route(event);
    }
}

/// A registered connection: receives the events of one user. Dropping it unregisters the
/// connection.
#[derive(Debug)]
pub struct Subscription {
    hub: Arc<Hub>,
    user_id: i64,
    receiver: broadcast::Receiver<PushEvent>,
}

impl Subscription {
    /// The next event; `Err(Lagged)` when events were dropped because the connection fell
    /// behind.
    pub async fn recv(&mut self) -> Result<PushEvent, broadcast::error::RecvError> {
        self.receiver.recv().await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.hub.unsubscribe(self.user_id);
    }
}

/// A reserved handshake slot (see [`Hub::begin_handshake`]); released on drop.
#[derive(Debug)]
pub struct Handshake {
    hub: Arc<Hub>,
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.hub.handshakes.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Delivers changes logged by other processes: reads `change_log` rows above the hub's
/// watermark every [`FEED_INTERVAL`] until the hub shuts down.
pub async fn run_feed(hub: Arc<Hub>, meta: MetaStore) {
    loop {
        loop {
            match meta.changes_since(hub.watermark(), FEED_PAGE).await {
                Ok(events) => {
                    hub.ingest_logged(&events);
                    if events.len() < FEED_PAGE as usize {
                        break;
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "cannot read the change log for notify_push");
                    break;
                }
            }
        }
        tokio::select! {
            () = tokio::time::sleep(FEED_INTERVAL) => {}
            () = hub.stopped() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use gono_server_core::{RelPath, Username, meta::ChangeOperation};
    use gono_server_dav::Mount;

    use super::*;

    fn settings(max_connections_per_user: usize) -> PushSettings {
        PushSettings {
            ping_interval: Duration::from_secs(30),
            auth_timeout: Duration::from_secs(15),
            pre_auth_ttl: Duration::from_secs(15),
            debounce: Duration::from_secs(5),
            max_connections_per_user,
        }
    }

    fn identity(user_id: i64) -> Arc<Identity> {
        Arc::new(Identity {
            user_id,
            username: Username::new(format!("user{user_id}")).unwrap(),
            display_name: String::new(),
            app_password_id: Some(user_id * 10),
            mounts: vec![Mount {
                mount_path: RelPath::root(),
                storage_path: RelPath::root(),
                writable: true,
            }],
        })
    }

    fn event(id: i64, owner_id: i64) -> ChangeEvent {
        ChangeEvent {
            id,
            owner_id,
            file_id: 100 + id,
            rel_path: RelPath::parse("f").unwrap(),
            old_rel_path: None,
            operation: ChangeOperation::Delete,
        }
    }

    fn received(subscription: &mut Subscription) -> Vec<i64> {
        let mut ids = Vec::new();
        while let Ok(PushEvent::File(change)) = subscription.receiver.try_recv() {
            ids.push(change.id);
        }
        ids
    }

    #[test]
    fn connection_limit_and_cleanup() {
        let hub = Hub::new(settings(2), 0);
        let first = hub.subscribe(1).unwrap();
        let second = hub.subscribe(1).unwrap();
        assert_eq!(
            hub.subscribe(1).unwrap_err(),
            SubscribeError::TooManyConnections
        );
        let other = hub.subscribe(2).unwrap();
        assert_eq!(hub.connections(1), 2);
        assert_eq!(hub.connection_stats(), (3, 2));
        drop(other);
        drop(first);
        assert_eq!(hub.connections(1), 1);
        let third = hub.subscribe(1).unwrap();
        drop(second);
        drop(third);
        assert_eq!(hub.connections(1), 0);
        assert!(lock(&hub.routes).users.is_empty(), "channels are removed");
    }

    #[test]
    fn closing_and_opening_concurrently_never_loses_a_channel() {
        let hub = Hub::new(settings(1000), 0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..500 {
                        let subscription = hub.subscribe(1).unwrap();
                        drop(subscription);
                    }
                });
            }
            // A long-lived connection must keep receiving while others come and go.
            let mut steady = hub.subscribe(1).unwrap();
            for id in 1..=100 {
                hub.publish(&event(id, 1));
            }
            assert_eq!(received(&mut steady).len(), 100);
        });
        assert_eq!(hub.connections(1), 0);
    }

    #[test]
    fn events_reach_only_their_owner() {
        let hub = Hub::new(settings(4), 0);
        let mut alice = hub.subscribe(1).unwrap();
        let mut bob = hub.subscribe(2).unwrap();
        hub.publish(&event(1, 1));
        assert_eq!(received(&mut alice), [1]);
        assert!(received(&mut bob).is_empty());
    }

    #[test]
    fn both_sources_deliver_each_change_once() {
        let hub = Hub::new(settings(4), 10);
        let mut connection = hub.subscribe(1).unwrap();

        // Older than the watermark: never announced.
        hub.publish(&event(9, 1));
        // In process first, then seen by the feed.
        hub.publish(&event(11, 1));
        // Another process wrote 12; 13 is in process but the feed sees it first.
        hub.ingest_logged(&[event(11, 1), event(12, 1), event(13, 1)]);
        hub.publish(&event(13, 1));
        // In process, later seen by the feed again.
        hub.publish(&event(14, 1));
        hub.ingest_logged(&[event(14, 1)]);
        hub.ingest_logged(&[event(14, 1)]);

        assert_eq!(received(&mut connection), [11, 12, 13, 14]);
        assert_eq!(hub.watermark(), 14);
        assert!(lock(&hub.routes).delivered.is_empty());
    }

    #[test]
    fn pre_auth_tokens_are_single_use_and_bounded() {
        let hub = Hub::new(settings(4), 0);
        let token = hub.issue_pre_auth(identity(1)).unwrap();
        assert!(token.expose_secret().len() >= 32);
        assert_eq!(hub.redeem_pre_auth("wrong"), None);
        let identity_back = hub.redeem_pre_auth(token.expose_secret()).unwrap();
        assert_eq!(identity_back.user_id, 1);
        assert_eq!(
            hub.redeem_pre_auth(token.expose_secret()),
            None,
            "single use"
        );

        for _ in 0..MAX_PRE_AUTH_PER_USER {
            assert!(hub.issue_pre_auth(identity(2)).is_some());
        }
        assert!(hub.issue_pre_auth(identity(2)).is_none(), "per-user bound");
        assert!(hub.issue_pre_auth(identity(3)).is_some());
    }

    #[test]
    fn pre_auth_tokens_expire() {
        let mut short = settings(4);
        short.pre_auth_ttl = Duration::ZERO;
        let hub = Hub::new(short, 0);
        let token = hub.issue_pre_auth(identity(1)).unwrap();
        assert_eq!(hub.redeem_pre_auth(token.expose_secret()), None);
    }

    #[test]
    fn handshakes_are_bounded() {
        let hub = Hub::new(settings(4), 0);
        let slots: Vec<Handshake> = (0..MAX_HANDSHAKES)
            .map(|_| hub.begin_handshake().unwrap())
            .collect();
        assert!(hub.begin_handshake().is_none());
        drop(slots);
        assert!(hub.begin_handshake().is_some());
    }
}
