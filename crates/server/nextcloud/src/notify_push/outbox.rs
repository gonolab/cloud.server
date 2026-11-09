//! What one authenticated connection sends, and when: scope filtering and debouncing.
//!
//! [`Outbox`] is a pure state machine driven by the connection task: it is told about events
//! ([`Outbox::push`]) and about the current time, and says when the next message is due
//! ([`Outbox::next_due`]) and which messages to send ([`Outbox::take_due`]).
//!
//! # Scope
//!
//! An event reaches the connection only if [`visible`] says the connection's app password can
//! see the change: the owner must be the connection's user, and the changed path (or, for a
//! move, either path) must lie inside one of the app password's mounts or contain one (a
//! deleted or moved ancestor removes the mount's content as well).
//!
//! # Debouncing
//!
//! Each message kind (file, activity, notification) is debounced on its own:
//!
//! - The first change after a quiet period is sent after a short coalescing delay
//!   ([`COALESCE`]), so a burst of related writes (an upload with its parent folders) becomes
//!   one message.
//! - After a message was sent, the next one of the same kind waits until `debounce` has passed;
//!   every change in between is merged into it.
//!
//! So messages of one kind are at least `debounce` apart, and no change waits longer than
//! `debounce` (`notify_push.debounce_secs`) before it is announced.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use gono_core::meta::ChangeEvent;
use gono_dav::Identity;

use super::message::{self, LISTEN_FILE_ID, UpdatedFiles};

/// Delay before the first message after a quiet period, to coalesce bursts.
pub const COALESCE: Duration = Duration::from_millis(250);

/// What the hub delivers to the connections of one user.
#[derive(Debug, Clone)]
pub enum PushEvent {
    /// A committed change of the user's files.
    File(Arc<ChangeEvent>),
    /// A new activity of the user.
    Activity,
    /// A new notification for the user.
    Notification,
}

/// Whether an app password with `identity`'s mounts can see the change (see the module
/// documentation).
pub fn visible(identity: &Identity, event: &ChangeEvent) -> bool {
    event.owner_id == identity.user_id
        && event.paths().any(|path| {
            identity.mounts.iter().any(|mount| {
                path.starts_with(&mount.storage_path) || mount.storage_path.starts_with(path)
            })
        })
}

/// Debounce state of one message kind.
#[derive(Debug)]
struct Slot<T> {
    pending: Option<T>,
    due: Option<Instant>,
    last_sent: Option<Instant>,
}

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self {
            pending: None,
            due: None,
            last_sent: None,
        }
    }
}

impl<T> Slot<T> {
    /// Records a change: merges it into the pending message and schedules that message.
    fn add(&mut self, now: Instant, debounce: Duration, merge: impl FnOnce(&mut Option<T>)) {
        merge(&mut self.pending);
        if self.due.is_none() {
            let earliest = now + COALESCE;
            let due = self
                .last_sent
                .map_or(earliest, |sent| earliest.max(sent + debounce));
            self.due = Some(due);
        }
    }

    /// The pending message if it is due at `now`.
    fn take(&mut self, now: Instant) -> Option<T> {
        if self.due.is_some_and(|due| due <= now) {
            self.due = None;
            self.last_sent = Some(now);
            self.pending.take()
        } else {
            None
        }
    }
}

/// Outgoing messages of one authenticated connection. See the module documentation.
#[derive(Debug)]
pub struct Outbox {
    identity: Arc<Identity>,
    debounce: Duration,
    /// The client sent `listen notify_file_id`.
    file_ids: bool,
    files: Slot<UpdatedFiles>,
    activity: Slot<()>,
    notification: Slot<()>,
}

impl Outbox {
    /// An outbox for a connection authenticated as `identity`.
    pub fn new(identity: Arc<Identity>, debounce: Duration) -> Self {
        Self {
            identity,
            debounce,
            file_ids: false,
            files: Slot::default(),
            activity: Slot::default(),
            notification: Slot::default(),
        }
    }

    /// The identity the connection authenticated as.
    pub fn identity(&self) -> &Arc<Identity> {
        &self.identity
    }

    /// Handles a text frame from the client. Unknown frames are ignored, like Nextcloud's
    /// push server does.
    pub fn client_text(&mut self, text: &str) {
        if text.trim() == LISTEN_FILE_ID {
            self.file_ids = true;
        }
    }

    /// Records an event delivered by the hub, if the connection can see it.
    pub fn push(&mut self, event: &PushEvent, now: Instant) {
        let debounce = self.debounce;
        match event {
            PushEvent::File(change) => {
                if visible(&self.identity, change) {
                    let files = UpdatedFiles::one(change.file_id);
                    self.files.add(now, debounce, |pending| match pending {
                        Some(pending) => pending.merge(&files),
                        None => *pending = Some(files),
                    });
                }
            }
            PushEvent::Activity => self.activity.add(now, debounce, |p| *p = Some(())),
            PushEvent::Notification => self.notification.add(now, debounce, |p| *p = Some(())),
        }
    }

    /// Records that events were lost (the connection fell behind): announce an unknown file
    /// change, which makes the client look at everything.
    pub fn missed(&mut self, now: Instant) {
        self.files.add(now, self.debounce, |pending| {
            *pending = Some(UpdatedFiles::Unknown);
        });
    }

    /// When the next message is due, if any is pending.
    pub fn next_due(&self) -> Option<Instant> {
        [self.files.due, self.activity.due, self.notification.due]
            .into_iter()
            .flatten()
            .min()
    }

    /// The messages due at `now`, in a fixed order.
    pub fn take_due(&mut self, now: Instant) -> Vec<String> {
        let mut messages = Vec::new();
        if let Some(files) = self.files.take(now) {
            messages.push(files.message(self.file_ids));
        }
        if self.activity.take(now).is_some() {
            messages.push(message::NOTIFY_ACTIVITY.to_owned());
        }
        if self.notification.take(now).is_some() {
            messages.push(message::NOTIFY_NOTIFICATION.to_owned());
        }
        messages
    }
}

#[cfg(test)]
mod tests {
    use gono_core::{RelPath, Username, meta::ChangeOperation};
    use gono_dav::identity::Mount;

    use super::*;

    fn identity(mounts: &[(&str, bool)]) -> Arc<Identity> {
        Arc::new(Identity {
            user_id: 1,
            username: Username::new("alice").unwrap(),
            display_name: "Alice".into(),
            app_password_id: 1,
            mounts: mounts
                .iter()
                .enumerate()
                .map(|(index, (storage, writable))| Mount {
                    mount_path: RelPath::parse(&format!("m{index}")).unwrap(),
                    storage_path: RelPath::parse(storage).unwrap(),
                    writable: *writable,
                })
                .collect(),
        })
    }

    fn change(owner: i64, id: i64, path: &str, old: Option<&str>) -> Arc<ChangeEvent> {
        Arc::new(ChangeEvent {
            id,
            owner_id: owner,
            file_id: id,
            rel_path: RelPath::parse(path).unwrap(),
            old_rel_path: old.map(|old| RelPath::parse(old).unwrap()),
            operation: if old.is_some() {
                ChangeOperation::Move
            } else {
                ChangeOperation::Modify
            },
        })
    }

    #[test]
    fn scope_filter() {
        let full = identity(&[("", true)]);
        assert!(visible(&full, &change(1, 1, "a/b.txt", None)));
        assert!(
            !visible(&full, &change(2, 1, "a/b.txt", None)),
            "other owner"
        );

        let scoped = identity(&[("Photos/2024", false), ("Inbox", true)]);
        assert!(visible(&scoped, &change(1, 1, "Photos/2024/x.jpg", None)));
        assert!(visible(&scoped, &change(1, 1, "Photos/2024", None)));
        assert!(visible(&scoped, &change(1, 1, "Inbox/new", None)));
        // An ancestor of a mount: deleting or moving it removes the mount's content.
        assert!(visible(&scoped, &change(1, 1, "Photos", None)));
        assert!(!visible(&scoped, &change(1, 1, "Photos/2023/x.jpg", None)));
        assert!(!visible(&scoped, &change(1, 1, "Photos/20245", None)));
        assert!(!visible(&scoped, &change(1, 1, "Inboxes/x", None)));
        // Moves count for both ends.
        assert!(visible(&scoped, &change(1, 1, "Trash/x", Some("Inbox/x"))));
        assert!(visible(&scoped, &change(1, 1, "Inbox/x", Some("Trash/x"))));
        assert!(!visible(&scoped, &change(1, 1, "Trash/y", Some("Trash/x"))));
    }

    #[test]
    fn invisible_changes_are_dropped() {
        let mut outbox = Outbox::new(identity(&[("Inbox", true)]), Duration::from_secs(5));
        let now = Instant::now();
        outbox.push(&PushEvent::File(change(1, 1, "Other/x", None)), now);
        outbox.push(&PushEvent::File(change(2, 2, "Inbox/x", None)), now);
        assert_eq!(outbox.next_due(), None);
    }

    #[test]
    fn first_change_is_sent_after_the_coalescing_delay() {
        let mut outbox = Outbox::new(identity(&[("", true)]), Duration::from_secs(5));
        let start = Instant::now();
        outbox.push(&PushEvent::File(change(1, 1, "a", None)), start);
        outbox.push(&PushEvent::File(change(1, 2, "b", None)), start);
        assert_eq!(outbox.next_due(), Some(start + COALESCE));
        assert!(outbox.take_due(start).is_empty(), "not due yet");
        assert_eq!(outbox.take_due(start + COALESCE), ["notify_file"]);
        assert_eq!(outbox.next_due(), None);
    }

    #[test]
    fn later_changes_wait_for_the_debounce_interval_and_merge() {
        let debounce = Duration::from_secs(5);
        let mut outbox = Outbox::new(identity(&[("", true)]), debounce);
        outbox.client_text("listen notify_file_id");
        let start = Instant::now();
        outbox.push(&PushEvent::File(change(1, 1, "a", None)), start);
        let sent = start + COALESCE;
        assert_eq!(outbox.take_due(sent), ["notify_file_id [1]"]);

        let one_second = sent + Duration::from_secs(1);
        outbox.push(&PushEvent::File(change(1, 3, "c", None)), one_second);
        outbox.push(&PushEvent::File(change(1, 2, "b", None)), one_second);
        assert_eq!(outbox.next_due(), Some(sent + debounce), "rate limited");
        assert!(outbox.take_due(sent + Duration::from_secs(4)).is_empty());
        assert_eq!(outbox.take_due(sent + debounce), ["notify_file_id [2,3]"]);

        // After a quiet period the next change goes out quickly again.
        let quiet = sent + debounce * 3;
        outbox.push(&PushEvent::File(change(1, 4, "d", None)), quiet);
        assert_eq!(outbox.next_due(), Some(quiet + COALESCE));
    }

    #[test]
    fn no_change_waits_longer_than_the_debounce_interval() {
        let debounce = Duration::from_secs(5);
        let mut outbox = Outbox::new(identity(&[("", true)]), debounce);
        let start = Instant::now();
        let mut now = start;
        let mut sent = Vec::new();
        // A change every 100 ms for 20 seconds.
        while now < start + Duration::from_secs(20) {
            outbox.push(&PushEvent::File(change(1, 1, "a", None)), now);
            if !outbox.take_due(now).is_empty() {
                sent.push(now);
            }
            assert!(outbox.next_due().is_none_or(|due| due <= now + debounce));
            now += Duration::from_millis(100);
        }
        assert!(sent.len() >= 4, "{} messages", sent.len());
        for pair in sent.windows(2) {
            assert!(pair[1] - pair[0] >= debounce, "{pair:?}");
        }
    }

    #[test]
    fn kinds_are_debounced_separately_and_missed_events_become_notify_file() {
        let mut outbox = Outbox::new(identity(&[("", true)]), Duration::from_secs(5));
        outbox.client_text("listen notify_file_id");
        let now = Instant::now();
        outbox.push(&PushEvent::File(change(1, 1, "a", None)), now);
        outbox.missed(now);
        outbox.push(&PushEvent::Activity, now);
        outbox.push(&PushEvent::Notification, now);
        assert_eq!(
            outbox.take_due(now + COALESCE),
            ["notify_file", "notify_activity", "notify_notification"]
        );
    }
}
