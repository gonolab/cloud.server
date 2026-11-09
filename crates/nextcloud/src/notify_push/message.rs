//! The text frames of the notify_push protocol.
//!
//! | Direction | Frame | Meaning |
//! |---|---|---|
//! | client → server | `<username>`, then `<app password>` | Authenticate with device credentials. |
//! | client → server | `""`, then `<pre-auth token>` | Authenticate with a token from the pre-auth endpoint. |
//! | server → client | `authenticated` | Authentication succeeded. |
//! | server → client | `err: <reason>` | Authentication failed; the server closes the socket. |
//! | client → server | `listen notify_file_id` | Ask for file ids in file notifications. |
//! | server → client | `notify_file` | Something in the user's files changed. |
//! | server → client | `notify_file_id [1,2]` | The files with these ids changed (only after `listen notify_file_id`). |
//! | server → client | `notify_activity` | A new activity exists. |
//! | server → client | `notify_notification` | A new notification exists. |

use std::collections::BTreeSet;

/// Reply to successful authentication.
pub const AUTHENTICATED: &str = "authenticated";

/// Request to receive file ids with file notifications.
pub const LISTEN_FILE_ID: &str = "listen notify_file_id";

/// A file changed (no ids).
pub const NOTIFY_FILE: &str = "notify_file";

/// A new activity exists.
pub const NOTIFY_ACTIVITY: &str = "notify_activity";

/// A new notification exists.
pub const NOTIFY_NOTIFICATION: &str = "notify_notification";

/// Most file ids sent in one `notify_file_id` message. Larger sets degrade to `notify_file`,
/// which tells the client to look at everything, so messages stay small.
pub const MAX_FILE_IDS: usize = 64;

/// The `err: <reason>` frame sent before the server closes an unauthenticated socket.
pub fn error(reason: &str) -> String {
    format!("err: {reason}")
}

/// The files changed since the last file notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdatedFiles {
    /// Too many changes, or changes whose ids are not known: the client should look at
    /// everything.
    Unknown,
    /// The ids of the changed entries (at most [`MAX_FILE_IDS`]).
    Known(BTreeSet<i64>),
}

impl UpdatedFiles {
    /// One changed entry.
    pub fn one(file_id: i64) -> Self {
        Self::Known(BTreeSet::from([file_id]))
    }

    /// Adds the changes of `other`. Unknown absorbs everything; too many ids become Unknown.
    pub fn merge(&mut self, other: &Self) {
        match (&mut *self, other) {
            (Self::Known(ids), Self::Known(more)) => {
                ids.extend(more.iter().copied());
                if ids.len() > MAX_FILE_IDS {
                    *self = Self::Unknown;
                }
            }
            (this, _) => *this = Self::Unknown,
        }
    }

    /// The message announcing these changes: `notify_file_id [..]` when the client asked for
    /// ids and they are known, `notify_file` otherwise.
    pub fn message(&self, with_ids: bool) -> String {
        match self {
            Self::Known(ids) if with_ids => {
                let list: Vec<String> = ids.iter().map(i64::to_string).collect();
                format!("notify_file_id [{}]", list.join(","))
            }
            _ => NOTIFY_FILE.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_messages_merge_and_list_ids() {
        let mut files = UpdatedFiles::one(2);
        files.merge(&UpdatedFiles::one(1));
        files.merge(&UpdatedFiles::one(2));
        assert_eq!(files.message(true), "notify_file_id [1,2]");
        assert_eq!(files.message(false), "notify_file");
    }

    #[test]
    fn unknown_changes_degrade_to_notify_file() {
        let mut files = UpdatedFiles::one(2);
        files.merge(&UpdatedFiles::Unknown);
        assert_eq!(files, UpdatedFiles::Unknown);
        files.merge(&UpdatedFiles::one(3));
        assert_eq!(files.message(true), "notify_file");
    }

    #[test]
    fn too_many_ids_degrade_to_notify_file() {
        let mut files = UpdatedFiles::one(0);
        for id in 1..=i64::try_from(MAX_FILE_IDS).unwrap() {
            files.merge(&UpdatedFiles::one(id));
        }
        assert_eq!(files, UpdatedFiles::Unknown);
        assert_eq!(error("Invalid credentials"), "err: Invalid credentials");
    }
}
