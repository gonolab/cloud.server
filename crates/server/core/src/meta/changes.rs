//! Change events: what [`MetaStore`](super::MetaStore) reports after every committed change.
//!
//! Every change transaction appends one row to `change_log` and, once the transaction has
//! committed, hands the same row to the store's [`ChangeSink`] as a [`ChangeEvent`]. The event
//! carries everything a consumer needs (owner, file id, path, previous path), so nothing has to
//! be looked up afterwards: when a file is deleted, its row is already gone, but its id and
//! path are still in the event.
//!
//! Changes made by another process (for example `gono-cloud rescan` while the server runs) only
//! reach the server through the `change_log` table; consumers that must see them read it with
//! [`MetaStore::changes_since`](super::MetaStore::changes_since). The `id` of an event is the
//! `change_log` row id, so both sources can be merged without duplicates.

use std::{fmt, str::FromStr};

use crate::path::RelPath;

/// The kind of a logged change (`change_log.operation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeOperation {
    /// An entry appeared (written, created, copied, adopted by `rescan`).
    Create,
    /// A file's content changed.
    Modify,
    /// An entry and everything below it disappeared.
    Delete,
    /// An entry was renamed; the event carries the previous path.
    Move,
}

impl ChangeOperation {
    /// The value stored in `change_log.operation`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Delete => "delete",
            Self::Move => "move",
        }
    }
}

impl fmt::Display for ChangeOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ChangeOperation {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "create" => Ok(Self::Create),
            "modify" => Ok(Self::Modify),
            "delete" => Ok(Self::Delete),
            "move" => Ok(Self::Move),
            other => Err(format!("unknown change operation {other:?}")),
        }
    }
}

/// One committed change, as logged in `change_log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    /// The `change_log` row id. Increases with every committed change.
    pub id: i64,
    /// Owner of the changed entry.
    pub owner_id: i64,
    /// File id of the changed entry; for a delete, the id the entry had.
    pub file_id: i64,
    /// Path of the entry after the change (for a delete, the path it had).
    pub rel_path: RelPath,
    /// Previous path of a [`ChangeOperation::Move`].
    pub old_rel_path: Option<RelPath>,
    /// What happened.
    pub operation: ChangeOperation,
}

impl ChangeEvent {
    /// The paths the change touched: the path and, for a move, the previous path.
    pub fn paths(&self) -> impl Iterator<Item = &RelPath> {
        std::iter::once(&self.rel_path).chain(self.old_rel_path.as_ref())
    }
}

/// Receives the events of committed changes.
///
/// [`ChangeSink::publish`] is called after the transaction committed, on the task that made
/// the change, so it must return quickly and must not block on I/O.
pub trait ChangeSink: Send + Sync + fmt::Debug {
    /// Called once per committed change.
    fn publish(&self, event: &ChangeEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_round_trip() {
        for operation in [
            ChangeOperation::Create,
            ChangeOperation::Modify,
            ChangeOperation::Delete,
            ChangeOperation::Move,
        ] {
            assert_eq!(operation.as_str().parse(), Ok(operation));
        }
        assert!("rename".parse::<ChangeOperation>().is_err());
    }

    #[test]
    fn a_move_touches_both_paths() {
        let event = ChangeEvent {
            id: 1,
            owner_id: 1,
            file_id: 7,
            rel_path: RelPath::parse("b").unwrap(),
            old_rel_path: Some(RelPath::parse("a").unwrap()),
            operation: ChangeOperation::Move,
        };
        let paths: Vec<&str> = event.paths().map(RelPath::as_str).collect();
        assert_eq!(paths, ["b", "a"]);
    }
}
