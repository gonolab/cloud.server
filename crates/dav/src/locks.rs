//! Persistent `DavLockSystem` backed by the `locks` table.
//!
//! - Locks are keyed by owner and storage `rel_path`, not by the DAV path, so the same file
//!   reached through different mounts conflicts correctly.
//! - Every lock has an absolute `timeout_at`. `Timeout: Infinite` and requests above the
//!   server maximum are clamped, so abandoned locks always expire.
//! - Expired locks are ignored on read and purged in the background.
//! - Locks survive restarts, so a client holding a token can still refresh or release it.
