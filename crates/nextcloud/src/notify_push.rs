//! notify_push: real-time change notifications over WebSocket.
//!
//! Implements the protocol of Nextcloud's `notify_push` app so desktop and mobile clients sync
//! immediately instead of polling. Clients authenticate on the socket with their credentials or
//! a short-lived pre-auth token obtained over OCS. Changes recorded by the `MetaStore` are
//! fanned out to every connection of the affected user, debounced per
//! `notify_push.debounce_secs`.
