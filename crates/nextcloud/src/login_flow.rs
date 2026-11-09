//! Login Flow v2.
//!
//! 1. `POST /index.php/login/v2` creates a `login_flows` row and returns a login URL and a poll
//!    token. Only SHA-256 digests of both tokens are stored.
//! 2. The user opens the login URL, signs in with their web login password and approves the
//!    device on an explicit consent page.
//! 3. `POST /index.php/login/v2/poll` mints a new app password for that device in the same
//!    transaction that deletes the flow row, and returns it exactly once. Every device gets its
//!    own app password; the plaintext is never stored.
//!
//! Flows expire after a short time and can be used only once.
