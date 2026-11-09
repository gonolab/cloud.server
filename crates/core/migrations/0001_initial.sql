-- Initial schema of Gono Cloud v1.
--
-- Rules that apply to this file and every later migration:
--
-- 1. Append-only. Once a migration is published (merged into main) it is never edited,
--    reformatted or renamed. sqlx stores a checksum of every applied migration and refuses to
--    start when a published file no longer matches. Schema changes go into a new,
--    higher-numbered file. `crates/core/tests/migrations.rs` pins the published checksums.
--
-- 2. `rel_path` columns use BINARY collation (spelled out explicitly below). Paths compare
--    byte-for-byte; `Foo` and `foo` are different files.
--
-- 3. Subtree ("prefix") queries use a half-open range, never LIKE:
--
--        rel_path >= 'a/' AND rel_path < 'a0'
--
--    '0' is the byte after '/'. LIKE treats '_' and '%' in file names as wildcards and is
--    case-insensitive for ASCII in SQLite, so it matches unrelated rows.
--
-- Conventions:
--
-- - `rel_path` is relative to the owner's root: no leading or trailing slash, '' for the root.
-- - Timestamps named `*_at` are UNIX seconds (UTC). `mtime_ns` is UNIX nanoseconds.
-- - Booleans are INTEGER 0/1 with a CHECK constraint.
-- - Secrets (app passwords, session cookies, Login Flow tokens) are stored only as SHA-256
--   digests (32-byte BLOBs). They are high-entropy random tokens, so a fast hash is enough and
--   lookups are a single indexed equality match.
-- - Tables are STRICT so SQLite enforces the declared column types.

-- Accounts. Users authenticate devices with app passwords; the web login password below is
-- used only for Login Flow v2 and the web admin UI.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    -- Validated by `gono_core::Username`: lowercase ASCII, appears verbatim in DAV URLs.
    username      TEXT    NOT NULL UNIQUE COLLATE BINARY,
    display_name  TEXT    NOT NULL,
    -- Argon2id PHC string of the web login password.
    password_hash TEXT    NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
) STRICT;

-- Per-device credentials, minted by Login Flow v2, the CLI or the web admin UI.
CREATE TABLE app_passwords (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the token. The plaintext is shown once at creation and never stored.
    token_hash   BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    -- Human-readable name, for example the device name reported by Login Flow v2.
    -- Not unique: the same device may sign in more than once.
    label        TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    -- NULL means the password never expires.
    expires_at   INTEGER,
    last_used_at INTEGER
) STRICT;

CREATE INDEX app_passwords_user_id ON app_passwords (user_id);

-- What an app password can reach. Each row mounts `storage_path` (inside the owner's tree) at
-- `mount_path` (in the tree the client sees). An app password without any scope row has no
-- access at all; full access is an explicit ('', '', 'full') row.
CREATE TABLE app_password_scopes (
    app_password_id INTEGER NOT NULL REFERENCES app_passwords (id) ON DELETE CASCADE,
    mount_path      TEXT    NOT NULL COLLATE BINARY,
    storage_path    TEXT    NOT NULL COLLATE BINARY,
    permission      TEXT    NOT NULL CHECK (permission IN ('view', 'full')),
    PRIMARY KEY (app_password_id, mount_path)
) STRICT;

-- Metadata of every file and directory, written only through MetaStore.
CREATE TABLE files (
    -- Exposed to clients as `oc:fileid`. AUTOINCREMENT so that ids of deleted entries are never
    -- handed out again; clients cache them. Preserved across MOVE.
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    rel_path TEXT    NOT NULL COLLATE BINARY,
    is_dir   INTEGER NOT NULL CHECK (is_dir IN (0, 1)),
    -- Changes whenever the entry or, for directories, anything below it changes.
    etag     TEXT    NOT NULL,
    mtime_ns INTEGER NOT NULL,
    size     INTEGER NOT NULL DEFAULT 0 CHECK (size >= 0),
    favorite INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
    -- Also the index for subtree range scans (rule 3 above).
    UNIQUE (owner_id, rel_path)
) STRICT;

-- Favorites lookup for the `filter-files` REPORT.
CREATE INDEX files_favorites ON files (owner_id, rel_path) WHERE favorite = 1;

-- WebDAV dead properties set through PROPPATCH. Keyed by file id, so MOVE keeps them and
-- DELETE removes them.
CREATE TABLE dead_props (
    file_id   INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    namespace TEXT    NOT NULL,
    name      TEXT    NOT NULL,
    -- The serialized property element as received from the client.
    xml       BLOB    NOT NULL,
    PRIMARY KEY (file_id, namespace, name)
) STRICT;

-- Append-only journal of changes per owner, written in the same transaction as the change.
-- `id` is a monotonically increasing sequence number.
CREATE TABLE change_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- No foreign key: the row outlives the deleted file it describes.
    file_id      INTEGER NOT NULL,
    rel_path     TEXT    NOT NULL COLLATE BINARY,
    -- Previous path of a 'move'; NULL otherwise.
    old_rel_path TEXT    COLLATE BINARY,
    operation    TEXT    NOT NULL CHECK (operation IN ('create', 'modify', 'delete', 'move')),
    changed_at   INTEGER NOT NULL,
    CHECK ((operation = 'move') = (old_rel_path IS NOT NULL))
) STRICT;

CREATE INDEX change_log_owner ON change_log (owner_id, id);

-- WebDAV locks, keyed by storage location so that the same file reached through different
-- mounts conflicts correctly.
CREATE TABLE locks (
    -- `opaquelocktoken:` URI returned to the client.
    token      TEXT    PRIMARY KEY,
    owner_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    rel_path   TEXT    NOT NULL COLLATE BINARY,
    -- Principal that took the lock.
    principal  TEXT,
    -- The <D:owner> element sent by the client, returned verbatim in lock discovery.
    owner_xml  BLOB,
    shared     INTEGER NOT NULL CHECK (shared IN (0, 1)),
    deep       INTEGER NOT NULL CHECK (deep IN (0, 1)),
    created_at INTEGER NOT NULL,
    -- Absolute expiry. NOT NULL on purpose: `Timeout: Infinite` and overly long requests are
    -- clamped to the server maximum, so an abandoned lock always expires.
    timeout_at INTEGER NOT NULL
) STRICT;

CREATE INDEX locks_owner_path ON locks (owner_id, rel_path);
CREATE INDEX locks_timeout_at ON locks (timeout_at);

-- Nextcloud chunked upload v2 sessions (`/remote.php/dav/uploads/<user>/<upload_id>`).
CREATE TABLE upload_sessions (
    owner_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Chosen by the client; unique per user only.
    upload_id   TEXT    NOT NULL,
    -- Final destination (`Destination` header of the initial MKCOL), as a storage rel_path.
    target_path TEXT    NOT NULL COLLATE BINARY,
    -- `OC-Total-Length`, when the client sent it.
    total_size  INTEGER CHECK (total_size IS NULL OR total_size >= 0),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (owner_id, upload_id)
) STRICT;

CREATE INDEX upload_sessions_expires_at ON upload_sessions (expires_at);

-- Pending Login Flow v2 sign-ins. The app password is minted when the client polls after the
-- user granted access, inside the transaction that deletes the flow row, so its plaintext is
-- never stored.
CREATE TABLE login_flows (
    id               INTEGER PRIMARY KEY,
    -- SHA-256 of the token the client polls with.
    poll_token_hash  BLOB    NOT NULL UNIQUE CHECK (length(poll_token_hash) = 32),
    -- SHA-256 of the token embedded in the login URL opened in the browser.
    login_token_hash BLOB    NOT NULL UNIQUE CHECK (length(login_token_hash) = 32),
    -- Device name derived from the client's User-Agent; becomes the app password label.
    client_name      TEXT    NOT NULL,
    -- Set when the user approves the request on the consent page.
    granted_user_id  INTEGER REFERENCES users (id) ON DELETE CASCADE,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL
) STRICT;

CREATE INDEX login_flows_expires_at ON login_flows (expires_at);

-- Browser sessions of the web admin UI and the Login Flow v2 consent page. Created only by
-- signing in with the web login password; app passwords cannot create them.
CREATE TABLE web_sessions (
    id           INTEGER PRIMARY KEY,
    -- SHA-256 of the session cookie value.
    token_hash   BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX web_sessions_user_id ON web_sessions (user_id);
CREATE INDEX web_sessions_expires_at ON web_sessions (expires_at);
