-- Chunked upload sessions whose destination is not known yet. See the rules at the top of
-- 0001_initial.sql.
--
-- Chunking v2 clients name the destination when they create a session (`MKCOL` with a
-- `Destination` header); older clients name it only in the final `MOVE`. `target_path` is
-- therefore NULL until the destination is known. SQLite cannot drop a NOT NULL constraint, so
-- the table is recreated. No release ever wrote upload sessions, so there is nothing to copy.

DROP TABLE upload_sessions;

CREATE TABLE upload_sessions (
    owner_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Chosen by the client; unique per user only. Compared byte for byte.
    upload_id   TEXT    NOT NULL COLLATE BINARY,
    -- Final destination as a storage rel_path of the owner, or NULL until the MOVE names it.
    target_path TEXT    COLLATE BINARY,
    -- `OC-Total-Length`, when the client sent it.
    total_size  INTEGER CHECK (total_size IS NULL OR total_size >= 0),
    created_at  INTEGER NOT NULL,
    -- Last chunk received; sessions expire a fixed time after it.
    updated_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (owner_id, upload_id)
) STRICT;

CREATE INDEX upload_sessions_expires_at ON upload_sessions (expires_at);
