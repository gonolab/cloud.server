-- Direct download links. See the rules at the top of 0001_initial.sql.
--
-- The Nextcloud apps stream video and audio that is not downloaded yet from a URL without
-- credentials (`/remote.php/direct/<token>`), which they request through
-- `POST /ocs/v2.php/apps/dav/api/v1/direct`. A link names one file by id and acts with the
-- app password that requested it: revoking that app password, or deleting the file, removes
-- the link.

CREATE TABLE direct_downloads (
    -- SHA-256 of the token in the URL. The token is returned once and never stored.
    token_hash      BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
    app_password_id INTEGER NOT NULL REFERENCES app_passwords (id) ON DELETE CASCADE,
    file_id         INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
) STRICT;

-- The cascades look links up by these columns; without the indexes every deleted file would
-- scan the table.
CREATE INDEX direct_downloads_app_password_id ON direct_downloads (app_password_id);
CREATE INDEX direct_downloads_file_id ON direct_downloads (file_id);
CREATE INDEX direct_downloads_expires_at ON direct_downloads (expires_at);
