-- The creation time of a file as its client reports it. See the rules at the top of
-- 0001_initial.sql.
--
-- Clients send it with uploads (`X-OC-CTime`) and read it back as `nc:creation_time`, the way
-- Nextcloud stores it. Nextcloud Android compares it with the local file before it reports a
-- name collision as "same file". UNIX seconds; 0 when no client reported one, as on Nextcloud.

ALTER TABLE files ADD COLUMN creation_time INTEGER NOT NULL DEFAULT 0 CHECK (creation_time >= 0);

-- Until now `nc:creation_time` was an ordinary dead property, which the live column replaces.
DELETE FROM dead_props WHERE namespace = 'http://nextcloud.org/ns' AND name = 'creation_time';
