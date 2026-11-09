-- Server-wide settings that are generated once and must stay stable for the lifetime of the
-- installation. See the rules at the top of 0001_initial.sql.

CREATE TABLE settings (
    name  TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- Instance id in the Nextcloud format: "oc" followed by ten lowercase characters. It is the
-- suffix of every `oc:id` (`<zero-padded file id><instance id>`), which clients use to tell
-- files of different servers apart.
INSERT INTO settings (name, value) VALUES ('instance_id', 'oc' || lower(hex(randomblob(5))));
