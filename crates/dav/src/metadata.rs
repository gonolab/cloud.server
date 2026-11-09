//! Wrapper around `DavMetaData`.
//!
//! Every entry returned to dav-server is wrapped so that its ETag comes from exactly one
//! place: the `etag` column of the `files` table maintained by the `MetaStore`. The wrapper
//! never derives ETags from size or mtime, which would make directory ETags (bumped on every
//! change below them) disagree with file ETags.
//!
//! It also carries the Nextcloud-specific values the live properties need (`oc:fileid`,
//! `oc:permissions`, `oc:favorite`, `oc:size`) so PROPFIND does not query the database once
//! per property.
