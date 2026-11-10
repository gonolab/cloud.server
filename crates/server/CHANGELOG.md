# Changelog: Gono Cloud server

All notable changes to the Gono Cloud server (the `gono-cloud` binary and the crates under
`crates/server/`) are recorded here. Server releases are tagged `server-v<version>` (see
`docs/repository-layout.md`); the release workflow takes the release notes from this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The protocol stays backward
compatible within a major version: released clients keep working with newer servers.

## [Unreleased]

### Added

- Chunked upload accepts chunks named by byte range (`<start>-<end>`, the end inclusive), as
  rclone's Nextcloud backend sends them, so that `rclone` with `vendor = nextcloud` can upload
  files larger than its chunk size. The ranges must cover the file from byte 0 without gaps or
  overlaps; a session holds either numbered chunks or byte ranges.

### Changed

- The install script is attached to releases as `cloud.server.sh` instead of `install.sh`, and
  `https://gono.dev/cloud.server.sh` redirects to the one of the newest server release. Release
  1.0.0 carries both names.
- The server reports Nextcloud 32.0.0 instead of 30.0.0 in `status.php` and the capabilities.
  Nextcloud Android 35 no longer says the server has reached end of life and no longer
  lowercases the extensions of uploaded files.
- Large folders list much faster: dead properties are loaded once per entry and per listing in
  batches instead of one query per requested property and entry (20,000 entries with the
  Nextcloud iOS app's properties: 2 s instead of 15 s).
- The XML of WebDAV responses is gzipped for clients that send `Accept-Encoding: gzip`, as
  Nextcloud does for `PROPFIND` (a listing of 20,000 photos: 0.9 MB instead of 69 MB). File
  downloads are never compressed.

### Fixed

- Nextcloud Android can list the folders of users whose name contains `@`: hrefs leave `@`,
  `:`, `(` and `)` unencoded, as Nextcloud does, instead of writing `%40`, which the app could
  not match against the user name.
- A database error while checking credentials answers `503` instead of `401`. After a `401`
  the Nextcloud iOS app deleted the account from the device and Nextcloud Android discarded
  the stored password. The web login says the server is temporarily unavailable instead of
  "wrong username or password".
- Valid app passwords keep working from an address that has used up its failed attempts; only
  further wrong credentials get `429`. Before, one failing client (an old device, a WebDAV app
  set up with the web login password) locked out every device behind the same address. The web
  login has a limiter of its own.
- `PROPFIND` with `Depth: infinity` is answered like `Depth: 1`, as Nextcloud does, instead of
  `403`. Folders made available offline in the Nextcloud iOS app downloaded nothing.
- Uploads keep the creation time clients send in `X-OC-CTime`, reported as
  `nc:creation_time` and settable with `PROPPATCH` (a database migration adds the column).
  Nextcloud Android reported files that were already on the server as conflicts, for example
  after a reinstall or a lost response; images can still conflict, because their dimensions
  are not reported.
- A `MOVE` that assembles a chunked upload session without any chunk is refused with `400`
  unless a length of 0 was announced. Before, it replaced the destination with an empty file.

## [1.0.0] - 2026-11-10

First release of the rewrite on top of [dav-server-rs](https://github.com/messense/dav-server-rs).
It shares nothing with the legacy `v0.1.x` releases: there is no migration path from them, and
their tags stay as they are.

### Added

- WebDAV under `/remote.php/dav/files/<user>/` (and `/remote.php/webdav/`): `PROPFIND`, `GET`,
  `HEAD`, `PUT`, `MKCOL`, `COPY`, `MOVE`, `DELETE`, `PROPPATCH`, `LOCK` and `UNLOCK`, with
  Nextcloud live properties, `OC-*` headers, directory ETag propagation and lock timeouts.
- Nextcloud client protocol: `status.php`, capabilities and the OCS user endpoints, favorites
  with the `filter-files` REPORT, chunked upload v2, and Login Flow v2 with an explicit consent
  page that mints one app password per device.
- notify_push: real-time change notifications over WebSocket (`/push/ws`).
- Multiple users with web login passwords (Argon2) for the browser and app passwords for devices,
  optionally read-only, expiring or limited to mounted folders.
- Web admin UI (`admin.enabled`, `admin.path`): server overview, accounts, admin role, display
  names, web login passwords and app passwords.
- Command line: `init`, `serve`, `config check`, `user` (add, list, delete, set-password,
  enable, disable, promote, demote, set-display-name), `app-password` (add, list, delete) and
  `rescan` for files changed directly in the data directory.
- At least one enabled admin always remains: disabling, demoting or deleting the last one is
  refused.
- Management commands and `serve` refuse to run as root on an installation that belongs to the
  service user, so they cannot leave files behind that the service cannot write.
- Release archives for Linux (x86_64, aarch64; fully static musl binaries with mimalloc that run
  on any distribution, without glibc) and macOS (Apple silicon, Intel) with a hardened systemd
  unit, a launchd job (`cloud.gono.server`) and an install script
  that verifies the archive, creates a service user, runs `init` on fresh installs, backs the
  database up before upgrades and never deletes data when uninstalling.
- Documentation: deployment (`docs/deployment.md`), reverse proxies (`docs/reverse-proxy.md`),
  v1 scope and the mobile test checklist.

[Unreleased]: https://github.com/gonolab/gono.cloud/compare/server-v1.0.0...HEAD
[1.0.0]: https://github.com/gonolab/gono.cloud/releases/tag/server-v1.0.0
