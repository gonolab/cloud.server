# Changelog: Gono Cloud server

All notable changes to the Gono Cloud server (the `gono-cloud` binary and the crates under
`crates/server/`) are recorded here. Server releases are tagged `server-v<version>` (see
`docs/repository-layout.md`); the release workflow takes the release notes from this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The protocol stays backward
compatible within a major version: released clients keep working with newer servers.

## [Unreleased]

### Changed

- The web admin UI moves to `/apps/manage/` by default (`admin.path`), next to the web file UI
  and the account page; `admin.path` may now be `/apps/manage` although `/apps` is otherwise
  reserved. Configurations that set `path` keep their path: the one written by the install
  script of 1.0 to 1.2 sets `path = "/gono-admin"`; change it to `"/apps/manage"` or remove the
  line to move the admin UI, and adjust reverse proxy rules that restrict the old path.

## [1.2.0] - 2026-11-12

A web file UI and account page in the browser, and every page in English or Chinese. There are
no database migrations. Upgrading turns the web file UI on: configurations written for 1.x have
no `[files_ui]` section, so `/` now leads to the sign-in page; add `[files_ui]` with
`enabled = false` to keep it off. The admin UI keeps its setting where the configuration sets
`enabled` in `[admin]`, as the one written by the 1.x install script does (`enabled = false`).

### Added

- A web file UI at `/apps/files/` (`/` leads there), on by default (`files_ui.enabled`). Users
  sign in at `/login` with their web login password and can browse, sort and search by name,
  preview images, video, audio and text, download files and folders (folders and selections
  as streamed `.zip` archives), upload (a form without JavaScript; drag and drop, folders and
  resumable chunked uploads with it), create folders, rename, move and delete (one or many
  entries), and mark favorites, which the apps see too. Everything works without JavaScript.
  Every change is a WebDAV operation of the server itself, so ETags, file ids, locks and
  notify_push behave as for the clients. User files never open as part of the site: downloads
  are attachments, and only images, video and audio are shown inline, with a type the server
  chooses.
- An account page at `/apps/account/`: users change their display name and web login password
  (the other browser sessions end) and create, view and revoke their own app passwords.
- Every browser page, the admin UI included, follows the browser's language (English or
  Chinese) and offers a light, dark or system theme.
- `/index.php/apps/files/` (Nextcloud's web address, which the apps link to) leads to the web
  file UI.

### Changed

- The web admin UI is on by default (`admin.enabled = true`). Installations that rely on the old
  default and do not want it must set `enabled = false` in `[admin]`.
- Every HTML page (sign-in, Login Flow, admin UI) has a new look and a shared masthead. Pages
  load one stylesheet and one script from `/apps/assets/` under content-hashed names; the
  Content-Security-Policy allows exactly that script by a per-response nonce and still no
  inline styles or scripts.

## [1.1.1] - 2026-11-11

Security fix for the direct download links added in 1.1.0. Every installation of 1.1.0 should
upgrade; there are no database migrations.

### Security

- User files no longer open as part of the site. Direct download links need no credentials and
  served a file with its own type, so a user could send an administrator a link to an HTML file
  whose scripts then ran on the server's origin, with the administrator's web session and
  access to the admin UI. File downloads through WebDAV and direct links are now sent with
  `Content-Disposition: attachment` (named after the file, not the link's token), and every
  response of the WebDAV routes and of direct links carries
  `Content-Security-Policy: default-src 'none'; sandbox` and `X-Content-Type-Options: nosniff`.
  1.0.0 had no direct links; its WebDAV downloads lacked these headers too, but reached a
  browser only with the file owner's app password.

## [1.1.0] - 2026-11-11

Fixes for the Nextcloud mobile apps found by testing them against 1.0.0, media streaming and
rclone uploads. Upgrading applies two database migrations; going back to 1.0.0 afterwards needs
the database backup that the install script takes before the upgrade (see "Upgrading" in
`docs/deployment.md`).

### Added

- Chunked upload accepts chunks named by byte range (`<start>-<end>`, the end inclusive), as
  rclone's Nextcloud backend sends them, so that `rclone` with `vendor = nextcloud` can upload
  files larger than its chunk size. The ranges must cover the file from byte 0 without gaps or
  overlaps; a session holds either numbered chunks or byte ranges.
- Direct download links (`POST /ocs/v2.php/apps/dav/api/v1/direct`, then
  `GET /remote.php/direct/<token>` without credentials), through which the Nextcloud mobile
  apps stream video and audio that is not downloaded yet; before, such files did not play. A
  link expires after 8 hours (at most a day) and ends with the app password that asked for it
  or the file it names.

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

[Unreleased]: https://github.com/gonolab/gono.cloud/compare/server-v1.2.0...HEAD
[1.2.0]: https://github.com/gonolab/gono.cloud/compare/server-v1.1.1...server-v1.2.0
[1.1.1]: https://github.com/gonolab/gono.cloud/compare/server-v1.1.0...server-v1.1.1
[1.1.0]: https://github.com/gonolab/gono.cloud/compare/server-v1.0.0...server-v1.1.0
[1.0.0]: https://github.com/gonolab/gono.cloud/releases/tag/server-v1.0.0
