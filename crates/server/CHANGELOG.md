# Changelog: Gono Cloud server

All notable changes to the Gono Cloud server (the `gono-cloud` binary and the crates under
`crates/server/`) are recorded here. Server releases are tagged `server-v<version>` (see
`docs/repository-layout.md`); the release workflow takes the release notes from this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The protocol stays backward
compatible within a major version: released clients keep working with newer servers.

## [Unreleased]

## [1.0.0] - 2026-11-09

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
