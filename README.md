# Gono Cloud

Gono Cloud is a self-hosted WebDAV file server compatible with Nextcloud clients.

## Status

Version 1.0.0 is the first release of the rewrite on top of
[dav-server-rs](https://github.com/messense/dav-server-rs); see the
[changelog](crates/server/CHANGELOG.md) and [`docs/v1-scope.md`](docs/v1-scope.md). Nextcloud
clients can use it: users and app passwords, WebDAV under `/remote.php/dav/files/<user>/` with
Nextcloud live properties, ETags and locks, read-only or scoped app passwords, `status.php`,
capabilities and the OCS user endpoints, favorites with the `filter-files` REPORT, chunked
upload v2, Login Flow v2 with an explicit consent page, notify_push for real-time change
notifications, a web admin UI, and `gono-cloud rescan` for files changed directly in the data
directory. The desktop client is tested with `nextcloudcmd` in CI; the mobile apps with
[`docs/mobile-checklist.md`](docs/mobile-checklist.md).

## Quick start

Release builds exist for Linux (x86_64 and aarch64; static binaries for any distribution, the
install script needs systemd) and macOS 11 or newer. Download `install.sh` from a
[server release](https://github.com/gonolab/gono.cloud/releases) and run it with the address
users will open:

```sh
sudo sh install.sh --base-url https://cloud.example.com
```

It verifies and installs the binary, creates the `gono-cloud` service user, writes
`/etc/gono-cloud/config.toml`, asks for the password of the first admin account and starts the
service on `127.0.0.1:16102`. Then put a reverse proxy with HTTPS in front of it
([`docs/reverse-proxy.md`](docs/reverse-proxy.md)) and connect a Nextcloud client to
`https://cloud.example.com`. [`docs/deployment.md`](docs/deployment.md) covers manual
installation, accounts, upgrades, backups and uninstalling.

To build from source instead (Rust 1.94 or newer):

```sh
cargo build --release --locked
target/release/gono-cloud --help
```

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the checks to run before sending a change, and
[`SECURITY.md`](SECURITY.md) for reporting vulnerabilities privately.

## Repository layout

The server crates live under `crates/server/`. The repository is a monorepo that the Gono client
will join once its rewrite starts; [`docs/repository-layout.md`](docs/repository-layout.md)
describes the current and planned layout and the rules for both sides.

## Legacy implementation

The previous implementation was removed in preparation for the rewrite. It is kept in the git
history for reference:

- Last commit of the legacy code: `d366e79`
- Last legacy release: `v0.1.4`

To browse it:

```sh
git checkout d366e79
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
