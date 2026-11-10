# Gono Cloud server

Gono Cloud is a self-hosted WebDAV file server compatible with Nextcloud clients. This README is
part of every server release archive; in the repository, `packaging/server/` holds the files
those archives are made of and the scripts that build and install them.

## Release archive

`gono-cloud-<version>-<target>.tar.gz` contains one directory of the same name:

| File | Purpose |
|---|---|
| `gono-cloud` | The server and its command line interface |
| `config.example.toml` | Annotated configuration |
| `systemd/gono-cloud.service` (Linux) | Hardened systemd unit |
| `launchd/cloud.gono.server.plist` (macOS) | launchd job |
| `CHANGELOG.md` | Changes of each server release |
| `LICENSE-APACHE`, `LICENSE-MIT` | The license: MIT OR Apache-2.0, at your option |

The Linux binaries are fully static (musl, with mimalloc as the memory allocator): they need no
C library on the system and run on any x86_64 or aarch64 Linux distribution, glibc-based or not
(Alpine). The install script additionally needs systemd. macOS builds need macOS 11 or newer.

### musl notes

The Linux binaries use musl instead of glibc. Two differences between them were checked and do
not affect the server:

- **Name resolution.** musl's resolver handles search domains and large DNS responses
  differently from glibc's. The server resolves no names at all: it makes no outbound
  connections, `server.bind` is an address literal, `server.trusted_proxies` are addresses and
  CIDR blocks, and `server.base_url` is only used to build URLs. If outbound connections are
  ever added, use a resolver written in Rust (such as hickory-resolver) instead of
  `getaddrinfo`.
- **Thread stacks.** musl's default thread stack is about 128 KiB, glibc's 8 MiB. The server
  starts every thread through Rust's standard library or tokio, which set the stack size
  explicitly (2 MiB), and the main thread's stack comes from the kernel (`ulimit -s`). The
  bundled SQLite and mimalloc start no threads of their own. Stack sizes are therefore the same
  as with glibc.

## Installing

Download `cloud.server.sh` from the release you want and run it as root. It downloads that
release's archive for this machine, verifies it against `SHA256SUMS`, installs the binary and the
service, and on a fresh install writes the configuration and creates the first admin account.
`https://gono.dev/cloud.server.sh` redirects to the script of the newest server release:

```sh
curl -fsSLo cloud.server.sh https://gono.dev/cloud.server.sh
sudo sh cloud.server.sh --base-url https://cloud.example.com
```

The deployment guide covers the details, a manual installation, the reverse proxy, upgrades,
backups and uninstalling:
<https://github.com/gonolab/gono.cloud/blob/main/docs/deployment.md>.

## Repository files

| File | Purpose |
|---|---|
| `cloud.server.sh` | Installer for Linux (systemd) and macOS (launchd); `--help` lists its options |
| `package.sh` | Packs a compiled binary into a release archive |
| `test-install.sh` | End-to-end test of `cloud.server.sh`; installs a service, so it only runs in CI |
| `test-static.sh` | Checks that a Linux archive's binary is static and runs without glibc (containers) |
| `systemd/`, `launchd/` | Service definitions shipped in the archives |
| `zigbuild-requirements.txt` | Pinned zig toolchain for the static Linux builds |

The release workflow, `.github/workflows/release-server.yml`, builds the archives when a
`server-v<version>` tag is pushed.
