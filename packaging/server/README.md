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

Linux builds need glibc 2.28 or newer (Debian 10, Ubuntu 20.04, RHEL 8 and later); macOS builds
need macOS 11 or newer.

## Installing

Download `install.sh` from the release you want and run it as root. It downloads that release's
archive for this machine, verifies it against `SHA256SUMS`, installs the binary and the service,
and on a fresh install writes the configuration and creates the first admin account:

```sh
sudo sh install.sh --base-url https://cloud.example.com
```

The deployment guide covers the details, a manual installation, the reverse proxy, upgrades,
backups and uninstalling:
<https://github.com/gonolab/cloud.server/blob/main/docs/deployment.md>.

## Repository files

| File | Purpose |
|---|---|
| `install.sh` | Installer for Linux (systemd) and macOS (launchd); `--help` lists its options |
| `package.sh` | Packs a compiled binary into a release archive |
| `test-install.sh` | End-to-end test of `install.sh`; installs a service, so it only runs in CI |
| `systemd/`, `launchd/` | Service definitions shipped in the archives |
| `zigbuild-requirements.txt` | Pinned zig toolchain for the Linux release builds |

The release workflow, `.github/workflows/release.yml`, builds the archives when a
`server-v<version>` tag is pushed.
