# Repository layout

This repository is a monorepo: it holds the Gono Cloud server today, and the Gono client (sync
engine, desktop app, mobile apps) will move in once its rewrite starts. This document describes
the current layout, the planned one, and the rules that keep the two sides from getting in each
other's way.

## Current layout

```text
.
├── Cargo.toml              Cargo workspace: members, default-members, shared dependencies, lints
├── Cargo.lock              One lock file for the whole workspace
├── config.example.toml     Annotated server configuration
├── crates/
│   └── server/
│       ├── CHANGELOG.md    Changes of each server release
│       ├── bin/            gono-server: the `gono-cloud` binary (CLI, HTTP routing, Login Flow
│       │                   and admin UI pages with their templates and assets)
│       ├── core/           gono-server-core: configuration, SQLite metadata store and
│       │                   migrations, users, app passwords, web sessions, rescan
│       ├── dav/            gono-server-dav: WebDAV file system on top of dav-server
│       └── nextcloud/      gono-server-nextcloud: status, capabilities, OCS, chunked upload v2,
│                           Login Flow v2 documents, notify_push hub
├── packaging/
│   └── server/             Release archive contents (systemd unit, launchd job, README), the
│                           install script, the packing script and the install test
├── acceptance/             Black-box HTTP acceptance suite, its own workspace (see its README)
├── docs/                   Operator and project documentation
├── vendor/dav-server/      Patched copy of dav-server (see its VENDORED.md)
└── .github/workflows/      ci.yml (checks, tests, install test) and release-server.yml
```

Server crates are named `gono-server-*` (the binary crate is plain `gono-server`), so that no
name is ambiguous once client crates that also speak WebDAV join the workspace. Until the
restructure they were `gono-core`, `gono-dav` and `gono-nextcloud` under `crates/core`,
`crates/dav` and `crates/nextcloud`, and the binary crate lived in `crates/server`. Comments in
the released migrations under `crates/server/core/migrations/` still use those old names:
migrations are pinned by checksum and are never edited.

## Planned layout

Nothing below exists yet. Each part is added when work on it starts; there are no placeholder
crates or directories.

```text
crates/
├── protocol/           gono-protocol: wire types shared by server and client (request and
│                       response documents, capabilities)
├── server/             as above
└── client/
    ├── sync/           the sync engine
    └── ffi/            UniFFI bindings of the sync engine for the mobile apps
apps/
├── desktop/            Tauri 2 desktop app
├── android/            Android app
└── ios/                iOS app
```

`gono-protocol` is split out of the server crates only when the client work starts; until then
the wire types stay where they are used.

## Rules

### Default builds stay server-only

The root `Cargo.toml` lists the server crates in `default-members`. Client crates and the
desktop app will be workspace members but stay out of that list, so a plain `cargo build` or
`cargo test` in the repository root never builds Tauri or needs a mobile toolchain. Build them
explicitly with `-p <crate>`, or everything with `--workspace`.

### CI runs what a change touches

Today every CI job runs on every push. Once client code exists, the jobs get path filters:

- Server jobs run when `crates/server/**` changes, client jobs when `crates/client/**` or
  `apps/**` changes.
- The iOS job runs on macOS runners, and only when `apps/ios/**` changes.
- A change to `crates/protocol/**` runs both the server and the client jobs.
- Changes to shared files (the root `Cargo.toml`, `Cargo.lock`, `.github/workflows/**`) run
  everything.

### Releases are tagged per component

Each component is versioned and released on its own, with a prefixed tag: `server-v1.0.0`,
`desktop-v0.1.0`, `android-v0.1.0`, `ios-v0.1.0`. The tags of the legacy implementation
(`v0.1.4` and older) stay as they are.

Each component keeps:

- its version: the server's is the workspace version in the root `Cargo.toml`; a client crate
  or app that is versioned differently sets its own;
- a changelog next to its code, `crates/server/CHANGELOG.md` for the server (later
  `apps/desktop/CHANGELOG.md` and so on), with a section per released version;
- its packaging files under `packaging/<component>/`;
- a release workflow of its own, `.github/workflows/release-<component>.yml`, that reacts only
  to its tags, checks that the tag matches the version, takes the release notes from the
  changelog and creates a draft release for a maintainer to publish.

GitHub marks one release of the repository as "latest", whatever the component. Install
scripts and documentation therefore name a component's release by its tag
(`releases/download/server-v1.0.0/...`), never through `releases/latest`.

### The protocol stays backward compatible

Server and clients are released independently, and users do not update them together:

- The server never removes or changes the meaning of anything a released client uses.
- New abilities are advertised through capabilities (the `gono_cloud` block of the OCS
  capabilities), and clients check for them before use.
- Old released clients are tested against the current server.

### The acceptance suite stays black-box

`acceptance/` talks to a running server over HTTP only. It has its own `[workspace]` and lock
file and never depends on a crate of this repository, including `gono-protocol`: shared types
would let a wire-format change slip through on both sides at once, while the suite's own
definitions catch it.

### One lock file, with an escape hatch

All workspace members share one `Cargo.lock`, so server and client build against the same
dependency versions. If a dependency conflict between the server and the desktop app (Tauri)
cannot be resolved, `apps/desktop` gets its own `[workspace]` and lock file, the way
`acceptance/` already has, instead of holding back the rest of the workspace.

### Minimum Rust version

`rust-version` is set once for the workspace (`[workspace.package]` in the root `Cargo.toml`),
and CI checks the workspace with exactly that toolchain. A crate that needs a newer compiler,
for example because of Tauri or UniFFI, overrides `rust-version` in its own manifest instead of
raising it for everyone.
