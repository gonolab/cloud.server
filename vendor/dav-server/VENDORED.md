# Vendored dav-server

This directory holds [dav-server](https://crates.io/crates/dav-server) **0.11.0**, copied from
the published crate (`src/` and `README.md`; the manifest without examples, tests and
dev-dependencies). It replaces the crates.io release through `[patch.crates-io]` in the root
`Cargo.toml`. The crate is licensed under Apache-2.0 (see `LICENSE-APACHE` in the repository
root); copyright remains with its authors.

## Why

Gono Cloud runs every WebDAV request through dav-server and never rewrites its XML output.
dav-server 0.11.0 (the latest release, and upstream `main` as of 2026-11-09) silently drops
properties it cannot find from a `PROPFIND` with `<D:prop>`, while RFC 4918, section 9.1,
requires them in a `404 Not Found` propstat. Clients and the acceptance suite rely on that 404
to tell a removed dead property from a server that ignored the request.

## Changes

Every change is marked with a `GONO PATCH` comment in the source.

1. `src/handle_props.rs`, `PropWriter::write_props`: properties requested by name that do not
   exist are reported in a 404 propstat. `allprop` and `propname` responses are unchanged.

## Removing the copy

Drop this directory and the `[patch.crates-io]` entry once a dav-server release contains
equivalent fixes, then run the acceptance suite (`acceptance/scripts/run-new.sh`).
