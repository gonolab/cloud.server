# Gono Cloud

Gono Cloud is a self-hosted WebDAV file server compatible with Nextcloud clients.

## Status

The project is being rewritten from scratch on top of
[dav-server-rs](https://github.com/messense/dav-server-rs). Nextcloud clients can use it:
users and app passwords (`gono-cloud user`, `gono-cloud app-password`), WebDAV under
`/remote.php/dav/files/<user>/` with Nextcloud live properties, ETags and locks, read-only or
scoped app passwords, `status.php`, capabilities and the OCS user endpoints, favorites with the
`filter-files` REPORT, chunked upload v2, and Login Flow v2 with an explicit consent page. The
desktop client is tested with `nextcloudcmd` in CI; the mobile apps with
`docs/mobile-checklist.md`. notify_push, the web admin UI and `gono-cloud rescan` are not there
yet; see `docs/v1-scope.md` and `acceptance/new-expected-failures.txt`.

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

`vendor/dav-server` is a patched copy of dav-server (Apache-2.0); see its `VENDORED.md`.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
