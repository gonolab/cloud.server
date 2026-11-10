# Gono Cloud acceptance tests

Black-box HTTP acceptance tests for Gono Cloud. The suite talks to a running server only through
HTTP and WebSocket requests, so it can verify any implementation: the legacy v0.1.x server
(commit `d366e79`) and the rewrite alike. It does not depend on any crate under `crates/` and is
not a member of the root workspace (`[workspace]` in `Cargo.toml`, own `Cargo.lock`).

The assertions follow the rewrite's design (`docs/v1-scope.md`). Where the legacy server behaves
differently, its tests fail on purpose; [`legacy-baseline.md`](legacy-baseline.md) lists those
failures and [`legacy-expected-failures.txt`](legacy-expected-failures.txt) is the
machine-readable list. [`new-expected-failures.txt`](new-expected-failures.txt) lists, with a
reason for each, the tests the rewrite does not pass yet because their feature belongs to a later
phase.

## Running

Against any server:

```sh
export GONO_ACCEPT_BASE_URL=http://127.0.0.1:16102
export GONO_ACCEPT_USER=gono
export GONO_ACCEPT_PASSWORD=<full-scope app password>
cargo test --manifest-path acceptance/Cargo.toml
```

Against the server built from this checkout, with everything set up and torn down
automatically:

```sh
acceptance/scripts/run-new.sh
RUN_LITMUS=1 acceptance/scripts/run-new.sh   # also run litmus
```

The script builds `gono-cloud`, runs `init --password-stdin` in a temporary directory, starts
`serve` on a free loopback port with the web admin UI enabled, creates a second user and the
credentials below with the `user` and `app-password` commands, runs `cargo test`, and compares the failing tests with
`new-expected-failures.txt`. It exits non-zero when a test fails that is not on the list, when a
listed test passes, or (with `RUN_LITMUS=1`) when litmus is missing or fails. litmus runs against
`<base>/remote.php/dav/files/gono/`. CI runs it on Linux with `RUN_LITMUS=1`.

| Script option or variable | Effect |
|---|---|
| `-- <args>` | Extra arguments for the test binaries, e.g. `-- --test-threads=4`. |
| `--serve` | Start the server, print the path of an env file with the credentials, and wait for Ctrl-C instead of running the tests. |
| `NEW_TARGET_DIR=<dir>` | Cargo target directory for the server build (default: the repository's `target/`). |
| `RUN_LITMUS=1` | Also run litmus; fails when it is not installed. |
| `LITMUS=<path>` | `litmus` binary to use instead of the one on `PATH` (set `TESTROOT` too for an uninstalled build). |
| `KEEP_WORK_DIR=1` | Keep the temporary config, data directory, and logs. |
| `SERVER_PORT=<port>` | Loopback port of the server instead of a free one. |
| `PUBLIC_URL=<url>` | Public origin (`base_url`) that the suite and litmus use instead of the server's own address: a reverse proxy forwarding to `127.0.0.1:SERVER_PORT`. |

To test a reverse proxy configuration, start the proxy so that it forwards a local port to
`SERVER_PORT`, then run the suite through it; the notify_push tests connect to the WebSocket
URL the capabilities advertise, which is built from `PUBLIC_URL`, so they go through the proxy
as well:

```sh
SERVER_PORT=18091 PUBLIC_URL=http://127.0.0.1:18090 RUN_LITMUS=1 acceptance/scripts/run-new.sh
```

Against the legacy server, with everything set up and torn down automatically:

```sh
acceptance/scripts/run-legacy.sh
```

The script checks `d366e79` out into a temporary git worktree, builds it, starts it on a free
loopback port with a throwaway config and data directory, mints the credentials below with the
legacy CLI, runs `cargo test`, and compares the failing tests with
`legacy-expected-failures.txt`. It exits non-zero when a test fails that is not on the list, or
when a listed test passes. Everything it created is removed on exit. `tests/xml_limits.rs` is
skipped there: the legacy server crashes on a deeply nested XML body, which would take every
other running test down with it.

| Script option or variable | Effect |
|---|---|
| `-- <args>` | Extra arguments for the test binaries, e.g. `-- --test-threads=4`. |
| `--serve` | Start the legacy server, print the path of an env file with the credentials, and wait for Ctrl-C instead of running the tests. |
| `LEGACY_REV=<rev>` | Legacy revision to check out (default `d366e79`). |
| `LEGACY_TARGET_DIR=<dir>` | Cargo target directory for the legacy build. Point it at a persistent directory to reuse the build between runs. |
| `RUN_LITMUS=1` | Also run `litmus <base>/remote.php/dav/ gono <password>` when `litmus` is installed (skipped with a notice otherwise). |
| `LITMUS=<path>` | `litmus` binary to use instead of the one on `PATH`. |
| `KEEP_WORK_DIR=1` | Keep the temporary config, data directory, and logs. |

## Environment variables

Only `GONO_ACCEPT_*` variables configure the suite. Without `GONO_ACCEPT_BASE_URL` every test is
skipped. When an optional credential is missing, the tests that need it are skipped. A skipped
test still reports `ok`; it prints `SKIP <test>: <reason>` to stderr (also visible without
`--nocapture`).

| Variable | Required | Meaning |
|---|---|---|
| `GONO_ACCEPT_BASE_URL` | yes | Public server origin, e.g. `https://cloud.example.com` (a path prefix is allowed). |
| `GONO_ACCEPT_USER` | yes | User the tests run as. |
| `GONO_ACCEPT_PASSWORD` | yes | Device app password of that user with `full` permission mounted at `/`. |
| `GONO_ACCEPT_VIEW_PASSWORD` | no | App password of the same user with `view` permission mounted at `/` (legacy CLI: `app-password-add gono readonly --mount /=/:view`). |
| `GONO_ACCEPT_SCOPED_PASSWORD` | no | App password of the same user with two mounts: `/acc-view` → `/acc-scope/view` (`view`) and `/acc-full` → `/acc-scope/full` (`full`). The tests create the storage directories when they are missing. |
| `GONO_ACCEPT_WEB_PASSWORD` | no | The user's web login password, used for Login Flow v2 and the web admin UI. On the legacy server this is the app password. |
| `GONO_ACCEPT_ADMIN_PATH` | no | Web admin UI path (default `/gono-admin`). The user must be an admin. |
| `GONO_ACCEPT_USER2` | no | A second, unrelated, non-admin user. `run-new.sh` names it `alice@example.com`; the href test for names with `@` is skipped for names without one. |
| `GONO_ACCEPT_PASSWORD2` | no | Full-scope app password of `GONO_ACCEPT_USER2`. |
| `GONO_ACCEPT_PUSH_TIMEOUT_SECS` | no | How long to wait for a notify_push message (default 20). |

## Isolation and cleanup

- Every test that writes data creates its own directory `acc-<test name>-<random>` in the user's
  files root (and, for multi-user and scoped tests, the matching directories in the second user's
  root and under `acc-scope/view` and `acc-scope/full`). The directories are deleted when the test
  ends, also when it fails, so the suite can be re-run against the same server. Only the empty
  mount targets `acc-scope/view` and `acc-scope/full` stay behind.
- Tests run in parallel inside a binary. The notify_push tests run one at a time, because a
  change made by a parallel test of the same user would satisfy a "notification received" check.
  cargo runs the test binaries one after another. Do not run the suite while real clients of the
  test user are active.
- A few tests send a wrong password on purpose (WebDAV, Login Flow, notify_push). A server with
  brute-force protection should not lock the account after this handful of failures.

## Test groups

| Binary | Tests | Covers |
|---|---|---|
| `webdav` | 43 | OPTIONS; authentication challenges; PROPFIND Depth 0/1, Depth infinity answered as Depth 1, allprop, 404 propstats; GET/HEAD/PUT (overwrite, empty, 3 MiB, missing parent); MKCOL; DELETE (recursive); COPY/MOVE (overwrite, `Overwrite: F`, recursive, missing parent); PROPPATCH dead properties (set, remove, collections, copy/move, delete-and-recreate); LOCK/UNLOCK (blocking writes, conflicts, unknown tokens); special characters in names; encoded `..` and NUL segments; LIKE-wildcard regressions. |
| `nextcloud` | 42 | `status.php`; `/index.php/204`; capabilities on the v1/v2 and `index.php` aliases; OCS `cloud/user` (v1/v2 aliases, auth, other users); live properties (`oc:fileid`, `oc:id`, `oc:permissions`, `oc:favorite`, `oc:size`); the `d:` prefix and SabreDAV-style hrefs (`@` in user names); `OC-ETag`, `OC-FileId`, `X-NC-Permissions`, `X-OC-MTime`; file id stability; one ETag per file version, `If-Match`/`If-None-Match`; directory ETag propagation for every write operation; favorites with PROPPATCH and the `filter-files` REPORT; chunked upload v2 (assembly, overwrite, invalid names, mismatched destination, 507, total length, cancel). |
| `scope` | 12 | Read-only scope: reads work, permissions are read-only, every write method including PATCH and chunked upload is refused. Scoped app password: only its mounts are visible, mount paths map to storage paths, paths outside the mounts and writes into the `view` mount are refused. Users cannot reach each other's files, also not through `Destination`, `..` segments, or the upload namespace. |
| `login_flow` | 6 | Login Flow v2 init on both paths, pending polls, wrong passwords, an explicit consent page, a newly minted per-device app password, single-use poll tokens; the web login password is not a WebDAV credential. |
| `admin` | 4 | The admin UI needs a login, accepts the web login password, and refuses app passwords of any scope (as Basic credentials and at its login form). |
| `notify_push` | 12 | Capabilities; WebSocket authentication with an app password, bad credentials, and single-use pre-auth tokens; notifications for PUT, MKCOL, COPY, MOVE, chunked upload, and DELETE; `listen notify_file_id`; no notifications for other users. |

The Login Flow and admin tests drive plain HTML pages: they follow redirects, keep cookies, answer
HTTP Basic challenges, fill forms with a password field (username field matched by name), and
submit "grant"-like forms. They do not run JavaScript, so those pages must work without it.

### Regression tests

Tests named `regression_*` reproduce defects found in the legacy server. They must pass on the
rewrite.

| Defect in the legacy server | Test |
|---|---|
| A read-only app password can rewrite files with `PATCH` + `X-Update-Range: append`. | `scope::regression_read_only_scope_rejects_patch` |
| Deleting or moving `photos_1` also deletes or rewrites the metadata (dead properties, file id row) of `photosX1/x.txt` (unescaped `LIKE`). | `webdav::regression_delete_keeps_metadata_of_wildcard_sibling`, `webdav::regression_move_keeps_metadata_of_wildcard_sibling` |
| Deleting `Docs` deletes the metadata of `docs/x.txt` (`LIKE` is case-insensitive). Runs only when the server storage is case-sensitive. | `webdav::regression_delete_keeps_metadata_of_case_variant_sibling` |
| Two ETags for one file; `If-Match` with the PUT ETag returns 412. | `nextcloud::regression_etag_is_identical_across_methods`, `nextcloud::regression_if_match_with_put_etag_succeeds` |
| Modifying `d1/d2/f.txt` does not change the ETags of `d2`, `d1`, and the root. | `nextcloud::regression_dir_etag_propagates_on_modify` |
| The assembled chunked upload is not checked against `OC-Total-Length`. | `nextcloud::regression_chunked_upload_verifies_total_length` |
| A standalone DELETE does not trigger a notify_push notification. | `notify_push::regression_delete_triggers_a_file_notification` |
| Login Flow v2 has no consent page and returns the typed password as `appPassword`. | `login_flow::regression_login_flow_requires_explicit_consent`, `login_flow::regression_login_flow_mints_a_new_app_password` |
| The admin UI does not check app password scopes. | `admin::regression_admin_rejects_view_scoped_app_password` |

## Not covered

- `sync-collection` REPORT (out of scope for v1).
- Legacy-only behavior that is not part of the v1 scope: `/metrics`, the admin page contents, OCS
  placeholder endpoints (shares, notifications, user status, ...), `SEARCH`, the WebDAV aliases at
  `/` and `/remote.php/dav/` without `files/<user>`, `X-NC-WebDAV-AutoMkcol`, the notify_push test
  routes and `gono_client_info`.
- Cases from the legacy in-process tests (`d366e79:tests/phase0.rs`) that need access to the
  server's file system, database, configuration, or a restart: symlink escapes, the upload space
  reserve, bootstrap password generation, lock persistence across restarts, change log pruning,
  expired upload cleanup, pre-auth token expiry, connection limits, and disabled or relocated
  notify_push.
- The desktop client: `scripts/nextcloudcmd-scenarios.sh` (below) syncs real folders with
  `nextcloudcmd` instead.

## nextcloudcmd sync scenarios

```sh
acceptance/scripts/nextcloudcmd-scenarios.sh
```

Starts the server built from this checkout like `run-new.sh` and syncs two local folders
("devices") with the Nextcloud desktop client's command line tool: first sync, upload, a change
deep in the tree made on the other device, renames (including a case-only rename, skipped when
the local file system ignores case), deletes, and a 30 MiB file uploaded and replaced through
chunked upload. Every scenario checks the server over WebDAV and the other device; the chunked
upload is confirmed from the server's request log. CI runs it on Linux with `nextcloudcmd` from
the `nextcloud-desktop-cmd` package.

| Variable | Effect |
|---|---|
| `NEXTCLOUDCMD=<path>` | `nextcloudcmd` binary to use instead of the one on `PATH`. |
| `NEW_TARGET_DIR=<dir>` | Cargo target directory for the server build. |
| `KEEP_WORK_DIR=1` | Keep the configuration, data, sync folders and logs (`nextcloudcmd.log`, `server.log`). |
