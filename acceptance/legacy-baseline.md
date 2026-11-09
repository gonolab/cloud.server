# Legacy baseline

Result of the full acceptance suite against the legacy server, the last v0.1.x release (git
commit `d366e79`, v0.1.4).

- Run with `acceptance/scripts/run-legacy.sh` on 2026-11-09, macOS (APFS, case-insensitive),
  Rust 1.97.0. The script enables the legacy admin UI with `gono` as admin and creates the extra
  credentials (`readonly`, `scoped`, user `alice`). The legacy server has no separate web login
  password, so `GONO_ACCEPT_WEB_PASSWORD` is the bootstrap app password.
- `litmus` was not installed, so `RUN_LITMUS=1` was not exercised. The legacy documentation
  reports litmus 0.17 passing except for the `delete_fragment` warning.

## Summary

| Binary | Tests | Passed | Failed | Skipped (reported as passed) |
|---|---|---|---|---|
| `admin` | 4 | 2 | 2 | 0 |
| `login_flow` | 6 | 4 | 2 | 1 |
| `nextcloud` | 38 | 25 | 13 | 0 |
| `notify_push` | 12 | 11 | 1 | 0 |
| `scope` | 12 | 10 | 2 | 0 |
| `webdav` | 43 | 41 | 2 | 1 |
| **Total** | **115** | **93** | **22** | **2** |

All 22 failures are listed in `legacy-expected-failures.txt`; no other test fails. Everything else
passes, including all WebDAV core methods, locking, dead properties, chunked upload assembly,
status/capabilities/OCS, favorites and `filter-files`, read-only scope enforcement for every write
method except PATCH, scoped mounts, user isolation, and notify_push authentication and
notifications for PUT, MKCOL, COPY, MOVE, and chunked uploads.

Skipped:

- `webdav::regression_delete_keeps_metadata_of_case_variant_sibling`: the storage is
  case-insensitive (`Docs` and `docs` are the same directory on APFS). On a case-sensitive file
  system this test is expected to fail for defect 2 as well.
- `login_flow::web_password_is_not_a_device_credential`: the legacy server has no web login
  password distinct from the app password.

## Failures mapped to known defects

The numbering follows the defect list in the rewrite plan: 1–4 were reproduced by hand before,
5–8 were found by reading the code. Every one of them now has at least one failing test.

| # | Defect | Failing tests | Observed |
|---|---|---|---|
| 1 | A read-only app password can modify files with PATCH. | `scope::regression_read_only_scope_rejects_patch` | `PATCH` with `X-Update-Range: append` → 204 and the content changed to `original appended`. PUT with the same credential is 403. |
| 2 | Prefix queries use an unescaped, case-insensitive `LIKE`. | `webdav::regression_delete_keeps_metadata_of_wildcard_sibling`, `webdav::regression_move_keeps_metadata_of_wildcard_sibling` | After deleting **or moving** `photos_1`, `photosX1/x.txt` lost its dead property. Its `file_ids` row was deleted too, but the id came back from the `user.nc` xattr, so `oc:fileid` stayed the same. The MOVE case is new: `move_file_record` and `move_dead_props` use the same `LIKE 'photos_1/%'` pattern. |
| 3 | Two ETags for one file. | `nextcloud::regression_etag_is_identical_across_methods`, `nextcloud::regression_if_match_with_put_etag_succeeds`, `nextcloud::chunked_upload_reports_the_final_etag` | PUT, HEAD, `OC-ETag`, and the `filter-files` REPORT report `e-18e63dbcb0445428`; GET and PROPFIND report `cfb6118-e-65fce44c8c5b7`. `If-Match` with the PUT ETag → 412. The chunked upload `MOVE` response carries the database ETag as well. |
| 4 | Directory ETags do not propagate. | `nextcloud::regression_dir_etag_propagates_on_modify`, `nextcloud::dir_etag_propagates_on_{create,mkcol,delete,copy,move_between_directories,chunked_upload}` | Modifying `d1/d2/f.txt` leaves the ETags of `d2`, `d1`, and the test directory unchanged. Creating, deleting, copying, moving, and chunk-assembling change only the immediate parent (its mtime); grandparents keep their ETags. The root ETag sometimes changes only because parallel tests add or remove top-level directories. |
| 5 | Chunked upload does not verify `OC-Total-Length`. | `nextcloud::regression_chunked_upload_verifies_total_length` | Session created with `OC-Total-Length: 11`, 9 bytes uploaded, `MOVE .file` → 201 and a 9-byte file. |
| 6 | A standalone DELETE does not notify push clients. | `notify_push::regression_delete_triggers_a_file_notification` | No `notify_file` within 20 s after DELETE (the PUT before it was notified). The WebSocket filter resolves file ids to paths and drops ids whose rows were just deleted. |
| 7 | Login Flow v2 has no consent page and hands out the typed password. | `login_flow::regression_login_flow_requires_explicit_consent`, `login_flow::regression_login_flow_mints_a_new_app_password` | The flow page completes the flow as soon as Basic auth succeeds (poll → 200 before any consent), and `appPassword` equals the password typed in the browser. |
| 8 | The admin UI does not check app password scopes. | `admin::regression_admin_rejects_view_scoped_app_password`, `admin::admin_rejects_full_scope_app_password` | `GET /gono-admin/users` with the `readonly` (view) app password as Basic credentials → 200 with the user management page. The full-scope app password is accepted the same way; the rewrite only accepts the web login password through a session login. |

## New findings

Found while writing the suite. Each one fails a test that is on the expected list.

| Finding | Failing test | Observed |
|---|---|---|
| `oc:fileid` is not numeric. | `nextcloud::fileid_is_numeric_and_matches_oc_id` | `oc:fileid` is `59iJbmZI6sN9VWeIezS` (a counter followed by the instance id) and `oc:id` is `gono:59iJbmZI6sN9VWeIezS`. Nextcloud reports a numeric `oc:fileid` and an `oc:id` that starts with the zero-padded number; the Android app parses `oc:fileid` as a number and `notify_file_id` messages carry numbers. |
| `oc:size` is not supported. | `nextcloud::oc_size_reports_file_and_recursive_folder_sizes` | PROPFIND omits `oc:size` from the response for files and folders. Clients use it for folder sizes. |
| A read-only scope advertises write permissions. | `scope::read_only_scope_can_read` | With a `view` app password, files and folders report `oc:permissions` and `X-NC-Permissions` `RGDNV`: delete, rename, and move are advertised although the server answers 403. Clients offer actions that then fail. |

Smaller observations without a dedicated test:

- PROPFIND `DAV:getetag` values have no quotes (`cfb6118-e-65fce44c8c5b7`); RFC 4918 defines the
  property as a quoted entity tag, and Nextcloud returns quoted values. The suite normalizes
  quotes before comparing, so it does not fail on this.
- The chunked upload `MOVE` response has `OC-ETag` but no `ETag` header.
- PROPFIND on an upload session (`/remote.php/dav/uploads/<user>/<id>`) returns 404, so a client
  cannot list the chunks it already uploaded to resume an upload.
- With a `view` scope, folder hrefs in PROPFIND lose their trailing slash
  (`/remote.php/dav/files/gono/probe` instead of `.../probe/`).
