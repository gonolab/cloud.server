# Mobile client checklist

Manual test of the Nextcloud mobile apps against Gono Cloud. The desktop client is covered
automatically (`acceptance/scripts/nextcloudcmd-scenarios.sh`); the Android and iOS apps are
checked with this list before a release and after changes to the Nextcloud protocol surface.

Run every section on **Android** and on **iOS**. Record the results in the table at the end,
together with every request the server answered with `404`, `405` or `501` (see
[Server log](#server-log)): those answer the open question in `docs/v1-scope.md` about the
endpoints the mobile apps call.

## Setup

1. Run a release build of `gono-cloud` behind a reverse proxy with HTTPS and a certificate the
   phones trust (the apps refuse plain HTTP and warn about self-signed certificates).
   `server.base_url` must be the public `https://` origin.
2. Set `logging.level = "info"`, so that every request is logged with its method, path and
   status (tokens are redacted).
3. Create a test user and set their web login password:

   ```sh
   gono-cloud user add mobiletest
   ```

4. Prepare test files from another device (the desktop client or `curl`): a folder tree at least
   three levels deep, a file with spaces and non-ASCII characters in its name (`Ümlaut ß.txt`),
   a photo, and a file larger than 50 MiB.
5. Install the current release of the app from the store. Note the app version.

## 1. Add the account (Login Flow v2)

| # | Step | Expected |
|---|---|---|
| 1.1 | Add an account, enter the server address. | The app accepts the server (no "unsupported server" or "ownCloud is not supported" message) and opens the login page in a browser. |
| 1.2 | Look at the page. | "Connect a device" page of Gono Cloud that names the app, e.g. `Nextcloud Android 3.30.0` or `Nextcloud iOS 6.0.0`. No JavaScript errors, readable in light and dark mode. |
| 1.3 | Sign in with a wrong password. | "Wrong username or password." The app does not log in. |
| 1.4 | Sign in with the web login password. | The consent page "Grant access?" names the app and the account. The app is still waiting. |
| 1.5 | Press **Grant access**. | "Access granted"; the app finishes the login within a few seconds and shows the files. |
| 1.6 | On the server: `gono-cloud app-password list mobiletest`. | A new app password labeled with the app name, `last used` set. The web login password was not handed to the app. |
| 1.7 | Start adding the account again on a second phone (or after removing it) and press **Cancel** on the consent page. | "Access denied". The app does not log in (it gives up when the request expires after 20 minutes, or when the user cancels in the app). |
| 1.8 | Remove the account in the app. | `gono-cloud app-password list` no longer shows its app password (the app revokes it with `DELETE /ocs/v2.php/core/apppassword`). |

Add the account again (1.1–1.5) for the following sections.

## 2. Browse

| # | Step | Expected |
|---|---|---|
| 2.1 | Open the root and the nested folders. | All files and folders are listed with sizes and modification times; folder sizes are the total of their content. |
| 2.2 | Open the file with spaces and non-ASCII characters. | Listed and opened with the right name. |
| 2.3 | Change a file three levels deep from another device, then refresh the root in the app and go down to the file. | The app shows the new size and time (directory ETags changed up to the root). |
| 2.4 | Look at the actions offered for files and folders. | No sharing, no versions, no comments, no trash bin. Missing thumbnails are fine (previews are out of scope). |
| 2.5 | Account or settings screen. | Display name and storage usage are shown (quota is "unlimited" with the free space of the server). |

## 3. Upload

| # | Step | Expected |
|---|---|---|
| 3.1 | Upload a small file and a photo into a subfolder. | Uploaded; visible on another device with the same content. |
| 3.2 | Upload the file larger than 50 MiB. | Uploaded in chunks: the server log shows `MKCOL`, several `PUT` and one `MOVE .../.file` under `/remote.php/dav/uploads/<user>/`. The content matches the original (compare checksums). |
| 3.3 | Start another large upload and switch on airplane mode halfway; switch it off again. | The upload resumes or restarts and finishes; the file is complete. A `PROPFIND` on the upload session in the server log shows the app listing the chunks it already sent. |
| 3.4 | Upload a file with the same name as an existing one and choose "replace". | The file is replaced; its file id (shown as `oc:fileid` in a PROPFIND) stays the same. |
| 3.5 | Optional: enable automatic photo upload and take a photo. | The photo is uploaded into the configured folder. |

## 4. Download

| # | Step | Expected |
|---|---|---|
| 4.1 | Open a text file, a photo and the large file. | They open with the right content. |
| 4.2 | Make a file available offline, change it on another device, refresh. | The app downloads the new version. |

## 5. Favorites

| # | Step | Expected |
|---|---|---|
| 5.1 | Mark a file deep in the tree and a folder as favorites. | The star is set; it is still set after a refresh and on another device. |
| 5.2 | Open the Favorites view. | Both favorites are listed. The server log shows `REPORT` with status `207`. If the app uses `SEARCH` instead (logged as `405`), record it: `SEARCH` is not part of v1. |
| 5.3 | Remove a star. | The item disappears from the Favorites view. |
| 5.4 | Rename and then move a favorite file. | It stays a favorite and is listed under its new name. |

## 6. Rename and move

| # | Step | Expected |
|---|---|---|
| 6.1 | Rename a file and a folder with content. | Renamed on the server; the folder content is intact. |
| 6.2 | Rename a file so that only the case changes (`notes.txt` → `Notes.txt`). | Renamed (on servers whose storage is case-sensitive, which is the normal Linux setup). |
| 6.3 | Move a file into another folder. | Moved; another device sees it at the new place. |

## 7. Delete

| # | Step | Expected |
|---|---|---|
| 7.1 | Delete a file and a folder with content. | Gone from the server and from another device after a refresh. There is no trash bin: the deletion is permanent, and the app must not offer to restore. |

## Server log

Collect the requests that did not succeed while going through the list:

```sh
grep -E 'status=(404|405|501)' /path/to/gono-cloud.log | grep -o 'method=[A-Z]* target=[^ ]*' | sort | uniq -c
```

`404` for files that were just deleted or moved is normal. Note OCS endpoints
(`/ocs/v2.php/...`), `SEARCH`, `REPORT` and anything under `/index.php/` that is not Login Flow.

## Results

| Section | Android (app version: ) | iOS (app version: ) |
|---|---|---|
| 1. Add the account | | |
| 2. Browse | | |
| 3. Upload | | |
| 4. Download | | |
| 5. Favorites | | |
| 6. Rename and move | | |
| 7. Delete | | |
| Failed requests from the log | | |

Server version (`gono-cloud --version`), date and tester:
