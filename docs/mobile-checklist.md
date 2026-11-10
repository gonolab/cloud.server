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
3. Create a test user and set their web login password, and a second one whose name contains
   `@` (run sections 1 and 2 with it as well: the apps compare URLs with the user name):

   ```sh
   gono-cloud user add mobiletest
   gono-cloud user add mobile@example.com
   ```

4. Prepare test files from another device (the desktop client or `curl`): a folder tree at least
   three levels deep, a file with spaces and non-ASCII characters in its name (`Ümlaut ß.txt`),
   a photo, a file larger than 50 MiB, an MP4 video and an MP3, and a file whose name was
   created on a Mac with a decomposed accent (`Café.txt` typed in Finder). Create a folder with
   at least 5,000 small files on the server and run `gono-cloud rescan` for it.
5. Install the current release of the app from the store. Note the app version. The apps switch
   features by the Nextcloud version the server reports; check that the gates listed at
   `NEXTCLOUD_VERSION` (`crates/server/nextcloud/src/status.rs`) still hold for this version.

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
| 1.8 | Remove the account in the app. | Android: `gono-cloud app-password list` no longer shows its app password (the app revokes it with `DELETE /ocs/v2.php/core/apppassword`). iOS 35 only removes the account locally and leaves the app password; revoke it with `gono-cloud app-password delete`. |
| 1.9 | Look at the file list right after signing in. | No "end of life", "outdated" or "unsupported server" message (Android shows it as a snackbar under the file list). |
| 1.10 | With a second device signed in on the same network: revoke the first device's app password with `gono-cloud app-password delete`, then refresh in its app and keep it trying for a minute. | iOS says the account is no longer authorized and removes it; Android asks for a new login. The second device keeps syncing (no `429` for it in the server log). |

Add the account again (1.1–1.5) for the following sections.

## 2. Browse

| # | Step | Expected |
|---|---|---|
| 2.1 | Open the root and the nested folders. | All files and folders are listed with sizes and modification times; folder sizes are the total of their content. |
| 2.2 | Open the file with spaces and non-ASCII characters. | Listed and opened with the right name. |
| 2.3 | Change a file three levels deep from another device, then refresh the root in the app and go down to the file. | The app shows the new size and time (directory ETags changed up to the root). |
| 2.4 | Look at the actions offered for files and folders. | No sharing, no versions, no comments, no trash bin. Missing thumbnails are fine (previews are out of scope). The apps keep some entries regardless of the capabilities: Android's file details have a Sharing tab (it says sharing is not possible) and a comment field, iOS shows an empty trash bin. |
| 2.5 | Account or settings screen. | Display name and storage usage are shown (quota is "unlimited" with the free space of the server). |
| 2.6 | Open the folder with 5,000 files over mobile data. | Listed within a few seconds. Note the time and the response size in the proxy's access log: iOS asks for gzip and gets under 50 bytes per entry. |
| 2.7 | iOS: open the Media tab and Recent. Android: open Media, Recent and Favorites. | Known limitations for v1 (no `SEARCH`): empty or cached content only. Note what is shown. |
| 2.8 | Type a file name into the search box. | Known limitation for v1 (no unified search): only matches already on the phone; iOS shows an error banner. |
| 2.9 | iOS: add the Files widget to the home screen. Android: browse, open and save a file through the system file picker (another app's "Open" dialog). iOS: the same in the Files app. | The widget stays empty (no `SEARCH`, known limitation). The file picker and the Files app list folders, open files and save changes back. |
| 2.10 | Open the file with the decomposed name. | Listed and opened with the right name. |

## 3. Upload

| # | Step | Expected |
|---|---|---|
| 3.1 | Upload a small file and a photo into a subfolder. | Uploaded; visible on another device with the same content. |
| 3.2 | Upload the file larger than 50 MiB (on iOS larger than 100 MB: Nextcloud iOS uploads smaller files with one `PUT` and uses 100 MB chunks). | Uploaded in chunks: the server log shows `MKCOL`, several `PUT` and one `MOVE .../.file` under `/remote.php/dav/uploads/<user>/`. The content matches the original (compare checksums) and keeps its modification time. |
| 3.3 | Start another large upload and switch on airplane mode halfway; switch it off again. | The upload resumes or restarts and finishes; the file is complete. A `PROPFIND` on the upload session in the server log shows the app listing the chunks it already sent. |
| 3.4 | Upload a file with the same name as an existing one and choose "replace". | The file is replaced; its file id (shown as `oc:fileid` in a PROPFIND) stays the same. |
| 3.5 | Optional: enable automatic photo upload and take a photo. | The photo is uploaded into the configured folder. |
| 3.6 | Android: enable automatic upload for a folder that already contains a video uploaded before, then reinstall the app or choose "upload existing files". | No conflict for the video: the app recognizes it by size, modification and creation time. Photos can still be reported as conflicts, because the server does not report image dimensions. |
| 3.7 | Upload a photo named `IMG_0001.JPG` from each app. | The name keeps its upper-case extension on the server. |

## 4. Download

| # | Step | Expected |
|---|---|---|
| 4.1 | Open a text file, a photo and the large file. | They open with the right content. |
| 4.2 | Make a file available offline, change it on another device, refresh. (Android 35 has no offline switch for files, only "Sync" for folders; there, download the file, change it and open it again.) | The app downloads the new version. |
| 4.3 | Play the MP4 and the MP3 without downloading them first. | Known limitation for v1 (no `direct` endpoint): the player shows an error. After downloading, they play. |
| 4.4 | iOS: make a folder with files and a subfolder available offline, then go offline and open the files. | The files directly in the folder were downloaded (as on Nextcloud, the app's `Depth: infinity` listing returns one level). |

## 5. Favorites

| # | Step | Expected |
|---|---|---|
| 5.1 | Mark a file deep in the tree and a folder as favorites. | The star is set; it is still set after a refresh and on another device. |
| 5.2 | Open the Favorites view. | iOS: both favorites are listed; the server log shows `REPORT` with status `207`. Android 35 lists favorites with `SEARCH`, which is not part of v1: it sends `OPTIONS /remote.php/dav` (404), shows only the favorites it has cached and the message "Unable to fetch sharees". |
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
grep -E 'status=(404|405|429|501|503)' /path/to/gono-cloud.log | grep -o 'method=[A-Z]* target=[^ ]*' | sort | uniq -c
```

`404` for files that were just deleted or moved is normal. Note OCS endpoints
(`/ocs/v2.php/...`), `SEARCH`, `REPORT` and anything under `/index.php/` that is not Login Flow.
A `401` for a device whose app password was not revoked is a bug: the iOS app deletes the
account after a `401`.

## Results

### 2026-11-10, server 1.0.0

Server: `gono-cloud` 1.0.0 (release dry run of 4fc62b0) installed with `install.sh` on Debian 12
behind nginx 1.22.1, Let's Encrypt certificate for an `ipssl.cc` name; upgraded to each fix
below during the test. Tester: the maintainer, partly through an Android emulator and an iOS
simulator.

Devices:

- Android: Nextcloud Android 35.0.2 from the store on a phone, and the same release
  (`nextcloud-350000290.apk`) on an Android 15 emulator.
- iOS: Nextcloud iOS 35.2.2 built from the `35.2.2` tag for the iPhone 17 simulator (iOS 27.2).
  The simulator has no airplane mode, so 3.3 was not run on iOS.

Fixed during the test, each with tests:

- `e7e589d`: Android refused the server at 1.1: its anonymous `HEAD /remote.php/dav` got 404;
  the DAV root now answers 401 with a Basic challenge.
- `c975baa`: iOS never finished Login Flow v2: it polls with the token in the query and got 415.
- `ffad48a`: iOS showed every folder as empty: it reads multistatus entries only under the
  prefix `d:`, dav-server wrote `D:`.
- `2f4e2b8`: every iOS upload failed with 400: `X-OC-MTime`/`X-OC-CTime` with fractions of a
  second.

| Section | Android 35.0.2 | iOS 35.2.2 |
|---|---|---|
| 1. Add the account | Pass (1.1 after `e7e589d`) | Pass for 1.1, 1.2, 1.4, 1.5, 1.6 (after `c975baa`); 1.8: the app leaves its app password (client behavior); 1.3 and 1.7 not run (same server pages as on Android) |
| 2. Browse | Pass; notes on 2.4 | Pass (after `ffad48a`); notes on 2.4 |
| 3. Upload | Pass 3.1 to 3.4: 878 MB in 10 MB chunks, resume after a network cut lists the uploaded chunks with `PROPFIND` and continues, replace keeps the file id; 3.5 not run | Pass 3.1, 3.2 (220 MB in three 100 MB chunks, checksum and modification time kept), 3.4 (after `2f4e2b8`); 3.3 and 3.5 not run |
| 4. Download | Pass (4.2 as a re-download on open) | Pass ("Set available offline" file re-downloaded on refresh) |
| 5. Favorites | 5.1, 5.3, 5.4 pass; 5.2 shows only cached favorites and "Unable to fetch sharees" (needs `SEARCH`) | Pass (`REPORT` 207); the list updates after a refresh |
| 6. Rename and move | Pass, including the case-only rename | Pass, including the case-only rename |
| 7. Delete | Pass, with a confirmation, no restore offered | Pass; deletes without asking, and the sidebar's trash bin claims deleted files can be restored |
| Failed requests from the log | See `docs/v1-scope.md`, open questions: notifications, user_status, activity, shares, avatar, preview, Albums, `OPTIONS /remote.php/dav` | dashboard widgets, directEditing, notifications push, avatar, preview, trash bin |

Neither app connected to notify_push (`/push/ws`); the desktop client uses it.
