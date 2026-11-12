# Deploying Gono Cloud

This guide installs the Gono Cloud server as a system service, puts it behind a reverse proxy
and covers the day-to-day operation: accounts, logs, upgrades, backups, `rescan` and
uninstalling. The reverse proxy itself is described in [reverse-proxy.md](reverse-proxy.md).

Commands below use the Linux paths. On macOS, replace them as listed in
[Paths](#paths) (for example `_gono-cloud` instead of `gono-cloud` and
`/usr/local/etc/gono-cloud/config.toml` instead of `/etc/gono-cloud/config.toml`).

## Requirements

| | |
|---|---|
| **Linux** | x86_64 or aarch64, any distribution: the binary is statically linked (musl) and needs no C library, so glibc-based and musl-based systems (Alpine) work alike. The install script and the unit need systemd; systemd 247 or newer applies every hardening option of the unit, older versions ignore some of them with a warning. Without systemd, run the binary from the archive with your own service manager ([Installing by hand](#installing-by-hand)). |
| **macOS** | macOS 11 or newer, Apple silicon or Intel. |
| **Reverse proxy** | nginx or Caddy on the same host, terminating HTTPS for a domain name. Gono Cloud has no TLS of its own and listens on `127.0.0.1:16102`. |
| **Storage** | A local file system for the database and the data directory; the data directory must be a single file system. A case-sensitive file system (ext4, XFS, Btrfs, case-sensitive APFS) is recommended: on a case-insensitive one, `Report.pdf` and `report.pdf` cannot coexist. Keep the SQLite database off network file systems. |

## Installing with the install script

Every server release on the [releases page](https://github.com/gonolab/gono.cloud/releases)
has a `cloud.server.sh` that installs that release. `https://gono.dev/cloud.server.sh`
redirects to the one of the newest server release
(`https://github.com/gonolab/gono.cloud/releases/latest/download/cloud.server.sh`). Download
it, read it if you like, and run it as root with the public address of the server:

```sh
curl -fsSLo cloud.server.sh https://gono.dev/cloud.server.sh
sudo sh cloud.server.sh --base-url https://cloud.example.com
```

To install a particular release, take its script instead
(`https://github.com/gonolab/gono.cloud/releases/download/server-v1.0.0/cloud.server.sh`) or
pass `--version`. Release 1.0.0 also carries the same script under its original name,
`install.sh`.

The script:

1. downloads the archive for this machine and `SHA256SUMS` from the same release and stops if
   the checksum does not match;
2. creates the system user `gono-cloud` (no login shell, no home directory) and the
   directories;
3. installs the binary to `/usr/local/bin/gono-cloud`;
4. writes `/etc/gono-cloud/config.toml` from `config.example.toml` with your `--base-url` and
   absolute paths, and validates it;
5. runs `gono-cloud init` as the service user, which creates the database and the first admin
   account and asks for its web login password;
6. installs the systemd unit (or the launchd job on macOS), enables and starts it, and waits
   until the server answers on `http://127.0.0.1:16102/healthz`.

It never overwrites an existing configuration, database or data directory. Steps 4 and 5 only
run on a fresh install; if the script stops halfway, fix the cause and run it again.

Options for a fresh install:

| Option | Meaning |
|---|---|
| `--base-url URL` | Public origin, exactly as users type it: `https://cloud.example.com`, no path. Required. |
| `--admin NAME` | Username of the first admin account (default `admin`). |
| `--admin-password-stdin` | Read the admin's password from standard input instead of the terminal, for automated installs: `printf '%s\n' "$PASSWORD" \| sudo sh cloud.server.sh ... --admin-password-stdin`. |
| `--data-dir DIR` | Keep the users' files in `DIR` instead of `/var/lib/gono-cloud/data`. The directory must be new or empty. On Linux the script adds a systemd drop-in that lets the service write it. |
| `--no-start` | Install everything but do not start the service. |
| `--archive FILE` | Install a downloaded archive instead of downloading one (offline installs). `SHA256SUMS` must be next to it, or name it with `--checksums FILE`. |
| `--version VERSION` | Install another release than the one the script came from. |

`sh cloud.server.sh --help` lists every option.

### Verifying a download yourself

The install script checks the archive against `SHA256SUMS`. To check the release files by
hand, and that they were built by this repository's release workflow:

```sh
sha256sum --check --ignore-missing SHA256SUMS      # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
gh attestation verify gono-cloud-1.0.0-x86_64-unknown-linux-musl.tar.gz --repo gonolab/gono.cloud
```

### Paths

| | Linux | macOS |
|---|---|---|
| Binary | `/usr/local/bin/gono-cloud` | `/usr/local/bin/gono-cloud` |
| Configuration | `/etc/gono-cloud/config.toml` | `/usr/local/etc/gono-cloud/config.toml` |
| Database | `/var/lib/gono-cloud/gono-cloud.db` | `/usr/local/var/gono-cloud/gono-cloud.db` |
| Files | `/var/lib/gono-cloud/data/` | `/usr/local/var/gono-cloud/data/` |
| Database backups of upgrades | `/var/lib/gono-cloud/backups/` | `/usr/local/var/gono-cloud/backups/` |
| Logs | the journal: `journalctl -u gono-cloud` | `/usr/local/var/log/gono-cloud/gono-cloud.log` |
| Service | `/etc/systemd/system/gono-cloud.service` | `/Library/LaunchDaemons/cloud.gono.server.plist` |
| Service user and group | `gono-cloud` | `_gono-cloud` (hidden) |

The configuration is owned by root and readable by the service group (`0640`); the service only
reads it. The database and the files belong to the service user and are not readable by other
users.

## Installing by hand

The release archive contains everything the script uses. On Linux:

```sh
tar -xzf gono-cloud-1.0.0-x86_64-unknown-linux-musl.tar.gz
cd gono-cloud-1.0.0-x86_64-unknown-linux-musl

sudo useradd --system --user-group --home-dir /var/lib/gono-cloud --no-create-home \
  --shell /usr/sbin/nologin gono-cloud
sudo install -m 0755 gono-cloud /usr/local/bin/gono-cloud
sudo install -d -m 0750 -o root -g gono-cloud /etc/gono-cloud
sudo install -d -m 0750 -o gono-cloud -g gono-cloud /var/lib/gono-cloud

# Set base_url, and absolute paths: data_dir = "/var/lib/gono-cloud/data",
# path = "/var/lib/gono-cloud/gono-cloud.db".
sudo install -m 0640 -o root -g gono-cloud config.example.toml /etc/gono-cloud/config.toml
sudoedit /etc/gono-cloud/config.toml
sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml config check

sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml init --admin admin

sudo install -m 0644 systemd/gono-cloud.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gono-cloud
```

The unit expects exactly these paths. To use others, override them in a drop-in (see
[Service management](#service-management)) rather than editing the unit, which upgrades replace.

On a system without systemd (Alpine with OpenRC, a container), skip the unit: create the user,
directories and configuration the same way (on Alpine:
`addgroup -S gono-cloud && adduser -S -D -H -G gono-cloud gono-cloud`) and let the
service manager run `gono-cloud --config /etc/gono-cloud/config.toml serve` as `gono-cloud`. It
logs to standard output and stops cleanly on SIGTERM within 30 seconds.

## The first admin account

`gono-cloud init` creates the database, the data directory layout and one account with the
admin flag. Its web login password (at least 8 characters) is used in the browser only: for the
web file UI, the Login Flow consent page and the web admin UI. `init` refuses to run against a
database that already has accounts.

To connect the first device, enter the server address (`https://cloud.example.com`) in a
Nextcloud client. The client opens the browser, you sign in with the web login password and
approve the device, and the server creates an app password for that device. Each device gets its
own app password, which you can revoke on its own.

## The browser

Opening `https://cloud.example.com/` in a browser leads to the **web file UI** at
`/apps/files/`. Every user signs in there with their web login password and can browse, search,
preview, upload (drag and drop, folders, large files in resumable chunks), download (folders as
`.zip`), create folders, rename, move, delete and mark favorites. The **account page**
(`/apps/account/`) lets users change their display name and web login password and create or
revoke their own app passwords, for example for Finder, Windows Explorer or rclone. The pages
work without JavaScript; with it, uploads and the theme switch need no page reloads. They follow
the browser's language (English or Chinese) and its light or dark mode.

Changes made in the browser are the same WebDAV operations the clients use, so the apps see
them at once (notify_push included). Deleting is permanent: there is no trash bin. Files are
never opened as web pages: downloads are attachments, and only images, video, audio and text are
previewed. App passwords cannot sign in to the browser, and the browser session cannot be used
for WebDAV.

The **web admin UI** at `https://cloud.example.com/gono-admin/` (`admin.path`) shows this server
and manages accounts and app passwords. Only accounts with the admin flag can sign in. Consider
limiting the path to a VPN or office network in the reverse proxy
([examples](reverse-proxy.md)).

Both are on by default. To turn one off, set `enabled = false` in the `[files_ui]` or `[admin]`
section of the configuration and restart the service.

## Managing accounts

The command line manages accounts and app passwords directly in the database. Run it as the
service user, so that every file it creates belongs to the service:

```sh
sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml user list
```

A shell alias saves typing:

```sh
alias gono='sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml'
gono user add alice --display-name "Alice Example"
gono user promote alice
gono app-password add alice --label "Alice's laptop"
```

Run as root (`sudo gono-cloud ...`), the commands refuse to touch an installation that belongs to
the service user: files they would create, such as the database's write-ahead log or a new
user's directories, would belong to root and could no longer be written by the server.

| Command | Purpose |
|---|---|
| `user add NAME [--display-name NAME] [--admin]` | Create an account; asks for its web login password. |
| `user list` | List the accounts. |
| `user set-password NAME` | Set a new web login password; ends the user's browser sessions. |
| `user set-display-name NAME DISPLAY_NAME` | Change the name clients show. |
| `user promote NAME`, `user demote NAME` | Grant or withdraw access to the admin UI. |
| `user disable NAME`, `user enable NAME` | Block or allow signing in; disabling stops the user's app passwords too. |
| `user delete NAME` | Delete the account; its files move to `data/deleted/`. |
| `app-password add NAME --label LABEL [--scope ...] [--expires-in-days N]` | Create an app password, shown once. |
| `app-password list NAME`, `app-password delete NAME ID` | List or revoke app passwords. |

At least one enabled admin always remains: disabling, demoting or deleting the last one is
refused. `gono-cloud <command> --help` explains every command and option.

## Service management

```sh
sudo systemctl status gono-cloud
sudo systemctl restart gono-cloud       # after changing the configuration
sudo systemctl stop gono-cloud
sudo systemctl disable --now gono-cloud # stop it and do not start it at boot
```

On `stop` and `restart`, systemd sends SIGTERM. The server stops accepting connections, closes
notify_push WebSockets (clients reconnect on their own) and gives running requests, such as
uploads and downloads, up to 30 seconds to finish. systemd kills it after 45 seconds.

The unit runs the server with a strict sandbox: the whole file system is read-only for it except
`/var/lib/gono-cloud`, home directories are hidden, and it has no capabilities. Changes belong in
a drop-in, which upgrades keep:

```sh
sudo systemctl edit gono-cloud
```

```ini
[Service]
# A data directory or log file outside /var/lib/gono-cloud must be writable:
ReadWritePaths=/srv/gono-cloud/data
# A more detailed log filter (see "Logs"):
Environment=GONO_CLOUD_LOG=info,gono_server_dav=debug
```

On macOS:

```sh
sudo launchctl print system/cloud.gono.server             # status
sudo launchctl kickstart -k system/cloud.gono.server      # restart
sudo launchctl bootout system/cloud.gono.server           # stop until the next boot
sudo launchctl bootstrap system /Library/LaunchDaemons/cloud.gono.server.plist  # start again
```

launchd restarts the server after a crash, but not after a clean exit, and starts it at boot.

### Changing the configuration

Edit `/etc/gono-cloud/config.toml` (`sudoedit` keeps the file's owner and mode), validate it,
then restart:

```sh
sudoedit /etc/gono-cloud/config.toml
sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml config check
sudo systemctl restart gono-cloud
```

`config check` prints the effective settings and warnings. Unknown keys are errors, so typos do
not go unnoticed.

## Reverse proxy

Clients must reach the server only through a reverse proxy that terminates HTTPS. Set it up as
described in [reverse-proxy.md](reverse-proxy.md), which has tested configurations for nginx
and Caddy. Two settings of Gono Cloud have to match the proxy:

- `server.base_url` is the public origin, exactly as users open it. The server never derives it
  from request headers.
- `server.trusted_proxies` lists the proxies whose `X-Forwarded-For` headers are believed. The
  default configuration trusts `127.0.0.1` and `::1`, which fits a proxy on the same host.

## Logs

On Linux the server logs to the journal:

```sh
journalctl -u gono-cloud -f                 # follow
journalctl -u gono-cloud --since today
```

On macOS it logs to `/usr/local/var/log/gono-cloud/gono-cloud.log`. That file is not rotated;
to empty it while the server runs:

```sh
sudo sh -c ': > /usr/local/var/log/gono-cloud/gono-cloud.log'
```

Every request is logged at level `info` with its method, path, status, duration and client
address. Credentials never are: headers are not logged, query values are dropped and Login Flow
tokens in paths are replaced by `<redacted>`.
`logging.level` sets the level of Gono Cloud's own messages (`warn` drops the request lines);
dependencies log only warnings and errors. For debugging, the `GONO_CLOUD_LOG` environment
variable replaces the whole filter, for example `GONO_CLOUD_LOG=info,sqlx=debug` (set it in a
drop-in, see above). `logging.file` writes to a file instead of standard output; under systemd
the file must be in a writable path.

## Upgrading

Read the [changelog](../crates/server/CHANGELOG.md) of the new release first. Then download its
`cloud.server.sh` and run it without `--base-url`:

```sh
curl -fsSLo cloud.server.sh https://gono.dev/cloud.server.sh   # the newest server release
sudo sh cloud.server.sh
```

To upgrade to a particular release instead, download the script from that release
(`https://github.com/gonolab/gono.cloud/releases/download/server-v<version>/cloud.server.sh`).

The script checks that the new binary accepts the existing configuration, stops the service,
copies the database to `/var/lib/gono-cloud/backups/<time>-<old version>/`, replaces the binary
and the service file and starts the service again. The server applies database migrations when
it starts. The configuration and the files are not touched, and old backups are never deleted:
remove them yourself once the new version runs well.

Downgrading is not supported once a newer version has migrated the database: an older server
refuses to start on it. To go back, install the older release without starting it, restore the
database from the backup taken before the upgrade (see [Restoring](#restoring)), and start the
service:

```sh
sudo sh cloud.server.sh --version 1.0.0 --no-start   # the cloud.server.sh of any release
# restore /var/lib/gono-cloud/backups/<time>-1.0.0/gono-cloud.db as described below
sudo systemctl start gono-cloud
```

Changes made since the upgrade are lost from the database; `rescan --all` picks up the files
uploaded in the meantime.

Without the script: stop the service, back up the database, replace `/usr/local/bin/gono-cloud`
and the unit file with the ones from the new archive, run `systemctl daemon-reload` and start
the service.

## Backup and restore

A complete backup consists of:

- the configuration, `/etc/gono-cloud/config.toml`;
- the database, `/var/lib/gono-cloud/gono-cloud.db`: accounts, app passwords, file metadata
  (ids, ETags, favorites, locks) and the instance id;
- the data directory, `/var/lib/gono-cloud/data/`: the users' files.

### The database

The database is SQLite in WAL mode: committed changes may still sit in the write-ahead log,
`gono-cloud.db-wal`, next to it. **Copying `gono-cloud.db` alone while the server runs can
produce a backup that misses recent changes or is corrupt.** Use one of these:

- **While the server runs**, with SQLite's online backup, which writes a consistent snapshot to
  a single file (needs the `sqlite3` command line tool, for example `apt install sqlite3`;
  macOS includes it):

  ```sh
  sudo -u gono-cloud mkdir -p /var/lib/gono-cloud/backups
  sudo -u gono-cloud sqlite3 /var/lib/gono-cloud/gono-cloud.db \
    ".backup '/var/lib/gono-cloud/backups/gono-cloud-$(date +%Y%m%d).db'"
  ```

  Run it as the service user, as shown: SQLite may need to create the database's shared-memory
  file, which must belong to the service user. Then copy the backup file wherever your backups
  go. `VACUUM INTO '<file>'` gives the same result in a compacted file.
- **With the server stopped**: stop the service, copy `gono-cloud.db` and, if it exists,
  `gono-cloud.db-wal` together, start the service. This is what the install script does before
  an upgrade.

### The files

Back up the data directory with any file-level tool (restic, Borg, rsync, a file system
snapshot). Files that change during the backup may be captured in an intermediate state, as
with any live file server; a file system snapshot (LVM, ZFS, Btrfs, APFS) avoids that.

Back up the database first and the files right after it. Files that change in between do not
matter: `rescan` reconciles the metadata with the files after a restore.

### Restoring

1. Stop the service: `sudo systemctl stop gono-cloud`.
2. Put back the configuration, then the data directory, owned by the service user:
   `sudo chown -R gono-cloud:gono-cloud /var/lib/gono-cloud/data`.
3. Put back the database as `/var/lib/gono-cloud/gono-cloud.db`, owned by `gono-cloud` with mode
   `0640`, and delete any `gono-cloud.db-wal` and `gono-cloud.db-shm` left next to it from the
   replaced database. A `-wal` file from the same backup (a copy taken with the server stopped)
   belongs next to it.
4. Reconcile the metadata with the restored files, as the service user:
   `sudo -u gono-cloud gono-cloud --config /etc/gono-cloud/config.toml rescan --all`.
5. Start the service: `sudo systemctl start gono-cloud`.

Clients notice changed ETags and synchronize. Devices keep their app passwords as long as the
restored database has them.

## Files changed outside Gono Cloud: rescan

The data directory belongs to the server, and clients see changes only when they go through
WebDAV. After changing files directly (over SSH, Samba, rsync, or by restoring a backup), run
`rescan` as the service user:

```sh
gono rescan alice --dry-run           # show what would change (alias from above)
gono rescan alice --path Photos/2024  # only this folder of alice's files
gono rescan --all                     # every account
```

`rescan` adds metadata for new files and folders, removes it for missing ones, gives changed
files new ETags, recomputes folder sizes and renames names that are not Unicode NFC to NFC. It
may run while the server runs; connected clients learn about the changes through notify_push
within a few seconds, others at their next poll.

## Uninstalling

```sh
sudo sh cloud.server.sh --uninstall
```

This stops and removes the service and the binary. The configuration, the database, the files,
the upgrade backups, the logs and the service user stay, so that nothing is lost by accident.
Remove them yourself when you no longer need them:

```sh
sudo rm -r /etc/gono-cloud /var/lib/gono-cloud
sudo userdel gono-cloud
```

On macOS:

```sh
sudo rm -r /usr/local/etc/gono-cloud /usr/local/var/gono-cloud /usr/local/var/log/gono-cloud
sudo dscl . -delete /Users/_gono-cloud
sudo dscl . -delete /Groups/_gono-cloud
```

A data directory chosen with `--data-dir` is wherever `storage.data_dir` in the configuration
points.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| The service does not start | `journalctl -u gono-cloud -n 50` shows why. Validate the configuration with `config check`. |
| "Request blocked" after submitting a form in the browser | The browser's origin does not match `server.base_url`; see [reverse-proxy.md](reverse-proxy.md). |
| "this command runs as root, but ... belongs to user id ..." | Run the command as the service user: `sudo -u gono-cloud gono-cloud ...`. |
| "Read-only file system" or "Permission denied" for a data directory outside `/var/lib/gono-cloud` | Allow it with `ReadWritePaths=` in a drop-in, and make it owned by `gono-cloud`. |
| Files copied into the data directory do not appear in clients | Run `rescan` for that user. |
| Clients do not get changes in real time | The proxy must pass WebSocket upgrades on `/push/ws`; see [reverse-proxy.md](reverse-proxy.md#checking-the-setup). |
