#!/bin/sh
# Gono Cloud server installer for Linux (systemd) and macOS (launchd).
#
# Installs or upgrades a release: takes the release archive for this machine (downloaded from
# GitHub, or a local file), verifies it against SHA256SUMS, installs the binary, creates the
# service user and the directories, writes a configuration and runs `gono-cloud init` on a
# fresh install, and installs and (re)starts the service.
#
# It never overwrites an existing configuration, database or data directory. Before an upgrade
# it stops the service and copies the database to a backups/ directory next to it.
# `--uninstall` removes the service and the binary and keeps the configuration, the data and
# the service user.
#
# Run `install.sh --help` for the options; docs/deployment.md describes the whole setup.

set -eu
umask 022

# The release this copy installs by default. The release workflow fills it in for the copy it
# attaches to a release; the copy in the repository needs --version.
DEFAULT_VERSION=""
REPO="gonolab/cloud.server"
# Oldest GNU C library the Linux release binaries run on (see .github/workflows/release.yml).
MIN_GLIBC_MINOR=28

SERVICE_NAME="gono-cloud"
LAUNCHD_LABEL="cloud.gono.server"

usage() {
	cat <<'EOF'
Install, upgrade or uninstall the Gono Cloud server (Linux with systemd, or macOS).

Usage:
  sudo sh install.sh [--version VERSION] --base-url URL [options]   fresh install
  sudo sh install.sh [--version VERSION] [options]                  upgrade
  sudo sh install.sh --uninstall

Release:
  --version VERSION       Release to install, for example 1.0.0. Defaults to the release this
                          script was downloaded from.
  --archive FILE          Install this release archive instead of downloading one. It is
                          verified against SHA256SUMS next to it (or --checksums).
  --checksums FILE        SHA256SUMS file for --archive.
  --repo OWNER/NAME       GitHub repository to download from (default: gonolab/cloud.server).

Fresh install (ignored when a configuration exists):
  --base-url URL          Public origin of the server, for example https://cloud.example.com.
                          Required.
  --admin NAME            Username of the first admin account (default: admin).
  --admin-password-stdin  Read the admin's web login password from the first line of standard
                          input instead of prompting on the terminal.
  --data-dir DIR          Directory for the users' files (default: <state dir>/data). It must
                          not exist yet or be empty.

Other:
  --no-start              Install or upgrade, but do not start the service.
  --uninstall             Stop and remove the service and the binary. The configuration, the
                          database, the files, the logs and the service user are kept.
  -h, --help              Show this help.

Paths (Linux / macOS):
  binary         /usr/local/bin/gono-cloud
  configuration  /etc/gono-cloud/config.toml   /usr/local/etc/gono-cloud/config.toml
  state          /var/lib/gono-cloud           /usr/local/var/gono-cloud
  logs           journalctl -u gono-cloud      /usr/local/var/log/gono-cloud/
  service user   gono-cloud                    _gono-cloud
EOF
}

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# ---------------------------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------------------------

VERSION=$DEFAULT_VERSION
ARCHIVE=""
CHECKSUMS=""
BASE_URL=""
ADMIN="admin"
PASSWORD_STDIN=0
DATA_DIR=""
START=1
ACTION=install

need_value() {
	[ $# -ge 2 ] || die "$1 needs a value (see --help)"
}

while [ $# -gt 0 ]; do
	case $1 in
	--version)
		need_value "$@"
		VERSION=$2
		shift 2
		;;
	--archive)
		need_value "$@"
		ARCHIVE=$2
		shift 2
		;;
	--checksums)
		need_value "$@"
		CHECKSUMS=$2
		shift 2
		;;
	--repo)
		need_value "$@"
		REPO=$2
		shift 2
		;;
	--base-url)
		need_value "$@"
		BASE_URL=$2
		shift 2
		;;
	--admin)
		need_value "$@"
		ADMIN=$2
		shift 2
		;;
	--admin-password-stdin)
		PASSWORD_STDIN=1
		shift
		;;
	--data-dir)
		need_value "$@"
		DATA_DIR=$2
		shift 2
		;;
	--no-start)
		START=0
		shift
		;;
	--uninstall)
		ACTION=uninstall
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
done

# Accept 1.0.0, v1.0.0 and server-v1.0.0.
VERSION=${VERSION#server-}
VERSION=${VERSION#v}

# ---------------------------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------------------------

detect_platform() {
	case $(uname -s) in
	Linux) OS=linux ;;
	Darwin) OS=macos ;;
	*) die "unsupported operating system $(uname -s); Linux with systemd and macOS are supported" ;;
	esac

	ARCH=$(uname -m)
	# A shell running under Rosetta reports x86_64 on Apple silicon.
	if [ "$OS" = macos ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
		ARCH=arm64
	fi
	case $ARCH in
	x86_64 | amd64) ARCH=x86_64 ;;
	aarch64 | arm64) ARCH=aarch64 ;;
	*) die "unsupported CPU architecture $ARCH; release builds exist for x86_64 and aarch64" ;;
	esac

	BIN=/usr/local/bin/gono-cloud
	if [ "$OS" = linux ]; then
		TARGET=$ARCH-unknown-linux-gnu
		CONFIG_DIR=/etc/gono-cloud
		STATE_DIR=/var/lib/gono-cloud
		LOG_DIR=""
		SERVICE_USER=gono-cloud
		ROOT_GROUP=root
		UNIT=/etc/systemd/system/$SERVICE_NAME.service
		DROPIN_DIR=/etc/systemd/system/$SERVICE_NAME.service.d
		DROPIN=$DROPIN_DIR/10-install-data-dir.conf
	else
		TARGET=$ARCH-apple-darwin
		CONFIG_DIR=/usr/local/etc/gono-cloud
		STATE_DIR=/usr/local/var/gono-cloud
		LOG_DIR=/usr/local/var/log/gono-cloud
		SERVICE_USER=_gono-cloud
		ROOT_GROUP=wheel
		PLIST=/Library/LaunchDaemons/$LAUNCHD_LABEL.plist
	fi
	SERVICE_GROUP=$SERVICE_USER
	CONFIG_FILE=$CONFIG_DIR/config.toml
}

check_glibc() {
	glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
	case $glibc in
	"glibc "*) glibc=${glibc#glibc } ;;
	*) die "the release binaries need the GNU C library (glibc 2.$MIN_GLIBC_MINOR or newer), which this system does not use; build from source instead" ;;
	esac
	glibc_major=${glibc%%.*}
	glibc_minor=${glibc#*.}
	glibc_minor=${glibc_minor%%.*}
	if [ "$glibc_major" -lt 2 ] || { [ "$glibc_major" -eq 2 ] && [ "$glibc_minor" -lt "$MIN_GLIBC_MINOR" ]; }; then
		die "the release binaries need glibc 2.$MIN_GLIBC_MINOR or newer; this system has $glibc"
	fi
}

need_command() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is needed but not installed"
}

preflight() {
	[ "$(id -u)" = 0 ] || die "run the installer as root, for example: sudo sh $0 ..."
	if [ "$OS" = linux ]; then
		[ -d /run/systemd/system ] || die "systemd is not running; the installer sets the server up as a systemd service"
		for command in systemctl useradd groupadd getent tar gzip; do
			need_command "$command"
		done
		[ "$ACTION" = uninstall ] || check_glibc
	else
		for command in launchctl dscl tar sudo; do
			need_command "$command"
		done
	fi
}

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

# Rejects values that cannot be written into the configuration or a unit file verbatim.
check_plain() {
	case $2 in
	*[[:space:]\"\\\|\&\']*) die "$1 must not contain spaces, quotes, backslashes, '|' or '&': $2" ;;
	esac
}

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$2" "$1"
	else
		die "curl or wget is needed to download the release"
	fi
}

http_ok() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsS -o /dev/null --max-time 5 "$1" 2>/dev/null
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O /dev/null --timeout=5 "$1" 2>/dev/null
	else
		return 1
	fi
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	else
		die "sha256sum or shasum is needed to verify the release"
	fi
}

# Runs a command as the service user, from the state directory, with the service's umask.
as_service_user() {
	if [ "$OS" = linux ] && command -v runuser >/dev/null 2>&1; then
		(cd "$STATE_DIR" && umask 027 && runuser -u "$SERVICE_USER" -- "$@")
	else
		need_command sudo
		(cd "$STATE_DIR" && umask 027 && sudo -u "$SERVICE_USER" -- "$@")
	fi
}

# Prints one effective setting (`server.bind`, `db.path`, ...) of a configuration file, as
# reported by `gono-cloud config check`.
setting() {
	"$1" --config "$2" config check | awk -v key="$3" '$1 == key { sub(/^[ \t]*[^ \t]+[ \t]+/, ""); print; exit }'
}

# ---------------------------------------------------------------------------------------------
# Release archive
# ---------------------------------------------------------------------------------------------

# Leaves the verified, extracted release in $PAYLOAD and its version in $NEW_VERSION.
obtain_release() {
	if [ -n "$ARCHIVE" ]; then
		[ -f "$ARCHIVE" ] || die "archive $ARCHIVE not found"
		archive=$ARCHIVE
		[ -n "$CHECKSUMS" ] || CHECKSUMS=$(dirname "$ARCHIVE")/SHA256SUMS
		[ -f "$CHECKSUMS" ] || die "checksum file $CHECKSUMS not found; pass --checksums"
		checksums=$CHECKSUMS
	else
		[ -n "$VERSION" ] || die "pass the release to install with --version, for example --version 1.0.0"
		name=gono-cloud-$VERSION-$TARGET.tar.gz
		base=https://github.com/$REPO/releases/download/server-v$VERSION
		archive=$WORK/$name
		checksums=$WORK/SHA256SUMS
		log "Downloading $base/$name"
		fetch "$base/SHA256SUMS" "$checksums" || die "cannot download $base/SHA256SUMS; does release server-v$VERSION exist?"
		fetch "$base/$name" "$archive" || die "cannot download $base/$name"
	fi

	name=$(basename "$archive")
	case $name in
	gono-cloud-*-"$TARGET".tar.gz) ;;
	*) die "$name is not a Gono Cloud release archive for this machine ($TARGET)" ;;
	esac
	expected=$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1; exit }' "$checksums")
	[ -n "$expected" ] || die "$name is not listed in $checksums"
	actual=$(sha256_of "$archive")
	[ "$expected" = "$actual" ] || die "checksum mismatch for $name: expected $expected, got $actual"
	log "Verified $name (sha256 $actual)"

	mkdir "$WORK/release"
	tar -xzf "$archive" -C "$WORK/release"
	PAYLOAD=$WORK/release/${name%.tar.gz}
	[ -f "$PAYLOAD/gono-cloud" ] || die "$name does not contain ${name%.tar.gz}/gono-cloud"
	NEW_VERSION=$("$PAYLOAD/gono-cloud" --version 2>/dev/null) ||
		die "the binary in $name does not run on this machine"
	NEW_VERSION=${NEW_VERSION#gono-cloud }
	if [ -n "$VERSION" ] && [ "$VERSION" != "$NEW_VERSION" ]; then
		die "$name contains version $NEW_VERSION, not $VERSION"
	fi
}

# ---------------------------------------------------------------------------------------------
# Service user and directories
# ---------------------------------------------------------------------------------------------

ensure_service_user() {
	if [ "$OS" = linux ]; then
		if ! getent group "$SERVICE_GROUP" >/dev/null; then
			log "Creating group $SERVICE_GROUP"
			groupadd --system "$SERVICE_GROUP"
		fi
		if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
			log "Creating user $SERVICE_USER"
			nologin=/usr/sbin/nologin
			[ -x "$nologin" ] || nologin=/sbin/nologin
			[ -x "$nologin" ] || nologin=/bin/false
			useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" --no-create-home \
				--shell "$nologin" --comment "Gono Cloud" "$SERVICE_USER"
		fi
		return
	fi

	# macOS: a hidden system user and group with the same free id below 500.
	if dscl . -read "/Users/$SERVICE_USER" >/dev/null 2>&1; then
		return
	fi
	used=$(
		dscl . -list /Users UniqueID | awk '{ print $2 }'
		dscl . -list /Groups PrimaryGroupID | awk '{ print $2 }'
	)
	id=450
	while [ "$id" -gt 300 ]; do
		if ! printf '%s\n' "$used" | grep -qx "$id"; then
			break
		fi
		id=$((id - 1))
	done
	[ "$id" -gt 300 ] || die "no free user id between 301 and 450 for $SERVICE_USER"
	log "Creating user and group $SERVICE_USER (id $id)"
	if ! dscl . -read "/Groups/$SERVICE_GROUP" >/dev/null 2>&1; then
		dscl . -create "/Groups/$SERVICE_GROUP"
		dscl . -create "/Groups/$SERVICE_GROUP" PrimaryGroupID "$id"
		dscl . -create "/Groups/$SERVICE_GROUP" RealName "Gono Cloud"
		dscl . -create "/Groups/$SERVICE_GROUP" Password '*'
	fi
	gid=$(dscl . -read "/Groups/$SERVICE_GROUP" PrimaryGroupID | awk '{ print $2 }')
	dscl . -create "/Users/$SERVICE_USER"
	dscl . -create "/Users/$SERVICE_USER" UniqueID "$id"
	dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$gid"
	dscl . -create "/Users/$SERVICE_USER" RealName "Gono Cloud"
	dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
	dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
	dscl . -create "/Users/$SERVICE_USER" Password '*'
	dscl . -create "/Users/$SERVICE_USER" IsHidden 1
	dscacheutil -flushcache 2>/dev/null || true
}

# Creates a directory with the given mode and owner, leaving existing directories alone.
ensure_dir() {
	[ -d "$1" ] || install -d -m "$2" -o "$3" -g "$4" "$1"
}

# ---------------------------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------------------------

service_loaded() {
	if [ "$OS" = linux ]; then
		systemctl is-active --quiet "$SERVICE_NAME.service"
	else
		launchctl print "system/$LAUNCHD_LABEL" >/dev/null 2>&1
	fi
}

stop_service() {
	if service_loaded; then
		log "Stopping the service"
		if [ "$OS" = linux ]; then
			systemctl stop "$SERVICE_NAME.service"
		else
			launchctl bootout "system/$LAUNCHD_LABEL" || true
		fi
	fi
}

install_service() {
	if [ "$OS" = linux ]; then
		install -m 0644 -o root -g root "$PAYLOAD/systemd/$SERVICE_NAME.service" "$UNIT"
		systemctl daemon-reload
		systemctl enable --quiet "$SERVICE_NAME.service"
		log "Installed $UNIT"
	else
		# launchd reads the file again only when the job is loaded, so unload it first.
		if launchctl print "system/$LAUNCHD_LABEL" >/dev/null 2>&1; then
			launchctl bootout "system/$LAUNCHD_LABEL" || true
		fi
		install -m 0644 -o root -g wheel "$PAYLOAD/launchd/$LAUNCHD_LABEL.plist" "$PLIST"
		log "Installed $PLIST"
	fi
}

start_service() {
	log "Starting the service"
	if [ "$OS" = linux ]; then
		systemctl restart "$SERVICE_NAME.service"
	else
		launchctl bootstrap system "$PLIST"
	fi
}

wait_until_healthy() {
	bind=$(setting "$BIN" "$CONFIG_FILE" server.bind)
	[ -n "$bind" ] || bind=127.0.0.1:16102
	case $bind in
	0.0.0.0:*) bind=127.0.0.1:${bind#*:} ;;
	"[::]:"*) bind="[::1]:${bind##*:}" ;;
	esac
	attempt=0
	while [ "$attempt" -lt 30 ]; do
		if http_ok "http://$bind/healthz"; then
			log "The server answers on http://$bind"
			return 0
		fi
		sleep 1
		attempt=$((attempt + 1))
	done
	if [ "$OS" = linux ]; then
		warn "the server did not answer on http://$bind/healthz within 30 seconds; see: journalctl -u $SERVICE_NAME -n 50"
	else
		warn "the server did not answer on http://$bind/healthz within 30 seconds; see: $LOG_DIR/gono-cloud.log"
	fi
	return 1
}

# ---------------------------------------------------------------------------------------------
# Install and upgrade
# ---------------------------------------------------------------------------------------------

# Copies the database of a stopped server to backups/<time>-<version>/ next to it.
backup_database() {
	db=$1
	old_version=$2
	[ -f "$db" ] || return 0
	backups=$(dirname "$db")/backups
	target=$backups/$(date -u +%Y%m%dT%H%M%SZ)-$old_version
	ensure_dir "$backups" 0750 "$SERVICE_USER" "$SERVICE_GROUP"
	install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$target"
	# The write-ahead log holds committed changes until they are checkpointed: copy it too.
	for file in "$db" "$db-wal"; do
		if [ -f "$file" ]; then
			cp -p "$file" "$target/"
		fi
	done
	log "Backed the database up to $target"
}

# Writes the configuration of a fresh install to $WORK/config.toml and validates it.
prepare_config() {
	db_path=$1
	data_dir=$2
	config=$WORK/config.toml
	{
		printf '# Written by install.sh from config.example.toml of Gono Cloud %s on %s.\n' \
			"$NEW_VERSION" "$(date -u +%Y-%m-%d)"
		printf '# Validate changes with: gono-cloud --config %s config check\n\n' "$CONFIG_FILE"
		sed -e "s|^base_url = .*|base_url = \"$BASE_URL\"|" \
			-e "s|^data_dir = .*|data_dir = \"$data_dir\"|" \
			-e "s|^path = \"gono-cloud.db\"|path = \"$db_path\"|" \
			"$PAYLOAD/config.example.toml"
	} >"$config"
	for expected in "base_url = \"$BASE_URL\"" "data_dir = \"$data_dir\"" "path = \"$db_path\""; do
		grep -qxF "$expected" "$config" || die "cannot adapt config.example.toml ($expected missing)"
	done
	"$PAYLOAD/gono-cloud" --config "$config" config check >/dev/null ||
		die "the configuration written for --base-url $BASE_URL is invalid"
}

install_release() {
	WORK=$(mktemp -d)
	trap 'rm -rf "$WORK"' EXIT
	trap 'exit 130' INT TERM

	fresh_config=0
	[ -e "$CONFIG_FILE" ] || fresh_config=1
	if [ "$fresh_config" = 1 ]; then
		[ -n "$BASE_URL" ] || die "no configuration at $CONFIG_FILE yet: pass --base-url for a fresh install"
		case $BASE_URL in
		http://* | https://*) ;;
		*) die "--base-url must start with https:// (or http:// for a test setup)" ;;
		esac
		check_plain --base-url "$BASE_URL"
		[ -n "$DATA_DIR" ] || DATA_DIR=$STATE_DIR/data
		case $DATA_DIR in
		/*) ;;
		*) die "--data-dir must be an absolute path" ;;
		esac
		check_plain --data-dir "$DATA_DIR"
		if [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR")" ]; then
			die "$DATA_DIR is not empty; choose an empty or new directory with --data-dir"
		fi
		db_path=$STATE_DIR/gono-cloud.db
		if [ -e "$db_path" ]; then
			die "found a database at $db_path but no configuration at $CONFIG_FILE; restore the configuration or move the database away"
		fi
		needs_init=1
	else
		[ -z "$BASE_URL" ] || warn "--base-url is ignored: $CONFIG_FILE exists"
		[ -z "$DATA_DIR" ] || warn "--data-dir is ignored: $CONFIG_FILE exists"
		needs_init=0
	fi

	obtain_release

	if [ "$fresh_config" = 1 ]; then
		prepare_config "$db_path" "$DATA_DIR"
	else
		# The new binary must accept the existing configuration before anything changes.
		if ! "$PAYLOAD/gono-cloud" --config "$CONFIG_FILE" config check >/dev/null; then
			die "Gono Cloud $NEW_VERSION does not accept $CONFIG_FILE; fix it and run the installer again"
		fi
		db_path=$(setting "$PAYLOAD/gono-cloud" "$CONFIG_FILE" db.path)
		# A configuration without a database: an earlier install stopped before `init`.
		[ -e "$db_path" ] || needs_init=1
	fi
	if [ "$needs_init" = 1 ] && [ "$PASSWORD_STDIN" = 0 ] && ! [ -t 0 ]; then
		die "a fresh install creates the first admin account: run the installer from a terminal, or pass --admin-password-stdin"
	fi

	ensure_service_user
	ensure_dir "$CONFIG_DIR" 0750 root "$SERVICE_GROUP"
	ensure_dir "$STATE_DIR" 0750 "$SERVICE_USER" "$SERVICE_GROUP"
	if [ -n "$LOG_DIR" ]; then
		ensure_dir "$LOG_DIR" 0750 "$SERVICE_USER" "$SERVICE_GROUP"
		log_file=$LOG_DIR/gono-cloud.log
		if ! [ -e "$log_file" ]; then
			: >"$log_file"
			chown "$SERVICE_USER:$SERVICE_GROUP" "$log_file"
			chmod 0640 "$log_file"
		fi
	fi

	old_version=""
	if [ -x "$BIN" ]; then
		old_version=$("$BIN" --version 2>/dev/null) || old_version="gono-cloud unknown"
		old_version=${old_version#gono-cloud }
	fi
	if [ "$needs_init" = 0 ]; then
		stop_service
		backup_database "$db_path" "${old_version:-unknown}"
	fi

	# Replace the binary atomically: a running server keeps its old copy until it restarts.
	mkdir -p "$(dirname "$BIN")"
	install -m 0755 -o root -g "$ROOT_GROUP" "$PAYLOAD/gono-cloud" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	if [ -n "$old_version" ]; then
		log "Replaced gono-cloud $old_version with $NEW_VERSION at $BIN"
	else
		log "Installed gono-cloud $NEW_VERSION at $BIN"
	fi

	if [ "$fresh_config" = 1 ]; then
		if [ "$DATA_DIR" != "$STATE_DIR/data" ]; then
			mkdir -p "$(dirname "$DATA_DIR")"
			ensure_dir "$DATA_DIR" 0750 "$SERVICE_USER" "$SERVICE_GROUP"
		fi
		install -m 0640 -o root -g "$SERVICE_GROUP" "$WORK/config.toml" "$CONFIG_FILE"
		log "Wrote $CONFIG_FILE"
	fi
	if [ "$OS" = linux ] && [ "$fresh_config" = 1 ]; then
		case $DATA_DIR in
		"$STATE_DIR"/*) ;;
		*)
			# The unit only lets the server write /var/lib/gono-cloud.
			mkdir -p "$DROPIN_DIR"
			printf '# Written by install.sh: the data directory chosen at install time.\n[Service]\nReadWritePaths=%s\n' \
				"$DATA_DIR" >"$DROPIN"
			log "Wrote $DROPIN"
			;;
		esac
	fi

	if [ "$needs_init" = 1 ]; then
		log "Creating the database and the admin account $ADMIN"
		if [ "$PASSWORD_STDIN" = 1 ]; then
			as_service_user "$BIN" --config "$CONFIG_FILE" init --admin "$ADMIN" --password-stdin
		else
			as_service_user "$BIN" --config "$CONFIG_FILE" init --admin "$ADMIN"
		fi
	fi

	install_service
	healthy=1
	if [ "$START" = 1 ]; then
		start_service
		wait_until_healthy || healthy=0
	fi
	summary
	[ "$healthy" = 1 ] || exit 1
}

summary() {
	if [ "$OS" = linux ]; then
		status="systemctl status $SERVICE_NAME"
		logs="journalctl -u $SERVICE_NAME"
	else
		status="sudo launchctl print system/$LAUNCHD_LABEL"
		logs="$LOG_DIR/gono-cloud.log"
	fi
	cat <<EOF

Gono Cloud $NEW_VERSION is installed.

  binary         $BIN
  configuration  $CONFIG_FILE
  state          $STATE_DIR
  service        $status
  logs           $logs

Manage accounts as the service user, for example:
  sudo -u $SERVICE_USER $BIN --config $CONFIG_FILE user list

Put a reverse proxy with HTTPS in front of the server before clients connect; see
docs/reverse-proxy.md and docs/deployment.md.
EOF
	if [ "$START" = 0 ]; then
		printf '\nThe service was not started (--no-start).\n'
	fi
}

# ---------------------------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------------------------

uninstall() {
	if [ "$OS" = linux ]; then
		if [ -f "$UNIT" ]; then
			systemctl disable --now "$SERVICE_NAME.service" || true
			rm -f "$UNIT" "$DROPIN"
			rmdir "$DROPIN_DIR" 2>/dev/null || true
			systemctl daemon-reload
			log "Removed the systemd service"
		fi
	else
		if launchctl print "system/$LAUNCHD_LABEL" >/dev/null 2>&1; then
			launchctl bootout "system/$LAUNCHD_LABEL" || true
		fi
		if [ -f "$PLIST" ]; then
			rm -f "$PLIST"
			log "Removed the launchd job"
		fi
	fi
	if [ -f "$BIN" ]; then
		rm -f "$BIN"
		log "Removed $BIN"
	fi

	cat <<EOF

Gono Cloud is uninstalled. Kept, so that nothing is lost by accident:

  configuration  $CONFIG_DIR
  state          $STATE_DIR (database, backups and, by default, the files)
EOF
	if [ -n "$LOG_DIR" ]; then
		printf '  logs           %s\n' "$LOG_DIR"
	fi
	printf '  service user   %s\n\n' "$SERVICE_USER"
	printf '%s\n' 'Remove them yourself once you no longer need them. A data directory chosen with' \
		'--data-dir is named in the configuration (storage.data_dir).'
	if [ "$OS" = linux ]; then
		printf '  sudo rm -r %s %s\n  sudo userdel %s\n' "$CONFIG_DIR" "$STATE_DIR" "$SERVICE_USER"
	else
		printf '  sudo rm -r %s %s %s\n' "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
		printf '  sudo dscl . -delete /Users/%s\n  sudo dscl . -delete /Groups/%s\n' \
			"$SERVICE_USER" "$SERVICE_GROUP"
	fi
}

# ---------------------------------------------------------------------------------------------

detect_platform
preflight
case $ACTION in
install) install_release ;;
uninstall) uninstall ;;
esac
