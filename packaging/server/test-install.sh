#!/bin/sh
# End-to-end test of install.sh on a throwaway machine: refused installs, a fresh install, the
# running service, WebDAV through the (sandboxed) service, the root guard of the CLI, a
# graceful stop, an upgrade and the uninstall.
#
# Usage: packaging/server/test-install.sh <install.sh> <archive> [<SHA256SUMS>]
#
# Without a SHA256SUMS file, one is written for a copy of the archive. The test installs a
# system service and creates a system user, so it only runs where CI=true (GitHub Actions sets
# it); never run it on a machine you care about. It needs sudo without a password.

set -eu

[ "${CI:-}" = true ] || {
	echo "error: $0 installs a system service and only runs in CI (CI=true)" >&2
	exit 1
}
[ $# -ge 2 ] || {
	echo "usage: $0 <install.sh> <archive> [<SHA256SUMS>]" >&2
	exit 2
}
installer=$1
archive=$2
checksums=${3:-}

PASSWORD="install test password"
BASE_URL=https://cloud.example.com
ADDR=127.0.0.1:16102
BIN=/usr/local/bin/gono-cloud

case $(uname -s) in
Linux)
	os=linux
	user=gono-cloud
	config=/etc/gono-cloud/config.toml
	state=/var/lib/gono-cloud
	;;
Darwin)
	os=macos
	user=_gono-cloud
	config=/usr/local/etc/gono-cloud/config.toml
	state=/usr/local/var/gono-cloud
	;;
*)
	echo "error: unsupported system $(uname -s)" >&2
	exit 1
	;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

step() { printf '\n### %s\n' "$*"; }

dump_logs() {
	if [ "$os" = linux ]; then
		sudo journalctl -u gono-cloud --no-pager -n 100 || true
	else
		sudo tail -n 100 /usr/local/var/log/gono-cloud/gono-cloud.log || true
	fi
}

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	dump_logs
	exit 1
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

if [ -z "$checksums" ]; then
	cp "$archive" "$work/"
	archive=$work/$(basename "$archive")
	(cd "$work" && sha256 "$(basename "$archive")" >SHA256SUMS)
	checksums=$work/SHA256SUMS
fi

run_installer() {
	sudo sh "$installer" --archive "$archive" --checksums "$checksums" "$@"
}

as_service_user() {
	(cd / && sudo -u "$user" "$BIN" --config "$config" "$@")
}

wait_until_healthy() {
	attempt=0
	until curl -fsS "http://$ADDR/healthz" >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 30 ] || fail "the server does not answer on $ADDR"
		sleep 1
	done
}

owner_and_mode() {
	if [ "$os" = linux ]; then
		sudo stat -c '%U:%G %a' "$1"
	else
		sudo stat -f '%Su:%Sg %Lp' "$1"
	fi
}

# ---------------------------------------------------------------------------------------------

step "Nothing is installed yet"
[ ! -e "$config" ] || fail "$config exists before the test"
if id -u "$user" >/dev/null 2>&1; then fail "user $user exists before the test"; fi

step "A fresh install without --base-url is refused and changes nothing"
if run_installer </dev/null >"$work/out" 2>&1; then fail "installed without --base-url"; fi
cat "$work/out"
grep -q -- "--base-url" "$work/out" || fail "the error does not mention --base-url"
[ ! -e "$config" ] || fail "$config was written"
if id -u "$user" >/dev/null 2>&1; then fail "user $user was created"; fi

step "A fresh install without a terminal needs --admin-password-stdin"
if run_installer --base-url "$BASE_URL" </dev/null >"$work/out" 2>&1; then fail "installed without a password"; fi
cat "$work/out"
grep -q -- "--admin-password-stdin" "$work/out" || fail "the error does not mention --admin-password-stdin"
[ ! -e "$config" ] || fail "$config was written"

step "An archive that does not match SHA256SUMS is refused"
sed 's/^[0-9a-f]*/0000000000000000000000000000000000000000000000000000000000000000/' "$checksums" >"$work/BAD"
# shellcheck disable=SC2024 # The output file belongs to the test user, not to root.
if printf '%s\n' "$PASSWORD" | sudo sh "$installer" --archive "$archive" --checksums "$work/BAD" \
	--base-url "$BASE_URL" --admin-password-stdin >"$work/out" 2>&1; then
	fail "installed an archive with a wrong checksum"
fi
cat "$work/out"
grep -q "checksum mismatch" "$work/out" || fail "the error does not mention the checksum"
[ ! -e "$config" ] || fail "$config was written"

step "Fresh install"
printf '%s\n' "$PASSWORD" | run_installer --base-url "$BASE_URL" --admin-password-stdin

step "The service runs and answers"
wait_until_healthy
curl -fsS "http://$ADDR/status.php" | tee "$work/status"
echo
grep -q '"installed":true' "$work/status" || fail "status.php does not report an installed server"
if [ "$os" = linux ]; then
	systemctl is-active gono-cloud
	systemctl is-enabled gono-cloud
else
	sudo launchctl print system/cloud.gono.server | grep -q "state = running" || fail "the launchd job is not running"
fi

step "Ownership and modes"
[ "$(owner_and_mode "$config")" = "root:$user 640" ] || fail "config: $(owner_and_mode "$config")"
[ "$(owner_and_mode "$(dirname "$config")")" = "root:$user 750" ] || fail "config dir: $(owner_and_mode "$(dirname "$config")")"
[ "$(owner_and_mode "$state")" = "$user:$user 750" ] || fail "state dir: $(owner_and_mode "$state")"
owner_and_mode "$state/gono-cloud.db" | grep -q "^$user:$user " || fail "database: $(owner_and_mode "$state/gono-cloud.db")"
owner_and_mode "$state/data/files/1" | grep -q "^$user:$user " || fail "admin files: $(owner_and_mode "$state/data/files/1")"
sudo grep -qx "base_url = \"$BASE_URL\"" "$config" || fail "base_url not in $config"

step "Management commands refuse root and work as the service user"
if (cd / && sudo "$BIN" --config "$config" user list) >"$work/out" 2>&1; then
	fail "user list ran as root on the service user's installation"
fi
cat "$work/out"
grep -q "runs as root" "$work/out" || fail "the error does not explain the refusal"
as_service_user user list | tee "$work/users"
grep -q "^1 *admin " "$work/users" || fail "no admin account"

step "WebDAV through the service"
token=$(as_service_user app-password add admin --label install-test | sed -n 's/^App password: //p')
[ -n "$token" ] || fail "no app password"
printf 'hello from the install test\n' >"$work/hello.txt"
dav=http://$ADDR/remote.php/dav/files/admin
curl -fsS -u "admin:$token" -T "$work/hello.txt" "$dav/hello.txt"
curl -fsS -u "admin:$token" "$dav/hello.txt" >"$work/back.txt"
cmp "$work/hello.txt" "$work/back.txt" || fail "downloaded file differs"
status=$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$token" -X PROPFIND -H 'Depth: 1' "$dav/")
[ "$status" = 207 ] || fail "PROPFIND answered $status"
sudo test -f "$state/data/files/1/hello.txt" || fail "the file is not in the data directory"

if [ "$os" = linux ]; then
	step "systemd unit verification and exposure"
	sudo systemd-analyze verify /etc/systemd/system/gono-cloud.service
	systemd-analyze security gono-cloud.service --no-pager | tail -n 1
fi

step "SIGTERM stops the server cleanly"
if [ "$os" = linux ]; then
	sudo systemctl stop gono-cloud
	result=$(systemctl show gono-cloud -p Result --value)
	code=$(systemctl show gono-cloud -p ExecMainStatus --value)
	[ "$result" = success ] && [ "$code" = 0 ] || fail "stop: Result=$result ExecMainStatus=$code"
	sudo systemctl start gono-cloud
else
	sudo launchctl kill SIGTERM system/cloud.gono.server
	attempt=0
	while sudo launchctl print system/cloud.gono.server | grep -q "state = running"; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 45 ] || fail "the server did not stop after SIGTERM"
		sleep 1
	done
	sudo launchctl print system/cloud.gono.server | grep "last exit code"
	sudo launchctl print system/cloud.gono.server | grep -q "last exit code = 0" || fail "unclean exit"
	# KeepAlive restarts the job only after a failure.
	sleep 12
	if sudo launchctl print system/cloud.gono.server | grep -q "state = running"; then
		fail "launchd restarted the server after a clean exit"
	fi
	sudo launchctl kickstart system/cloud.gono.server
fi
wait_until_healthy

step "Upgrade keeps the configuration and the files and backs the database up"
before=$(sudo cat "$config" | sha256)
run_installer </dev/null
after=$(sudo cat "$config" | sha256)
[ "$before" = "$after" ] || fail "the upgrade changed $config"
sudo ls "$state/backups"
backup=$(sudo ls "$state/backups" | head -n 1)
sudo test -f "$state/backups/$backup/gono-cloud.db" || fail "no database backup"
wait_until_healthy
curl -fsS -u "admin:$token" "$dav/hello.txt" | cmp - "$work/hello.txt" || fail "the file is gone after the upgrade"

step "Uninstall keeps the configuration, the data and the service user"
sudo sh "$installer" --uninstall
[ ! -e "$BIN" ] || fail "$BIN is still there"
if [ "$os" = linux ]; then
	[ ! -e /etc/systemd/system/gono-cloud.service ] || fail "the unit is still installed"
else
	[ ! -e /Library/LaunchDaemons/cloud.gono.server.plist ] || fail "the launchd job is still installed"
fi
if curl -fsS "http://$ADDR/healthz" >/dev/null 2>&1; then fail "the server still answers"; fi
sudo test -f "$config" || fail "the configuration was removed"
sudo test -f "$state/gono-cloud.db" || fail "the database was removed"
sudo test -f "$state/data/files/1/hello.txt" || fail "the files were removed"
id -u "$user" >/dev/null || fail "the service user was removed"

step "Reinstalling after the uninstall picks the old installation up"
run_installer </dev/null
wait_until_healthy
curl -fsS -u "admin:$token" "$dav/hello.txt" | cmp - "$work/hello.txt" || fail "the file is gone after reinstalling"

printf '\nAll install tests passed.\n'
