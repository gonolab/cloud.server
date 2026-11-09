#!/bin/sh
# Proves that a Linux release archive holds a fully static binary: it has no program
# interpreter and no dynamic section (so no NEEDED libraries), and it runs `init`, serves
# requests and stops cleanly on SIGTERM in containers without any C library (an image with
# nothing but the binary), with musl (Alpine) and with a very old glibc (CentOS 7, glibc 2.17).
#
# Usage: packaging/server/test-static.sh <archive>
#
# Needs readelf, curl and a Docker-compatible CLI. Environment:
#   DOCKER=<command>       container CLI (default: docker; nerdctl works too)
#   CONTAINER_USER=<u:g>   user the containers run as (default: the caller's uid:gid, which
#                          owns the mounted state directory; use 0:0 with rootless nerdctl or
#                          Podman, whose container root is the caller)
#   PORT=<port>            loopback port published for the smoke tests (default: 16102)

set -eu

[ $# -eq 1 ] || {
	echo "usage: $0 <archive>" >&2
	exit 2
}
archive=$1
DOCKER=${DOCKER:-docker}
CONTAINER_USER=${CONTAINER_USER:-$(id -u):$(id -g)}
PORT=${PORT:-16102}
IMAGES="alpine:3.22 centos:7"

work=$(mktemp -d)
cleanup() {
	"$DOCKER" rm -f gono-static-smoke >/dev/null 2>&1 || true
	"$DOCKER" rmi gono-static-scratch >/dev/null 2>&1 || true
	rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

tar -xzf "$archive" -C "$work"
release=$work/$(basename "$archive" .tar.gz)
binary=$release/gono-cloud
[ -f "$binary" ] || fail "no gono-cloud in $archive"

printf '### ELF headers of %s\n' "$(basename "$archive")"
if command -v file >/dev/null 2>&1; then
	file "$binary"
fi
readelf -hW "$binary" | grep -E 'Class|Type:|Machine'
readelf -lW "$binary" >"$work/segments"
readelf -dW "$binary" >"$work/dynamic"
cat "$work/dynamic"
if grep -q INTERP "$work/segments"; then fail "the binary names a program interpreter"; fi
if grep -q NEEDED "$work/dynamic"; then fail "the binary needs shared libraries"; fi
echo "static: no interpreter, no NEEDED entries"

# An image with nothing but the binary: no C library, no shell, no /etc of its own.
printf 'FROM scratch\nCOPY gono-cloud /gono-cloud\n' >"$work/Dockerfile"
"$DOCKER" build -q -t gono-static-scratch -f "$work/Dockerfile" "$release" >/dev/null

for image in gono-static-scratch $IMAGES; do
	printf '\n### %s\n' "$image"
	state=$work/state-$(printf '%s' "$image" | tr -c 'a-zA-Z0-9\n' '-')
	mkdir "$state"
	# The server listens on all addresses inside the container; the port is published on the
	# loopback address of this machine only.
	sed -e 's|^bind = .*|bind = "0.0.0.0:16102"|' \
		-e 's|^allow_non_loopback_bind = .*|allow_non_loopback_bind = true|' \
		-e 's|^data_dir = .*|data_dir = "/state/data"|' \
		-e 's|^path = "gono-cloud.db"|path = "/state/gono-cloud.db"|' \
		"$release/config.example.toml" >"$state.toml"
	chmod 0644 "$state.toml"
	set -- run --user "$CONTAINER_USER" -v "$binary:/gono-cloud:ro" -v "$state.toml:/config.toml:ro" \
		-v "$state:/state"

	if [ "$image" != gono-static-scratch ]; then
		"$DOCKER" "$@" --rm "$image" sh -c \
			'sed -n "s/^PRETTY_NAME=//p" /etc/os-release; (ldd --version 2>&1 || true) | sed -n 1p'
	fi
	"$DOCKER" "$@" --rm "$image" /gono-cloud --version
	printf '%s\n' "static test password" |
		"$DOCKER" "$@" --rm -i "$image" /gono-cloud --config /config.toml init --password-stdin >/dev/null
	"$DOCKER" "$@" -d --name gono-static-smoke -p "127.0.0.1:$PORT:16102" "$image" \
		/gono-cloud --config /config.toml serve >/dev/null
	attempt=0
	until curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		if [ "$attempt" -ge 30 ]; then
			"$DOCKER" logs gono-static-smoke
			fail "$image: the server does not answer"
		fi
		sleep 1
	done
	curl -fsS "http://127.0.0.1:$PORT/status.php"
	echo
	"$DOCKER" stop -t 45 gono-static-smoke >/dev/null
	code=$("$DOCKER" inspect --format '{{.State.ExitCode}}' gono-static-smoke)
	"$DOCKER" logs gono-static-smoke 2>&1 | tail -n 1
	"$DOCKER" rm gono-static-smoke >/dev/null
	[ "$code" = 0 ] || fail "$image: exit code $code after SIGTERM"
	echo "$image: init, serve and SIGTERM work"
done

printf '\nThe binary is static and runs without glibc.\n'
