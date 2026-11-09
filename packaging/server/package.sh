#!/bin/sh
# Packs a compiled gono-cloud binary into a release archive.
#
# Usage: packaging/server/package.sh <target triple> <binary> <output directory>
#
# Writes <output directory>/gono-cloud-<version>-<target>.tar.gz, where <version> is the
# workspace version in Cargo.toml. The archive holds one directory of the same name with the
# binary, the licenses, config.example.toml, the server changelog, a short README and the service
# file for the platform (systemd unit or launchd job). Entries are sorted, owned by 0:0 and
# dated SOURCE_DATE_EPOCH (default: the time of the last commit), and gzip records no name or
# time, so packing the same binary twice gives the same archive.
#
# Run it from the repository root. The release workflow (.github/workflows/release.yml) calls it
# for every target.

set -eu

[ $# -eq 3 ] || {
	echo "usage: $0 <target triple> <binary> <output directory>" >&2
	exit 2
}
target=$1
binary=$2
out=$3

[ -f Cargo.toml ] && [ -d packaging/server ] || {
	echo "error: run $0 from the repository root" >&2
	exit 1
}
[ -f "$binary" ] || {
	echo "error: binary $binary not found" >&2
	exit 1
}

# The first `version = "..."` line of the root manifest is [workspace.package].version.
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$version" ] || {
	echo "error: no workspace version in Cargo.toml" >&2
	exit 1
}

case $target in
*-linux-*) service_dir=systemd service_file=gono-cloud.service ;;
*-apple-darwin) service_dir=launchd service_file=cloud.gono.server.plist ;;
*)
	echo "error: unsupported target $target" >&2
	exit 1
	;;
esac

name=gono-cloud-$version-$target
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
root=$stage/$name
mkdir -p "$root/$service_dir"

install -m 0755 "$binary" "$root/gono-cloud"
install -m 0644 LICENSE-APACHE LICENSE-MIT config.example.toml "$root/"
install -m 0644 crates/server/CHANGELOG.md "$root/CHANGELOG.md"
install -m 0644 packaging/server/README.md "$root/README.md"
install -m 0644 "packaging/server/$service_dir/$service_file" "$root/$service_dir/"
chmod 0755 "$root" "$root/$service_dir"

# Fixed timestamps and order.
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
stamp=$(date -u -d "@$epoch" +%Y%m%d%H%M.%S 2>/dev/null || date -u -r "$epoch" +%Y%m%d%H%M.%S)
entries="$name
$name/CHANGELOG.md
$name/LICENSE-APACHE
$name/LICENSE-MIT
$name/README.md
$name/config.example.toml
$name/gono-cloud
$name/$service_dir
$name/$service_dir/$service_file"
for entry in $entries; do
	TZ=UTC0 touch -h -t "$stamp" "$stage/$entry"
done

if tar --version 2>/dev/null | grep -q 'GNU tar'; then
	owner="--owner=0 --group=0 --numeric-owner"
else
	# bsdtar (macOS); COPYFILE_DISABLE keeps AppleDouble files out of the archive.
	owner="--uid 0 --gid 0 --numeric-owner --no-xattrs --no-acls --no-fflags"
	export COPYFILE_DISABLE=1
fi

mkdir -p "$out"
archive=$out/$name.tar.gz
# shellcheck disable=SC2086 # $owner and $entries are word lists by design.
tar -cf - -C "$stage" --format ustar --no-recursion $owner $entries | gzip -9 -n >"$archive"
echo "$archive"
