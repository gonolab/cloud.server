#!/usr/bin/env bash
# Sync scenarios with the Nextcloud desktop client's command line tool (`nextcloudcmd`)
# against the server built from this checkout.
#
# The script builds `gono-cloud`, initializes a throwaway installation in a temporary directory,
# starts `serve` on a free loopback port, mints an app password, and then syncs two local
# folders ("devices" A and B) with the server through nextcloudcmd:
#
#   1. first sync       files created on the server appear on a device
#   2. upload           new files and folders of a device reach the server
#   3. deep change      a file changed deep in the tree on device B is found by device A
#                       (directory ETag propagation)
#   4. rename           files and folders, including a rename that only changes the case
#   5. delete           files and folders deleted on a device disappear everywhere
#   6. chunked upload   a large file is uploaded in chunks (MKCOL/PUT/MOVE under
#                       /remote.php/dav/uploads/), then replaced by a chunked upload again
#
# Every scenario checks the server over WebDAV and the other device after syncing it. The
# script exits non-zero when a scenario fails. Everything is removed again on exit.
#
# Usage:
#   acceptance/scripts/nextcloudcmd-scenarios.sh
#
# Environment:
#   NEXTCLOUDCMD=<path>    nextcloudcmd binary (default: the one on PATH)
#   NEW_TARGET_DIR=<dir>   cargo target dir for the server build (default: the repository's)
#   KEEP_WORK_DIR=1        keep the temporary config, data, sync folders and logs
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
NEXTCLOUDCMD="${NEXTCLOUDCMD:-nextcloudcmd}"
USER_NAME="gono"

usage() {
  sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
  "") ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "unknown argument: $1" >&2
    usage >&2
    exit 2
    ;;
esac

# Reports a problem as a GitHub Actions error annotation (see run-new.sh).
annotate() {
  local title="$1" message="$2"
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    message="${message//'%'/'%25'}"
    message="${message//$'\r'/'%0D'}"
    message="${message//$'\n'/'%0A'}"
    title="${title//'%'/'%25'}"
    title="${title//$'\r'/'%0D'}"
    title="${title//$'\n'/'%0A'}"
    title="${title//':'/'%3A'}"
    title="${title//','/'%2C'}"
    echo "::error title=${title}::${message:-${title}}"
  fi
}

trap '[[ $- == *e* ]] && annotate "nextcloudcmd-scenarios.sh" "command failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    annotate "nextcloudcmd-scenarios.sh" "missing required command: $1"
    exit 1
  fi
}

require_cmd cargo
require_cmd curl
require_cmd python3
require_cmd "${NEXTCLOUDCMD}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gono-nextcloudcmd.XXXXXX")"
TARGET_DIR="${NEW_TARGET_DIR:-${REPO_ROOT}/target}"
CONFIG_FILE="${WORK_DIR}/config.toml"
LOG_FILE="${WORK_DIR}/server.log"
STDOUT_LOG="${WORK_DIR}/server-stdout.log"
SYNC_LOG="${WORK_DIR}/nextcloudcmd.log"
DEVICE_A="${WORK_DIR}/device-a"
DEVICE_B="${WORK_DIR}/device-b"
SERVER_PID=""
CURRENT="setup"

cleanup() {
  local status=$?
  if [[ "${status}" != "0" ]]; then
    local tails=""
    for log in "${SYNC_LOG}" "${STDOUT_LOG}" "${LOG_FILE}"; do
      if [[ -s "${log}" ]]; then
        tails+="== ${log##*/}"$'\n'"$(tail -n 20 "${log}")"$'\n'
      fi
    done
    annotate "nextcloudcmd scenario '${CURRENT}' failed (exit ${status})" "${tails}"
  fi
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ "${KEEP_WORK_DIR}" == "1" ]]; then
    echo "kept work dir: ${WORK_DIR}" >&2
  else
    rm -rf "${WORK_DIR}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "FAIL [${CURRENT}]: $*" >&2
  echo "---- last nextcloudcmd output" >&2
  tail -n 30 "${SYNC_LOG}" >&2 || true
  exit 1
}

# --- Server -------------------------------------------------------------------------------------

find_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

echo "==> building gono-cloud (target dir: ${TARGET_DIR})"
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --quiet --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p gono-server --bin gono-cloud
BIN="${TARGET_DIR}/debug/gono-cloud"

PORT="$(find_port)"
BASE_URL="http://127.0.0.1:${PORT}"
DAV_URL="${BASE_URL}/remote.php/dav/files/${USER_NAME}"

# `info` so that the request log shows which requests the client made.
cat >"${CONFIG_FILE}" <<EOF
[server]
bind = "127.0.0.1:${PORT}"
base_url = "${BASE_URL}"

[storage]
data_dir = "${WORK_DIR}/data"

[db]
path = "${WORK_DIR}/gono-cloud.db"

[logging]
level = "info"
file = "${LOG_FILE}"
EOF

echo "==> initializing a fresh installation in ${WORK_DIR}"
python3 -c 'import secrets; print(secrets.token_urlsafe(18))' |
  "${BIN}" --config "${CONFIG_FILE}" init --admin "${USER_NAME}" --password-stdin >/dev/null
PASSWORD="$("${BIN}" --config "${CONFIG_FILE}" app-password add "${USER_NAME}" --label nextcloudcmd 2>&1 |
  sed -n 's/^App password: \([^[:space:]]*\)$/\1/p' | tail -n 1)"
[[ -n "${PASSWORD}" ]] || fail "app-password add did not print a password"

echo "==> starting gono-cloud on ${BASE_URL}"
"${BIN}" --config "${CONFIG_FILE}" serve >"${STDOUT_LOG}" 2>&1 &
SERVER_PID="$!"
for _ in $(seq 1 200); do
  curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1 && break
  kill -0 "${SERVER_PID}" 2>/dev/null || fail "the server exited: $(tail -n 5 "${STDOUT_LOG}")"
  sleep 0.1
done
curl -fsS "${BASE_URL}/healthz" >/dev/null || fail "the server did not become ready"

# --- Helpers ------------------------------------------------------------------------------------

curl_dav() {
  curl -sS -u "${USER_NAME}:${PASSWORD}" "$@"
}

# Percent-encodes a relative path, segment by segment.
encode() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

remote_status() {
  curl_dav -o /dev/null -w '%{http_code}' -I "${DAV_URL}/$(encode "$1")"
}

remote_get() {
  curl_dav -f "${DAV_URL}/$(encode "$1")"
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@" | cut -d' ' -f1
  else
    shasum -a 256 "$@" | cut -d' ' -f1
  fi
}

remote_sha256() {
  curl_dav -f "${DAV_URL}/$(encode "$1")" | sha256
}

remote_put() {
  curl_dav -f -o /dev/null -T - "${DAV_URL}/$(encode "$1")"
}

remote_mkcol() {
  curl_dav -f -o /dev/null -X MKCOL "${DAV_URL}/$(encode "$1")"
}

# Names directly inside a remote folder, one per line.
remote_list() {
  curl_dav -f -X PROPFIND -H 'Depth: 1' "${DAV_URL}/$(encode "$1")" |
    python3 -c '
import sys, urllib.parse, xml.etree.ElementTree as ET
hrefs = [e.text for e in ET.parse(sys.stdin).iter("{DAV:}href")]
base = hrefs[0].rstrip("/")
for href in hrefs[1:]:
    print(urllib.parse.unquote(href.rstrip("/")[len(base) + 1:]))
'
}

remote_fileid() {
  curl_dav -f -X PROPFIND -H 'Depth: 0' --data \
    '<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>' \
    "${DAV_URL}/$(encode "$1")" |
    python3 -c 'import sys, xml.etree.ElementTree as ET; print(next(ET.parse(sys.stdin).iter("{http://owncloud.org/ns}fileid")).text)'
}

local_sha256() {
  sha256 "$1"
}

# Syncs a device folder with the server. Extra environment variables can be passed as
# arguments (`sync_device <dir> NAME=value ...`).
sync_device() {
  local dir="$1"
  shift
  mkdir -p "${dir}"
  echo "---- sync ${dir##*/} (${CURRENT})" >>"${SYNC_LOG}"
  if ! env "$@" "${NEXTCLOUDCMD}" --non-interactive -u "${USER_NAME}" -p "${PASSWORD}" \
    "${dir}" "${BASE_URL}" >>"${SYNC_LOG}" 2>&1; then
    fail "nextcloudcmd exited with an error while syncing ${dir##*/}"
  fi
}

expect_eq() {
  local what="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] || fail "${what}: expected '${expected}', got '${actual}'"
}

expect_local() {
  local file="$1" content="$2"
  [[ -f "${file}" ]] || fail "missing on the device: ${file#"${WORK_DIR}"/}"
  expect_eq "content of ${file#"${WORK_DIR}"/}" "${content}" "$(cat "${file}")"
}

expect_local_absent() {
  [[ ! -e "$1" ]] || fail "still on the device: ${1#"${WORK_DIR}"/}"
}

expect_remote() {
  local rel="$1" content="$2"
  expect_eq "server status of ${rel}" "200" "$(remote_status "${rel}")"
  expect_eq "server content of ${rel}" "${content}" "$(remote_get "${rel}")"
}

expect_remote_absent() {
  expect_eq "server status of $1" "404" "$(remote_status "$1")"
}

# Counts request log lines of the server with this method whose target starts with a prefix.
count_requests() {
  local method="$1" prefix="$2"
  grep -c "method=${method} target=${prefix}" "${LOG_FILE}" || true
}

scenario() {
  CURRENT="$1"
  echo "==> scenario: $1"
}

passed() {
  echo "    ok: ${CURRENT}"
  PASSED+=("${CURRENT}")
}

PASSED=()
"${NEXTCLOUDCMD}" --version 2>/dev/null | head -n 1 || true

# --- 1. First sync ------------------------------------------------------------------------------

scenario "first sync"
remote_mkcol "docs"
remote_mkcol "docs/deep"
remote_mkcol "docs/deep/er"
printf 'read me' | remote_put "docs/readme.txt"
printf 'deep notes v1' | remote_put "docs/deep/er/notes.txt"
printf 'spaces' | remote_put "with space.txt"
printf 'unicode' | remote_put "Ümlaut ß.txt"
sync_device "${DEVICE_A}"
expect_local "${DEVICE_A}/docs/readme.txt" "read me"
expect_local "${DEVICE_A}/docs/deep/er/notes.txt" "deep notes v1"
expect_local "${DEVICE_A}/with space.txt" "spaces"
expect_local "${DEVICE_A}/Ümlaut ß.txt" "unicode"
passed

# --- 2. Upload ----------------------------------------------------------------------------------

scenario "upload"
printf 'new file' >"${DEVICE_A}/new.txt"
mkdir -p "${DEVICE_A}/folder/sub"
head -c 200000 /dev/urandom >"${DEVICE_A}/folder/sub/random.bin"
sync_device "${DEVICE_A}"
expect_remote "new.txt" "new file"
expect_eq "server copy of folder/sub/random.bin" \
  "$(local_sha256 "${DEVICE_A}/folder/sub/random.bin")" "$(remote_sha256 "folder/sub/random.bin")"
sync_device "${DEVICE_B}"
expect_local "${DEVICE_B}/new.txt" "new file"
expect_eq "device B copy of folder/sub/random.bin" \
  "$(local_sha256 "${DEVICE_A}/folder/sub/random.bin")" "$(local_sha256 "${DEVICE_B}/folder/sub/random.bin")"
passed

# --- 3. Deep change from another device ----------------------------------------------------------

scenario "deep change"
printf 'deep notes v2 from B' >"${DEVICE_B}/docs/deep/er/notes.txt"
sync_device "${DEVICE_B}"
expect_remote "docs/deep/er/notes.txt" "deep notes v2 from B"
# Device A only finds the change if every ancestor folder got a new ETag.
sync_device "${DEVICE_A}"
expect_local "${DEVICE_A}/docs/deep/er/notes.txt" "deep notes v2 from B"
passed

# --- 4. Rename ----------------------------------------------------------------------------------

scenario "rename"
mv "${DEVICE_A}/docs/readme.txt" "${DEVICE_A}/docs/renamed.txt"
mv "${DEVICE_A}/folder" "${DEVICE_A}/folder2"
fileid_before="$(remote_fileid "new.txt")"
# A rename that only changes the case needs a case-sensitive device folder.
touch "${DEVICE_A}/.case-probe"
if [[ -e "${DEVICE_A}/.CASE-PROBE" ]]; then
  CASE_ONLY=0
  echo "    (case-insensitive file system here: skipping the case-only rename)"
else
  CASE_ONLY=1
  mv "${DEVICE_A}/new.txt" "${DEVICE_A}/New.txt"
fi
rm -f "${DEVICE_A}/.case-probe"
sync_device "${DEVICE_A}"
expect_remote_absent "docs/readme.txt"
expect_remote "docs/renamed.txt" "read me"
expect_remote_absent "folder"
expect_eq "server status of folder2/sub/random.bin" "200" "$(remote_status "folder2/sub/random.bin")"
if [[ "${CASE_ONLY}" == "1" ]]; then
  root_listing="$(remote_list "")"
  grep -qx 'New.txt' <<<"${root_listing}" || fail "New.txt is not on the server: ${root_listing}"
  ! grep -qx 'new.txt' <<<"${root_listing}" || fail "new.txt is still on the server"
  expect_eq "file id after the case-only rename" "${fileid_before}" "$(remote_fileid "New.txt")"
fi
sync_device "${DEVICE_B}"
expect_local_absent "${DEVICE_B}/docs/readme.txt"
expect_local "${DEVICE_B}/docs/renamed.txt" "read me"
expect_local_absent "${DEVICE_B}/folder"
[[ -f "${DEVICE_B}/folder2/sub/random.bin" ]] || fail "folder2 is missing on device B"
if [[ "${CASE_ONLY}" == "1" ]]; then
  expect_local "${DEVICE_B}/New.txt" "new file"
  expect_local_absent "${DEVICE_B}/new.txt"
fi
passed

# --- 5. Delete ----------------------------------------------------------------------------------

scenario "delete"
rm "${DEVICE_A}/docs/deep/er/notes.txt"
rm -r "${DEVICE_A}/folder2"
sync_device "${DEVICE_A}"
expect_remote_absent "docs/deep/er/notes.txt"
expect_remote_absent "folder2"
expect_eq "server status of docs/deep/er" "200" "$(remote_status "docs/deep/er")"
sync_device "${DEVICE_B}"
expect_local_absent "${DEVICE_B}/docs/deep/er/notes.txt"
expect_local_absent "${DEVICE_B}/folder2"
passed

# --- 6. Chunked upload --------------------------------------------------------------------------

scenario "chunked upload"
# Small chunks, so that the file is split into several of them whatever the client's defaults.
CHUNKS=(OWNCLOUD_CHUNK_SIZE=4194304 OWNCLOUD_MIN_CHUNK_SIZE=1048576 OWNCLOUD_MAX_CHUNK_SIZE=4194304
  OWNCLOUD_TARGET_CHUNK_UPLOAD_DURATION=0)
head -c 31457280 /dev/urandom >"${DEVICE_A}/big.bin"
moves_before="$(count_requests MOVE "/remote.php/dav/uploads/${USER_NAME}/")"
sync_device "${DEVICE_A}" "${CHUNKS[@]}"
expect_eq "server copy of big.bin" "$(local_sha256 "${DEVICE_A}/big.bin")" "$(remote_sha256 "big.bin")"
mkcols="$(count_requests MKCOL "/remote.php/dav/uploads/${USER_NAME}/")"
chunks="$(count_requests PUT "/remote.php/dav/uploads/${USER_NAME}/")"
moves="$(count_requests MOVE "/remote.php/dav/uploads/${USER_NAME}/")"
echo "    upload requests: ${mkcols} MKCOL, ${chunks} chunk PUTs, $((moves - moves_before)) MOVE"
[[ "${mkcols}" -ge 1 && "${chunks}" -ge 2 && "$((moves - moves_before))" -ge 1 ]] ||
  fail "big.bin was not uploaded in chunks (${mkcols} MKCOL, ${chunks} PUT, ${moves} MOVE)"
fileid_before="$(remote_fileid "big.bin")"
sync_device "${DEVICE_B}"
expect_eq "device B copy of big.bin" "$(local_sha256 "${DEVICE_A}/big.bin")" "$(local_sha256 "${DEVICE_B}/big.bin")"

# Replace it with a chunked upload from device B.
head -c 20971520 /dev/urandom >"${DEVICE_B}/big.bin"
sync_device "${DEVICE_B}" "${CHUNKS[@]}"
expect_eq "server copy of the replaced big.bin" "$(local_sha256 "${DEVICE_B}/big.bin")" "$(remote_sha256 "big.bin")"
expect_eq "file id of the replaced big.bin" "${fileid_before}" "$(remote_fileid "big.bin")"
expect_eq "chunk MOVEs after replacing big.bin" "$((moves + 1))" \
  "$(count_requests MOVE "/remote.php/dav/uploads/${USER_NAME}/")"
sync_device "${DEVICE_A}"
expect_eq "device A copy of the replaced big.bin" "$(local_sha256 "${DEVICE_B}/big.bin")" "$(local_sha256 "${DEVICE_A}/big.bin")"
# Finished uploads leave no session behind.
sessions="$(curl_dav -f -X PROPFIND -H 'Depth: 1' "${BASE_URL}/remote.php/dav/uploads/${USER_NAME}/" |
  grep -o '<d:response>' | wc -l | tr -d ' ')"
expect_eq "responses in the upload namespace (the root only)" "1" "${sessions}"
passed

CURRENT="summary"
echo
echo "==> all ${#PASSED[@]} nextcloudcmd scenarios passed:"
printf '    %s\n' "${PASSED[@]}"
