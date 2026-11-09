#!/usr/bin/env bash
# Run the acceptance suite against the legacy v0.1.x server (git commit d366e79).
#
# The script checks the legacy revision out into a temporary git worktree, builds it, starts it
# on a free loopback port with a throwaway config and data directory, mints the credentials the
# suite needs, runs `cargo test` in acceptance/, and compares the failures with
# acceptance/legacy-expected-failures.txt. Everything is removed again on exit.
#
# Usage:
#   acceptance/scripts/run-legacy.sh [-- <extra cargo test args>]
#   acceptance/scripts/run-legacy.sh --serve
#
# Environment:
#   LEGACY_REV=<rev>          legacy revision to check out (default: d366e79)
#   LEGACY_TARGET_DIR=<dir>   cargo target dir for the legacy build; point it at a persistent
#                             directory to reuse the build between runs (default: temporary)
#   RUN_LITMUS=1              also run `litmus` against the server when it is installed
#   LITMUS=<path>             litmus binary to use instead of the one on PATH
#   KEEP_WORK_DIR=1           keep the temporary config, data, and logs for inspection
set -euo pipefail

ACCEPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git -C "${ACCEPT_DIR}" rev-parse --show-toplevel)"
LEGACY_REV="${LEGACY_REV:-d366e79}"
RUN_LITMUS="${RUN_LITMUS:-0}"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
EXPECTED_FAILURES_FILE="${ACCEPT_DIR}/legacy-expected-failures.txt"
MODE="test"
CARGO_TEST_ARGS=()

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while (($#)); do
  case "$1" in
    --serve)
      MODE="serve"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      CARGO_TEST_ARGS=("$@")
      break
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd curl
require_cmd git
require_cmd python3
require_cmd sed

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gono-legacy-accept.XXXXXX")"
LEGACY_TREE="${WORK_DIR}/legacy"
TARGET_DIR="${LEGACY_TARGET_DIR:-${WORK_DIR}/target}"
CONFIG_FILE="${WORK_DIR}/config.toml"
LOG_FILE="${WORK_DIR}/server.log"
STDOUT_LOG="${WORK_DIR}/server-stdout.log"
TEST_LOG="${WORK_DIR}/cargo-test.log"
SERVER_PID=""
WORKTREE_ADDED=0

cleanup() {
  local status=$?
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ "${WORKTREE_ADDED}" == "1" ]]; then
    git -C "${REPO_ROOT}" worktree remove --force "${LEGACY_TREE}" >/dev/null 2>&1 || true
    git -C "${REPO_ROOT}" worktree prune >/dev/null 2>&1 || true
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

strip_ansi() {
  sed $'s/\033\\[[0-9;]*m//g'
}

find_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_server() {
  for _ in $(seq 1 200); do
    if curl -fsS "${BASE_URL}/status.php" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      echo "legacy server exited before becoming ready" >&2
      cat "${STDOUT_LOG}" "${LOG_FILE}" >&2 2>/dev/null || true
      exit 1
    fi
    sleep 0.1
  done
  echo "legacy server did not become ready" >&2
  cat "${STDOUT_LOG}" "${LOG_FILE}" >&2 2>/dev/null || true
  exit 1
}

wait_for_bootstrap_password() {
  local password=""
  for _ in $(seq 1 200); do
    password="$(strip_ansi <"${LOG_FILE}" 2>/dev/null |
      sed -n 's/.*Generated app password for gono: \([^[:space:]]*\).*/\1/p' | tail -n 1)"
    if [[ -n "${password}" ]]; then
      echo "${password}"
      return 0
    fi
    sleep 0.1
  done
  echo "the legacy server did not log a generated app password" >&2
  cat "${LOG_FILE}" >&2 2>/dev/null || true
  exit 1
}

# Runs a legacy CLI command and prints the `App password: <pw>` value it reports.
legacy_cli_password() {
  local output password
  output="$(GONE_CLOUD_CONFIG="${CONFIG_FILE}" "${LEGACY_BIN}" "$@" 2>&1)"
  password="$(printf '%s\n' "${output}" | strip_ansi |
    sed -n 's/^App password: \([^[:space:]]*\).*/\1/p' | tail -n 1)"
  if [[ -z "${password}" ]]; then
    echo "legacy CLI did not print an app password for: $*" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  echo "${password}"
}

echo "==> checking out ${LEGACY_REV} into ${LEGACY_TREE}"
git -C "${REPO_ROOT}" worktree add --detach --quiet "${LEGACY_TREE}" "${LEGACY_REV}"
WORKTREE_ADDED=1

echo "==> building the legacy server (target dir: ${TARGET_DIR})"
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --quiet --manifest-path "${LEGACY_TREE}/Cargo.toml"
LEGACY_BIN="${TARGET_DIR}/debug/gono-cloud"

PORT="$(find_port)"
BASE_URL="http://127.0.0.1:${PORT}"

cat >"${CONFIG_FILE}" <<EOF
[server]
bind = "127.0.0.1:${PORT}"
cert_file = "${WORK_DIR}/missing-cert.pem"
key_file = "${WORK_DIR}/missing-key.pem"
base_url = "${BASE_URL}"

[storage]
data_dir = "${WORK_DIR}/data"
xattr_ns = "user.nc"
upload_min_free_bytes = 0
upload_min_free_percent = 0

[db]
path = "${WORK_DIR}/gono-cloud.db"
max_connections = 5

[auth]
realm = "Gono Cloud"

[admin]
enabled = true
users = ["gono"]

[notify_push]
enabled = true

[logging]
loglevel = "warning"
logfile = "${LOG_FILE}"
EOF

echo "==> starting the legacy server on ${BASE_URL}"
GONE_CLOUD_CONFIG="${CONFIG_FILE}" GONE_CLOUD_INSECURE_HTTP=1 \
  "${LEGACY_BIN}" serve >"${STDOUT_LOG}" 2>&1 &
SERVER_PID="$!"
wait_for_server
PASSWORD="$(wait_for_bootstrap_password)"

echo "==> minting credentials with the legacy CLI"
VIEW_PASSWORD="$(legacy_cli_password app-password-add gono readonly --mount /=/:view)"
SCOPED_PASSWORD="$(legacy_cli_password app-password-add gono scoped \
  --mount /acc-view=/acc-scope/view:view \
  --mount /acc-full=/acc-scope/full:full)"
USER2_PASSWORD="$(legacy_cli_password user-add alice)"

export GONO_ACCEPT_BASE_URL="${BASE_URL}"
export GONO_ACCEPT_USER="gono"
export GONO_ACCEPT_PASSWORD="${PASSWORD}"
export GONO_ACCEPT_VIEW_PASSWORD="${VIEW_PASSWORD}"
export GONO_ACCEPT_SCOPED_PASSWORD="${SCOPED_PASSWORD}"
# The legacy server has no separate web login password; the app password is used instead.
export GONO_ACCEPT_WEB_PASSWORD="${PASSWORD}"
export GONO_ACCEPT_ADMIN_PATH="/gono-admin"
export GONO_ACCEPT_USER2="alice"
export GONO_ACCEPT_PASSWORD2="${USER2_PASSWORD}"

ENV_FILE="${WORK_DIR}/accept.env"
{
  for name in GONO_ACCEPT_BASE_URL GONO_ACCEPT_USER GONO_ACCEPT_PASSWORD \
    GONO_ACCEPT_VIEW_PASSWORD GONO_ACCEPT_SCOPED_PASSWORD GONO_ACCEPT_WEB_PASSWORD \
    GONO_ACCEPT_ADMIN_PATH GONO_ACCEPT_USER2 GONO_ACCEPT_PASSWORD2; do
    printf 'export %s=%q\n' "${name}" "${!name}"
  done
} >"${ENV_FILE}"

if [[ "${MODE}" == "serve" ]]; then
  echo "==> legacy server is running; load the credentials with:"
  echo "    source ${ENV_FILE}"
  echo "==> press Ctrl-C to stop the server and remove the temporary files"
  wait "${SERVER_PID}"
  exit 0
fi

STATUS=0

echo "==> running the acceptance suite"
set +e
cargo test --manifest-path "${ACCEPT_DIR}/Cargo.toml" --no-fail-fast -- ${CARGO_TEST_ARGS[@]+"${CARGO_TEST_ARGS[@]}"} 2>&1 |
  tee "${TEST_LOG}"
CARGO_STATUS="${PIPESTATUS[0]}"
set -e

# Collect `<binary>::<test>` names for failed and passed tests from the libtest output.
collect_results() {
  local outcome="$1"
  awk -v outcome="${outcome}" '
    /^ *Running tests\// {
      binary = $2
      sub(/^tests\//, "", binary)
      sub(/\.rs$/, "", binary)
    }
    /^test .* \.\.\. / {
      name = $2
      result = $NF
      if (result == outcome && binary != "") print binary "::" name
    }
  ' "${TEST_LOG}" | sort -u
}

FAILED="$(collect_results FAILED)"
PASSED="$(collect_results ok)"
EXPECTED="$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "${EXPECTED_FAILURES_FILE}" | sort -u)"
UNEXPECTED_FAILURES="$(comm -23 <(printf '%s\n' "${FAILED}") <(printf '%s\n' "${EXPECTED}") | sed '/^$/d')"
UNEXPECTED_PASSES="$(comm -12 <(printf '%s\n' "${PASSED}") <(printf '%s\n' "${EXPECTED}") | sed '/^$/d')"
SKIPPED="$(grep -o 'SKIP [A-Za-z0-9_:]*: ' "${TEST_LOG}" | wc -l | tr -d ' ')"

echo
echo "==> legacy baseline summary"
echo "passed:  $(printf '%s\n' "${PASSED}" | sed '/^$/d' | wc -l | tr -d ' ') (skipped inside: ${SKIPPED})"
echo "failed:  $(printf '%s\n' "${FAILED}" | sed '/^$/d' | wc -l | tr -d ' ')"
if [[ -n "${UNEXPECTED_FAILURES}" ]]; then
  echo "unexpected failures (not in legacy-expected-failures.txt):"
  printf '  %s\n' ${UNEXPECTED_FAILURES}
  STATUS=1
fi
if [[ -n "${UNEXPECTED_PASSES}" ]]; then
  echo "expected failures that passed (update legacy-expected-failures.txt):"
  printf '  %s\n' ${UNEXPECTED_PASSES}
  STATUS=1
fi
if [[ "${CARGO_STATUS}" != "0" && -z "${FAILED}" ]]; then
  echo "cargo test failed without reporting test failures (build error?)"
  STATUS=1
fi
if [[ "${STATUS}" == "0" ]]; then
  echo "all failures match the expected legacy failures"
fi

if [[ "${RUN_LITMUS}" == "1" ]]; then
  LITMUS_BIN="${LITMUS:-$(command -v litmus || true)}"
  if [[ -z "${LITMUS_BIN}" || ! -x "${LITMUS_BIN}" ]]; then
    echo "==> RUN_LITMUS=1 but litmus is not installed; skipping litmus"
  else
    echo "==> running litmus against ${BASE_URL}/remote.php/dav/"
    if ! (cd "${WORK_DIR}" && "${LITMUS_BIN}" "${BASE_URL}/remote.php/dav/" gono "${PASSWORD}"); then
      echo "litmus reported failures"
      STATUS=1
    fi
  fi
fi

exit "${STATUS}"
