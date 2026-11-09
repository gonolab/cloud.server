#!/usr/bin/env bash
# Run the acceptance suite against the server built from this checkout.
#
# The script builds `gono-cloud`, initializes a throwaway installation in a temporary
# directory (`init --password-stdin`), starts `serve` on a free loopback port, mints the
# credentials the suite needs with the `user` and `app-password` commands, runs `cargo test` in
# acceptance/, and compares the failures with acceptance/new-expected-failures.txt. Everything
# is removed again on exit.
#
# Usage:
#   acceptance/scripts/run-new.sh [-- <extra cargo test args>]
#   acceptance/scripts/run-new.sh --serve
#
# Environment:
#   NEW_TARGET_DIR=<dir>   cargo target dir for the server build (default: the repository's)
#   RUN_LITMUS=1           also run `litmus` against the WebDAV root of the test user; fails
#                          when litmus is not installed or reports a failure
#   LITMUS=<path>          litmus binary to use instead of the one on PATH
#   KEEP_WORK_DIR=1        keep the temporary config, data, and logs for inspection
set -euo pipefail

ACCEPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ACCEPT_DIR}/.." && pwd)"
RUN_LITMUS="${RUN_LITMUS:-0}"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"
EXPECTED_FAILURES_FILE="${ACCEPT_DIR}/new-expected-failures.txt"
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
require_cmd python3
require_cmd sed

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gono-new-accept.XXXXXX")"
TARGET_DIR="${NEW_TARGET_DIR:-${REPO_ROOT}/target}"
CONFIG_FILE="${WORK_DIR}/config.toml"
LOG_FILE="${WORK_DIR}/server.log"
STDOUT_LOG="${WORK_DIR}/server-stdout.log"
TEST_LOG="${WORK_DIR}/cargo-test.log"
SERVER_PID=""

cleanup() {
  local status=$?
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

find_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

random_password() {
  python3 -c 'import secrets; print(secrets.token_urlsafe(18))'
}

wait_for_server() {
  for _ in $(seq 1 200); do
    if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      echo "the server exited before becoming ready" >&2
      cat "${STDOUT_LOG}" "${LOG_FILE}" >&2 2>/dev/null || true
      exit 1
    fi
    sleep 0.1
  done
  echo "the server did not become ready" >&2
  cat "${STDOUT_LOG}" "${LOG_FILE}" >&2 2>/dev/null || true
  exit 1
}

gono() {
  "${BIN}" --config "${CONFIG_FILE}" "$@"
}

# Runs `app-password add` and prints the value of its `App password: <value>` line.
mint_app_password() {
  local output password
  output="$(gono app-password add "$@" 2>&1)"
  password="$(printf '%s\n' "${output}" | sed -n 's/^App password: \([^[:space:]]*\)$/\1/p' | tail -n 1)"
  if [[ -z "${password}" ]]; then
    echo "app-password add did not print a password for: $*" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  echo "${password}"
}

echo "==> building gono-cloud (target dir: ${TARGET_DIR})"
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --quiet --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p gono-server --bin gono-cloud
BIN="${TARGET_DIR}/debug/gono-cloud"

PORT="$(find_port)"
BASE_URL="http://127.0.0.1:${PORT}"

cat >"${CONFIG_FILE}" <<EOF
[server]
bind = "127.0.0.1:${PORT}"
base_url = "${BASE_URL}"

[storage]
data_dir = "${WORK_DIR}/data"

[db]
path = "${WORK_DIR}/gono-cloud.db"

[logging]
level = "warn"
file = "${LOG_FILE}"
EOF

WEB_PASSWORD="$(random_password)"
USER2_WEB_PASSWORD="$(random_password)"

echo "==> initializing a fresh installation in ${WORK_DIR}"
printf '%s\n' "${WEB_PASSWORD}" | gono init --admin gono --password-stdin >/dev/null
printf '%s\n' "${USER2_WEB_PASSWORD}" | gono user add alice --password-stdin >/dev/null

echo "==> minting credentials"
PASSWORD="$(mint_app_password gono --label acceptance-full)"
VIEW_PASSWORD="$(mint_app_password gono --label acceptance-view --scope /=/:view)"
SCOPED_PASSWORD="$(mint_app_password gono --label acceptance-scoped \
  --scope /acc-view=/acc-scope/view:view \
  --scope /acc-full=/acc-scope/full:full)"
USER2_PASSWORD="$(mint_app_password alice --label acceptance-full)"

echo "==> starting gono-cloud on ${BASE_URL}"
# Started directly (not through the `gono` function) so that $! is the server itself.
"${BIN}" --config "${CONFIG_FILE}" serve >"${STDOUT_LOG}" 2>&1 &
SERVER_PID="$!"
wait_for_server

export GONO_ACCEPT_BASE_URL="${BASE_URL}"
export GONO_ACCEPT_USER="gono"
export GONO_ACCEPT_PASSWORD="${PASSWORD}"
export GONO_ACCEPT_VIEW_PASSWORD="${VIEW_PASSWORD}"
export GONO_ACCEPT_SCOPED_PASSWORD="${SCOPED_PASSWORD}"
export GONO_ACCEPT_WEB_PASSWORD="${WEB_PASSWORD}"
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
  echo "==> gono-cloud is running; load the credentials with:"
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
echo "==> summary"
echo "passed:  $(printf '%s\n' "${PASSED}" | sed '/^$/d' | wc -l | tr -d ' ') (skipped inside: ${SKIPPED})"
echo "failed:  $(printf '%s\n' "${FAILED}" | sed '/^$/d' | wc -l | tr -d ' ')"
if [[ -n "${UNEXPECTED_FAILURES}" ]]; then
  echo "unexpected failures (not in new-expected-failures.txt):"
  printf '  %s\n' ${UNEXPECTED_FAILURES}
  STATUS=1
fi
if [[ -n "${UNEXPECTED_PASSES}" ]]; then
  echo "expected failures that passed (remove them from new-expected-failures.txt):"
  printf '  %s\n' ${UNEXPECTED_PASSES}
  STATUS=1
fi
if [[ "${CARGO_STATUS}" != "0" && -z "${FAILED}" ]]; then
  echo "cargo test failed without reporting test failures (build error?)"
  STATUS=1
fi
if [[ "${STATUS}" == "0" ]]; then
  echo "all failures match new-expected-failures.txt"
fi

if [[ "${RUN_LITMUS}" == "1" ]]; then
  LITMUS_BIN="${LITMUS:-$(command -v litmus || true)}"
  if [[ -z "${LITMUS_BIN}" || ! -x "${LITMUS_BIN}" ]]; then
    echo "==> RUN_LITMUS=1 but litmus is not installed"
    STATUS=1
  else
    LITMUS_URL="${BASE_URL}/remote.php/dav/files/gono/"
    echo "==> running litmus against ${LITMUS_URL}"
    if ! (cd "${WORK_DIR}" && "${LITMUS_BIN}" "${LITMUS_URL}" gono "${PASSWORD}"); then
      echo "litmus reported failures"
      STATUS=1
    fi
  fi
fi

exit "${STATUS}"
