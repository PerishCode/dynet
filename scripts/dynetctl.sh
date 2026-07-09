#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_BIN="${ROOT}/target/debug/dynet"
BIN="${DYNETCTL_BIN:-${DEFAULT_BIN}}"
CONFIG="${DYNETCTL_CONFIG:-${ROOT}/dynet.toml}"
RUNTIME_DB="${DYNET_RUNTIME_DB:-${ROOT}/target/dynet-user-sim.sqlite}"
RUN_DIR="${DYNETCTL_RUN_DIR:-${ROOT}/.tmp/run}"
LOG_DIR="${DYNETCTL_LOG_DIR:-${ROOT}/.tmp/logs}"
PID_FILE="${DYNETCTL_PID_FILE:-${RUN_DIR}/dynetctl.pid}"
LOG_FILE="${DYNETCTL_LOG_FILE:-${LOG_DIR}/dynetctl.log}"
NOFILE_LIMIT="${DYNETCTL_NOFILE:-4096}"
STAMP="${DYNETCTL_STAMP:-dynetctl:$(printf '%s' "${ROOT}" | cksum | awk '{print $1}')}"
STAMP_ARG="--process-stamp=${STAMP}"
CONTROL_BIND=""
SOCKS5_BIND=""

usage() {
  cat <<'EOF'
Usage: scripts/dynetctl.sh <command>

Commands:
  start      Start dynet in the background.
  stop       Stop the stamped dynet process.
  restart    Stop, then start.
  status     Show process, health, and listener status.
  log [N]    Show the last N log lines. Defaults to 120.
  log -f     Follow the log.

Environment:
  DYNETCTL_CONFIG     Config path. Default: ./dynet.toml
  DYNET_RUNTIME_DB    Runtime DB path. Default: ./target/dynet-user-sim.sqlite
  DYNETCTL_BIN        dynet binary path. Default: ./target/debug/dynet
  DYNETCTL_STAMP      Process argv stamp. Default: dynetctl:<repo hash>
  DYNETCTL_LOG_DIR    Log directory. Default: ./.tmp/logs
  DYNETCTL_LOG_FILE   Log path. Default: ./.tmp/logs/dynetctl.log
  DYNETCTL_PID_FILE   PID cache. Default: ./.tmp/run/dynetctl.pid
  DYNETCTL_NOFILE     Open-file soft limit for dynet. Default: 4096
EOF
}

section_value() {
  local section="$1"
  local key="$2"
  local fallback="$3"
  if [[ ! -f "${CONFIG:-}" ]]; then
    printf '%s\n' "${fallback}"
    return
  fi
  awk -v section="${section}" -v key="${key}" -v fallback="${fallback}" '
    BEGIN { in_section = 0; value = fallback }
    /^\[/ {
      in_section = ($0 == "[" section "]")
      next
    }
    in_section && $1 == key {
      line = $0
      sub(/^[^=]*=[[:space:]]*/, "", line)
      sub(/[[:space:]]*#.*/, "", line)
      gsub(/^"|"$/, "", line)
      value = line
      exit
    }
    END { print value }
  ' "${CONFIG}"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

detach_dynet() {
  perl -MPOSIX=setsid -e '
    my ($bin, $config, $stamp_arg, $runtime_db, $log_file) = @ARGV;
    defined(my $pid = fork) or die "fork failed: $!\n";
    if ($pid) {
      print "$pid\n";
      exit 0;
    }
    setsid() or die "setsid failed: $!\n";
    open STDIN, "<", "/dev/null" or die "open /dev/null failed: $!\n";
    open STDOUT, ">>", $log_file or die "open log failed: $!\n";
    open STDERR, ">&", \*STDOUT or die "redirect stderr failed: $!\n";
    $ENV{DYNET_RUNTIME_DB} = $runtime_db;
    exec { $bin } $bin, "--config", $config, $stamp_arg;
    die "exec failed: $!\n";
  ' "${BIN}" "${CONFIG}" "${STAMP_ARG}" "${RUNTIME_DB}" "${LOG_FILE}"
}

health_url() {
  printf 'http://%s/api/v1/health\n' "${CONTROL_BIND}"
}

ensure_binary() {
  if [[ -x "${BIN}" && "${BIN}" != "${DEFAULT_BIN}" ]]; then
    return
  fi

  require_cmd cargo
  if [[ ! -x "${BIN}" ]]; then
    echo "dynet binary not found at ${BIN}; building..."
    cargo build --locked -p dynet-cli
    return
  fi

  if find "${ROOT}/Cargo.toml" "${ROOT}/Cargo.lock" "${ROOT}/crates" \
    \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) \
    -type f -newer "${BIN}" -print -quit | grep -q .; then
    echo "dynet binary is stale; building..."
    cargo build --locked -p dynet-cli
  fi
}

is_running() {
  local pid="$1"
  [[ "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" >/dev/null 2>&1
}

pid_command() {
  local pid="$1"
  ps -p "${pid}" -o command= 2>/dev/null || true
}

pid_matches_stamp() {
  local pid="$1"
  local command
  is_running "${pid}" || return 1
  command="$(pid_command "${pid}")"
  [[ "${command}" == *"${BIN}"* && "${command}" == *"${STAMP_ARG}"* ]]
}

pid_from_file() {
  [[ -f "${PID_FILE}" ]] || return 1
  local pid
  pid="$(tr -d '[:space:]' <"${PID_FILE}")"
  pid_matches_stamp "${pid}" || return 1
  printf '%s\n' "${pid}"
}

stamp_pids() {
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -f -- "${STAMP_ARG}" 2>/dev/null | while read -r pid; do
      [[ "${pid}" != "$$" ]] && printf '%s\n' "${pid}"
    done
    return
  fi
  ps -axo pid=,command= | awk -v stamp="${STAMP_ARG}" -v self="$$" '
    index($0, stamp) {
      pid = $1
      if (pid != self) print pid
    }
  '
}

current_pid() {
  local pid
  while read -r pid; do
    if pid_matches_stamp "${pid}"; then
      printf '%s\n' "${pid}"
      return 0
    fi
  done < <(stamp_pids)

  if pid="$(pid_from_file)"; then
    printf '%s\n' "${pid}"
    return 0
  fi
  return 1
}

listener_pids() {
  local bind="$1"
  local host="${bind%:*}"
  local port="${bind##*:}"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP@"${host}:${port}" -sTCP:LISTEN -t 2>/dev/null | sort -u
  fi
}

check_listener_available() {
  local bind="$1"
  local label="$2"
  local pids
  pids="$(listener_pids "${bind}" || true)"
  if [[ -n "${pids}" ]]; then
    echo "${label} listener ${bind} is already in use by pid(s): ${pids}" >&2
    exit 1
  fi
}

wait_for_health() {
  local url
  url="$(health_url)"
  for _ in $(seq 1 80); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "dynet did not become healthy at ${url}" >&2
  return 1
}

start_cmd() {
  mkdir -p "${RUN_DIR}" "${LOG_DIR}" "$(dirname "${RUNTIME_DB}")"

  local pid
  if pid="$(current_pid)"; then
    echo "dynet already running: pid=${pid} stamp=${STAMP}"
    status_cmd
    return
  fi
  rm -f "${PID_FILE}"

  if [[ ! -f "${CONFIG}" ]]; then
    echo "missing config: ${CONFIG}" >&2
    exit 1
  fi

  require_cmd curl
  require_cmd perl
  ensure_binary
  check_listener_available "${CONTROL_BIND}" "control"
  check_listener_available "${SOCKS5_BIND}" "socks5"
  ulimit -n "${NOFILE_LIMIT}" || {
    echo "failed to set open-file limit to ${NOFILE_LIMIT}" >&2
    exit 1
  }

  {
    echo "=== dynet start $(date '+%Y-%m-%d %H:%M:%S %Z') ==="
    echo "stamp=${STAMP}"
    echo "config=${CONFIG}"
    echo "runtime_db=${RUNTIME_DB}"
    echo "control=${CONTROL_BIND}"
    echo "socks5=${SOCKS5_BIND}"
    echo "nofile=$(ulimit -n)"
  } >>"${LOG_FILE}"

  pid="$(detach_dynet)"
  printf '%s\n' "${pid}" >"${PID_FILE}"

  if ! wait_for_health; then
    echo "startup failed; recent log:" >&2
    tail -n 80 "${LOG_FILE}" >&2 || true
    exit 1
  fi

  sleep 0.2
  if ! is_running "${pid}"; then
    echo "dynet exited after startup; recent log:" >&2
    tail -n 80 "${LOG_FILE}" >&2 || true
    exit 1
  fi

  echo "dynet started: pid=${pid}"
  echo "stamp=${STAMP}"
  echo "health=$(health_url)"
  echo "socks5=${SOCKS5_BIND}"
  echo "log=${LOG_FILE}"
}

stop_cmd() {
  local pid
  if ! pid="$(current_pid)"; then
    rm -f "${PID_FILE}"
    echo "dynet is not running"
    return
  fi

  kill "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 50); do
    if ! is_running "${pid}"; then
      rm -f "${PID_FILE}"
      echo "dynet stopped: pid=${pid}"
      return
    fi
    sleep 0.1
  done

  echo "dynet did not stop after SIGTERM; sending SIGKILL" >&2
  kill -9 "${pid}" >/dev/null 2>&1 || true
  rm -f "${PID_FILE}"
}

status_cmd() {
  local pid=""
  if pid="$(current_pid)"; then
    echo "process: running pid=${pid}"
  else
    echo "process: stopped"
  fi

  echo "stamp: ${STAMP}"
  echo "config: ${CONFIG}"
  echo "runtime_db: ${RUNTIME_DB}"
  echo "log: ${LOG_FILE}"
  echo "control: ${CONTROL_BIND}"
  echo "socks5: ${SOCKS5_BIND}"

  if curl -fsS "$(health_url)" >/dev/null 2>&1; then
    echo "health: ok"
  else
    echo "health: unavailable"
  fi

  if command -v lsof >/dev/null 2>&1; then
    echo "listeners:"
    lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk -v c="${CONTROL_BIND##*:}" -v s="${SOCKS5_BIND##*:}" '
      $9 ~ ":" c "$" || $9 ~ ":" s "$" { print "  " $1, $2, $9 }
    '
  fi
}

log_cmd() {
  local lines="${1:-120}"
  mkdir -p "${LOG_DIR}"
  touch "${LOG_FILE}"
  if [[ "${lines}" == "-f" || "${lines}" == "--follow" ]]; then
    tail -n 120 -f "${LOG_FILE}"
    return
  fi
  if ! [[ "${lines}" =~ ^[0-9]+$ ]]; then
    echo "log line count must be a positive integer or -f" >&2
    exit 1
  fi
  tail -n "${lines}" "${LOG_FILE}"
}

CONTROL_BIND="${DYNET_CONTROL_BIND:-$(section_value control bind "127.0.0.1:9977")}"
SOCKS5_BIND="${DYNET_SOCKS5_BIND:-$(section_value ingress.socks5 bind "127.0.0.1:11080")}"

cmd="${1:-}"
case "${cmd}" in
  start)
    start_cmd
    ;;
  stop)
    stop_cmd
    ;;
  restart)
    stop_cmd
    start_cmd
    ;;
  status)
    status_cmd
    ;;
  log)
    shift
    log_cmd "${1:-120}"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
