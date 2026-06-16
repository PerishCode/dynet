#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${ROOT}/target/dynet-ingress-smoke.log"
CONFIG="${ROOT}/target/dynet-ingress-smoke.toml"
RUNTIME_DB="${ROOT}/target/dynet-ingress-smoke.sqlite"
TCP_HOST="${DYNET_SMOKE_TCP_HOST:-baidu.com}"
TCP_PORT="${DYNET_SMOKE_TCP_PORT:-80}"
TCP_CONCURRENCY="${DYNET_SMOKE_TCP_CONCURRENCY:-10}"
TCP_CONCURRENCY_LIMIT=1000
DNS_NAMES="${DYNET_SMOKE_DNS_NAMES:-example.com}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

wait_for_health() {
  for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:9977/api/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "dynet control plane did not become healthy" >&2
  return 1
}

stop_dynet() {
  if [[ -n "${DYNET_PID:-}" ]]; then
    kill "${DYNET_PID}" >/dev/null 2>&1 || true
    wait "${DYNET_PID}" >/dev/null 2>&1 || true
    unset DYNET_PID
  fi
}

resolve_ipv4() {
  local host="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short A "$host" | awk 'NF { print; exit }'
  elif command -v drill >/dev/null 2>&1; then
    drill A "$host" | awk '/^[^;].*IN[[:space:]]+A[[:space:]]+/ { print $5; exit }'
  else
    python3 - "$host" <<'PY'
import socket
import sys

for family, _, _, _, sockaddr in socket.getaddrinfo(sys.argv[1], None, socket.AF_INET):
    if family == socket.AF_INET:
        print(sockaddr[0])
        break
PY
  fi
}

cleanup() {
  stop_dynet
}
trap cleanup EXIT

validate_concurrency() {
  if ! [[ "${TCP_CONCURRENCY}" =~ ^[1-9][0-9]*$ ]]; then
    echo "DYNET_SMOKE_TCP_CONCURRENCY must be a positive integer" >&2
    exit 1
  fi
  if (( TCP_CONCURRENCY > TCP_CONCURRENCY_LIMIT )); then
    echo "DYNET_SMOKE_TCP_CONCURRENCY must be <= ${TCP_CONCURRENCY_LIMIT}" >&2
    exit 1
  fi
}

run_dns_smoke() {
  if command -v dig >/dev/null 2>&1; then
    for name in ${DNS_NAMES}; do
      dig @127.0.0.1 -p 1053 "${name}" A +time=2 +tries=1 >/dev/null
    done
  elif command -v drill >/dev/null 2>&1; then
    for name in ${DNS_NAMES}; do
      drill @127.0.0.1 -p 1053 "${name}" A >/dev/null
    done
  else
    echo "skipping DNS smoke: dig or drill is required" >&2
  fi
}

run_tcp_smoke() {
  local failures=0
  local pids=()
  for index in $(seq 1 "${TCP_CONCURRENCY}"); do
    curl -fsS --max-time 5 -H "Host: ${TCP_HOST}" "http://127.0.0.1:18080/" >/dev/null &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    if ! wait "${pid}"; then
      failures=1
    fi
  done
  if [[ "${failures}" -ne 0 ]]; then
    echo "TCP smoke failed for ${TCP_HOST}:${TCP_PORT}" >&2
    return 1
  fi
  if [[ "${#pids[@]}" -ne "${TCP_CONCURRENCY}" ]]; then
    echo "TCP smoke did not start expected concurrency" >&2
    return 1
  fi
}

run_udp_smoke() {
  if command -v nc >/dev/null 2>&1; then
    printf 'udp-smoke' | nc -u -w 1 127.0.0.1 18443 >/dev/null 2>&1 || true
    UDP_CHECKED=1
  else
    echo "skipping UDP datagram smoke: nc is required" >&2
    UDP_CHECKED=0
  fi
}

run_socks5_smoke() {
  curl -fsS --max-time 5 --socks5-hostname 127.0.0.1:1080 "http://${TCP_HOST}/" >/dev/null
}

write_config() {
  cat >"${CONFIG}" <<EOF
[ingress.tcp]
upstream = "${TCP_IP}:${TCP_PORT}"

[outbound]
type = "direct"
EOF
}

validate_events() {
  EVENTS_JSON="$(curl -fsS "http://127.0.0.1:9977/api/v1/events")"
  EVENTS_JSON="${EVENTS_JSON}" python3 - "${UDP_CHECKED}" "${TCP_CONCURRENCY}" <<'PY'
import json
import os
import sys

payload = json.loads(os.environ["EVENTS_JSON"])
events = payload.get("events", [])
kinds = {event.get("kind") for event in events}
required = {"dns-query", "tcp-accept", "tcp-close"}
if sys.argv[1] == "1":
    required.add("udp-datagram")
missing = sorted(required - kinds)
if missing:
    raise SystemExit(f"missing expected ingress events: {', '.join(missing)}")
if not any(event.get("kind") == "dns-response" and event.get("fields", {}).get("answerIps") for event in events):
    raise SystemExit("missing DNS answer IP sniff result")
tcp_accepts = [
    event for event in events
    if event.get("kind") == "tcp-accept"
    and event.get("fields", {}).get("sessionId")
    and event.get("fields", {}).get("inbound") == "tcp"
    and event.get("fields", {}).get("outbound") == "direct"
    and event.get("fields", {}).get("targetIp")
    and event.get("fields", {}).get("upstreamIp")
]
if not tcp_accepts:
    raise SystemExit("missing TCP inbound/outbound session fields")
expected_tcp = int(sys.argv[2])
if len(tcp_accepts) < expected_tcp:
    raise SystemExit(f"expected at least {expected_tcp} TCP accept events, got {len(tcp_accepts)}")
tcp_sessions = {event.get("fields", {}).get("sessionId") for event in tcp_accepts}
if len(tcp_sessions) < expected_tcp:
    raise SystemExit(f"expected at least {expected_tcp} TCP sessions, got {len(tcp_sessions)}")
if not any(
    event.get("kind") == "tcp-accept"
    and event.get("fields", {}).get("sessionId")
    and event.get("fields", {}).get("inbound") == "socks5"
    and event.get("fields", {}).get("outbound") == "direct"
    and event.get("fields", {}).get("targetIp")
    for event in events
):
    raise SystemExit("missing SOCKS5 TCP session fields")
if sys.argv[1] == "1" and not any(
    event.get("kind") == "udp-datagram"
    and event.get("fields", {}).get("sessionId")
    and event.get("fields", {}).get("inbound") == "udp"
    and event.get("fields", {}).get("outbound") == "direct"
    and event.get("fields", {}).get("targetIp")
    and event.get("fields", {}).get("upstreamIp")
    for event in events
):
    raise SystemExit("missing UDP inbound/outbound session fields")
PY
}

require_cmd cargo
require_cmd curl
require_cmd python3
validate_concurrency

TCP_IP="$(resolve_ipv4 "${TCP_HOST}")"
if [[ -z "${TCP_IP}" ]]; then
  echo "failed to resolve ${TCP_HOST}" >&2
  exit 1
fi
curl -fsS --max-time 5 --connect-to "${TCP_HOST}:${TCP_PORT}:${TCP_IP}:${TCP_PORT}" "http://${TCP_HOST}/" >/dev/null

write_config
rm -f "${RUNTIME_DB}" "${RUNTIME_DB}-shm" "${RUNTIME_DB}-wal"
DYNET_RUNTIME_DB="${RUNTIME_DB}" "${CARGO:-cargo}" run --locked -p dynet-cli -- --config "${CONFIG}" >"${LOG}" 2>&1 &
DYNET_PID="$!"
wait_for_health

run_dns_smoke
run_tcp_smoke
run_udp_smoke
run_socks5_smoke
validate_events

echo "ingress smoke passed"
