#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${ROOT}/target/dynet-ingress-smoke.log"
TCP_HOST="${DYNET_SMOKE_TCP_HOST:-baidu.com}"
TCP_PORT="${DYNET_SMOKE_TCP_PORT:-80}"

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
  if [[ -n "${DYNET_PID:-}" ]]; then
    kill "${DYNET_PID}" >/dev/null 2>&1 || true
    wait "${DYNET_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_cmd cargo
require_cmd curl
require_cmd python3

TCP_IP="$(resolve_ipv4 "${TCP_HOST}")"
if [[ -z "${TCP_IP}" ]]; then
  echo "failed to resolve ${TCP_HOST}" >&2
  exit 1
fi
curl -fsS --max-time 5 --connect-to "${TCP_HOST}:${TCP_PORT}:${TCP_IP}:${TCP_PORT}" "http://${TCP_HOST}/" >/dev/null

DYNET_TCP_UPSTREAM="${TCP_IP}:${TCP_PORT}" "${CARGO:-cargo}" run --locked -p dynet-cli >"${LOG}" 2>&1 &
DYNET_PID="$!"
wait_for_health

if command -v dig >/dev/null 2>&1; then
  dig @127.0.0.1 -p 1053 example.com A +time=2 +tries=1 >/dev/null
elif command -v drill >/dev/null 2>&1; then
  drill @127.0.0.1 -p 1053 example.com A >/dev/null
else
  echo "skipping DNS smoke: dig or drill is required" >&2
fi

curl -fsS --max-time 5 -H "Host: ${TCP_HOST}" "http://127.0.0.1:18080/" >/dev/null

if command -v nc >/dev/null 2>&1; then
  printf 'udp-smoke' | nc -u -w 1 127.0.0.1 18443 >/dev/null 2>&1 || true
  UDP_CHECKED=1
else
  echo "skipping UDP datagram smoke: nc is required" >&2
  UDP_CHECKED=0
fi

EVENTS_JSON="$(curl -fsS "http://127.0.0.1:9977/api/v1/events")"
EVENTS_JSON="${EVENTS_JSON}" python3 - "${UDP_CHECKED}" <<'PY'
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
PY
echo "ingress smoke passed"
