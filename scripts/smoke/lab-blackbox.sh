#!/usr/bin/env bash
set -euo pipefail

CONTROL_URL="${DYNET_LAB_CONTROL_URL:-http://127.0.0.1:9977}"
GUEST_CONTROL_URL="${DYNET_LAB_GUEST_CONTROL_URL:-http://192.168.5.2:9977}"
VM="${DYNET_LAB_VM:-dynet-lab}"
DOMAINS="${DYNET_LAB_DOMAINS:-example.com example.org}"
TCP_URLS="${DYNET_LAB_TCP_URLS:-http://example.com/ http://example.org/}"
UDP_HOST="${DYNET_LAB_UDP_HOST:-1.1.1.1}"
UDP_PORT="${DYNET_LAB_UDP_PORT:-443}"
REQUIRE_UDP="${DYNET_LAB_REQUIRE_UDP:-1}"
EXPECT_TCP_GROUPS="${DYNET_LAB_EXPECT_TCP_GROUPS:-}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

validate_config() {
  if ! [[ "${UDP_PORT}" =~ ^[1-9][0-9]*$ ]]; then
    echo "DYNET_LAB_UDP_PORT must be a positive integer" >&2
    exit 1
  fi
  if (( UDP_PORT > 65535 )); then
    echo "DYNET_LAB_UDP_PORT must be <= 65535" >&2
    exit 1
  fi
  if [[ "${REQUIRE_UDP}" != "0" && "${REQUIRE_UDP}" != "1" ]]; then
    echo "DYNET_LAB_REQUIRE_UDP must be 0 or 1" >&2
    exit 1
  fi
}

event_count() {
  EVENTS_JSON="$(curl -fsS "${CONTROL_URL}/api/v1/events")" python3 - <<'PY'
import json
import os

payload = json.loads(os.environ["EVENTS_JSON"])
print(len(payload.get("events", [])))
PY
}

check_events() {
  EVENTS_JSON="$(curl -fsS "${CONTROL_URL}/api/v1/events")" \
    python3 - "${BASELINE_EVENTS}" "${DOMAINS}" "${TCP_URLS}" "${REQUIRE_UDP}" "${EXPECT_TCP_GROUPS}" <<'PY'
import json
import os
import sys
from urllib.parse import urlparse

baseline = int(sys.argv[1])
domains = [domain.rstrip(".").lower() for domain in sys.argv[2].split()]
tcp_hosts = [
    urlparse(url).hostname.rstrip(".").lower()
    for url in sys.argv[3].split()
    if urlparse(url).hostname
]
require_udp = sys.argv[4] == "1"
expect_tcp_groups = sys.argv[5]

payload = json.loads(os.environ["EVENTS_JSON"])
events = payload.get("events", [])[baseline:]

def fields(event):
    return event.get("fields", {})

def kind(event):
    return event.get("kind")

missing_dns = []
for domain in domains:
    if not any(
        kind(event) in {"dns-query", "dns-response"}
        and fields(event).get("queryName", "").rstrip(".").lower() == domain
        for event in events
    ):
        missing_dns.append(domain)

missing_tcp = []
for host in tcp_hosts:
    if not any(
        kind(event) == "tcp-accept"
        and fields(event).get("inbound") == "socks5"
        and fields(event).get("targetDomain", "").rstrip(".").lower() == host
        and fields(event).get("sessionId")
        and fields(event).get("nodeId")
        for event in events
    ):
        missing_tcp.append(host)

if expect_tcp_groups and not any(
    kind(event) == "tcp-accept"
    and fields(event).get("inbound") == "socks5"
    and fields(event).get("selectionGroups") == expect_tcp_groups
    for event in events
):
    missing_tcp.append(f"selectionGroups={expect_tcp_groups}")

missing = []
if missing_dns:
    missing.append("DNS query/response for " + ", ".join(missing_dns))
if missing_tcp:
    missing.append("SOCKS5 TCP accept for " + ", ".join(missing_tcp))
if require_udp and not any(
    kind(event) == "udp-datagram"
    and fields(event).get("inbound") == "socks5"
    and fields(event).get("sessionId")
    and fields(event).get("nodeId")
    for event in events
):
    missing.append("SOCKS5 UDP datagram")
if not any(
    kind(event) == "dns-response"
    and fields(event).get("answerIps")
    for event in events
):
    missing.append("DNS response with answer IPs")

if missing:
    raise SystemExit("missing expected lab events: " + "; ".join(missing))
PY
}

wait_for_events() {
  local last_error=""
  for _ in $(seq 1 30); do
    if last_error="$(check_events 2>&1)"; then
      return 0
    fi
    sleep 0.2
  done
  echo "${last_error}" >&2
  return 1
}

vm_dns() {
  local domain="$1"
  limactl shell "${VM}" getent hosts "${domain}" >/dev/null
}

vm_tcp() {
  local url="$1"
  limactl shell "${VM}" curl -fsS --max-time 10 "${url}" >/dev/null
}

vm_udp() {
  limactl shell "${VM}" env DYNET_UDP_HOST="${UDP_HOST}" DYNET_UDP_PORT="${UDP_PORT}" bash -lc \
      'printf dynet-lab-udp >"/dev/udp/${DYNET_UDP_HOST}/${DYNET_UDP_PORT}"'
}

require_cmd curl
require_cmd limactl
require_cmd python3
validate_config

curl -fsS "${CONTROL_URL}/api/v1/health" >/dev/null
limactl shell "${VM}" curl -fsS --max-time 5 "${GUEST_CONTROL_URL}/api/v1/health" >/dev/null

BASELINE_EVENTS="$(event_count)"

for domain in ${DOMAINS}; do
  vm_dns "${domain}"
done

for url in ${TCP_URLS}; do
  vm_tcp "${url}"
done

if [[ "${REQUIRE_UDP}" == "1" ]]; then
  vm_udp
fi
wait_for_events

echo "lab blackbox smoke passed"
