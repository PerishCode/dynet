#!/usr/bin/env bash
set -euo pipefail

CONTROL_URL="${DYNET_LAB_CONTROL_URL:-http://127.0.0.1:9977}"
GUEST_CONTROL_URL="${DYNET_LAB_GUEST_CONTROL_URL:-http://192.168.5.2:9977}"
VM="${DYNET_LAB_VM:-dynet-lab}"
URLS="${DYNET_LAB_PLAYWRIGHT_URLS:-https://example.com/ https://example.org/ https://www.iana.org/}"
OUTPUT_DIR="${DYNET_LAB_PLAYWRIGHT_OUTPUT_DIR:-/tmp/dynet-playwright-lab}"
TIMEOUT_MS="${DYNET_LAB_PLAYWRIGHT_TIMEOUT_MS:-30000}"
WAIT_MS="${DYNET_LAB_PLAYWRIGHT_WAIT_MS:-1000}"
SETTLE_SECONDS="${DYNET_LAB_PLAYWRIGHT_SETTLE_SECONDS:-2}"
EXPECT_GROUPS="${DYNET_LAB_PLAYWRIGHT_EXPECT_GROUPS:-}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

event_id() {
  CONTROL_URL="${CONTROL_URL}" python3 - <<'PY'
import json
import os
import urllib.request

with urllib.request.urlopen(os.environ["CONTROL_URL"] + "/api/v1/events") as response:
    payload = json.load(response)
print(max((event.get("id", 0) for event in payload.get("events", [])), default=0))
PY
}

safe_name() {
  URL="$1" python3 - <<'PY'
import os
import re
from urllib.parse import urlparse

url = os.environ["URL"]
parsed = urlparse(url)
host = parsed.hostname or "page"
path = parsed.path.strip("/").replace("/", "_")
name = host if not path else f"{host}_{path}"
print(re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "page")
PY
}

analyze_observability() {
  CONTROL_URL="${CONTROL_URL}" BASELINE_ID="${BASELINE_ID}" URLS="${URLS}" \
    EXPECT_GROUPS="${EXPECT_GROUPS}" python3 - <<'PY'
import json
import os
from urllib.parse import urlparse
import urllib.request

control_url = os.environ["CONTROL_URL"]
baseline_id = int(os.environ["BASELINE_ID"])
urls = os.environ["URLS"].split()
hosts = [urlparse(url).hostname.rstrip(".").lower() for url in urls if urlparse(url).hostname]
expect_groups = os.environ["EXPECT_GROUPS"]

def fetch(path):
    with urllib.request.urlopen(control_url + path) as response:
        return json.load(response)

events = [
    event for event in fetch("/api/v1/events").get("events", [])
    if event.get("id", 0) > baseline_id
]
sessions = fetch("/api/v1/observability/sessions").get("sessions", [])
shadows = fetch("/api/v1/observability/matrix-shadow").get("decisions", [])

event_session_ids = {
    int(fields["sessionId"])
    for event in events
    for fields in [event.get("fields", {})]
    if fields.get("sessionId", "").isdigit()
}
sessions = [session for session in sessions if session.get("sessionId") in event_session_ids]
shadow_ids = {shadow.get("sessionId") for shadow in shadows}

summary = {
    "baselineEventId": baseline_id,
    "newEventCount": len(events),
    "newSessionCount": len(sessions),
    "hosts": [],
}
missing = []

for host in hosts:
    host_events = []
    for event in events:
        fields = event.get("fields", {})
        query_name = fields.get("queryName", "").rstrip(".").lower()
        target_domain = fields.get("targetDomain", "").rstrip(".").lower()
        if query_name == host or target_domain == host:
            host_events.append(event)

    host_sessions = [
        session for session in sessions
        if (session.get("targetDomain") or "").rstrip(".").lower() == host
    ]
    groups = sorted({
        session.get("selectionGroups")
        for session in host_sessions
        if session.get("selectionGroups")
    })
    errors = [
        {"sessionId": session.get("sessionId"), "error": session.get("error")}
        for session in host_sessions
        if session.get("error")
    ]
    if not host_sessions:
        missing.append(f"{host}: no observed traffic session")
    if expect_groups and any(session.get("selectionGroups") != expect_groups for session in host_sessions):
        missing.append(f"{host}: selectionGroups not uniformly {expect_groups}")

    summary["hosts"].append({
        "host": host,
        "dnsEvents": sum(1 for event in host_events if event.get("kind", "").startswith("dns-")),
        "tcpEvents": sum(1 for event in host_events if event.get("kind", "").startswith("tcp-")),
        "sessionIds": [session.get("sessionId") for session in host_sessions],
        "selectionGroups": groups,
        "clientToUpstreamBytes": sum(session.get("clientToUpstreamBytes") or 0 for session in host_sessions),
        "upstreamToClientBytes": sum(session.get("upstreamToClientBytes") or 0 for session in host_sessions),
        "errors": errors,
        "hasMatrixShadow": all(session.get("sessionId") in shadow_ids for session in host_sessions),
    })

print(json.dumps(summary, indent=2, sort_keys=True))
if missing:
    raise SystemExit("missing expected Playwright observability: " + "; ".join(missing))
PY
}

require_cmd curl
require_cmd limactl
require_cmd python3

curl -fsS "${CONTROL_URL}/api/v1/health" >/dev/null
limactl shell "${VM}" curl -fsS --max-time 5 "${GUEST_CONTROL_URL}/api/v1/health" >/dev/null
limactl shell "${VM}" playwright --version >/dev/null
limactl shell "${VM}" mkdir -p "${OUTPUT_DIR}"

BASELINE_ID="$(event_id)"

for url in ${URLS}; do
  name="$(safe_name "${url}")"
  limactl shell "${VM}" playwright screenshot \
    --browser=chromium \
    --timeout "${TIMEOUT_MS}" \
    --wait-for-timeout "${WAIT_MS}" \
    "${url}" \
    "${OUTPUT_DIR}/${name}.png"
done

sleep "${SETTLE_SECONDS}"
analyze_observability
echo "lab playwright smoke passed"
