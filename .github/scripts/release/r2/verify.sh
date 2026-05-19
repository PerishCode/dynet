#!/usr/bin/env bash
set -euo pipefail

for name in DYNET_RELEASES_PUBLIC_URL RELEASE_CHANNEL RELEASE_VERSION R2_METADATA_URL RUNNER_TEMP; do
  if [ -z "${!name:-}" ]; then
    echo "$name is required" >&2
    exit 1
  fi
done

metadata="$RUNNER_TEMP/dynet-release-metadata.json"
curl -fsSL "$R2_METADATA_URL?run=${GITHUB_RUN_ID:-local}" -o "$metadata"

DOWNLOADED_METADATA="$metadata" \
EXPECTED_CHANNEL="$RELEASE_CHANNEL" \
EXPECTED_RELEASE_VERSION="$RELEASE_VERSION" \
python3 <<'PY'
import json
import os
from pathlib import Path

metadata = json.loads(Path(os.environ["DOWNLOADED_METADATA"]).read_text(encoding="utf-8"))
if metadata["channel"] != os.environ["EXPECTED_CHANNEL"]:
    raise SystemExit(f"unexpected channel: {metadata['channel']}")
if metadata["releaseVersion"] != os.environ["EXPECTED_RELEASE_VERSION"]:
    raise SystemExit(f"unexpected releaseVersion: {metadata['releaseVersion']}")
if metadata["channel"] == "beta":
    if metadata.get("betaVersion") != os.environ["EXPECTED_RELEASE_VERSION"]:
        raise SystemExit(f"unexpected betaVersion: {metadata.get('betaVersion')}")
    base_version = metadata.get("baseVersion")
    beta_number = metadata.get("betaNumber")
    if not isinstance(base_version, str) or not base_version:
        raise SystemExit("missing baseVersion")
    if not isinstance(beta_number, int):
        raise SystemExit("missing betaNumber")
    if f"v{base_version}-beta.{beta_number}" != os.environ["EXPECTED_RELEASE_VERSION"]:
        raise SystemExit("beta metadata does not reconstruct expected release version")
for key, item in metadata["artifacts"].items():
    if not item.get("url"):
        raise SystemExit(f"missing artifact url for {key}")
PY

for url in $(python3 - "$metadata" <<'PY'
import json
import sys
from pathlib import Path
metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in metadata["artifacts"].values():
    print(item["url"])
print(metadata["install"]["unix"])
print(metadata["install"]["windows"])
PY
); do
  curl -fsSI "$url" >/dev/null
done
