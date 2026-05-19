#!/usr/bin/env bash
set -euo pipefail

for name in DYNET_RELEASES_S3_AK DYNET_RELEASES_S3_SK DYNET_RELEASES_S3_BUCKET DYNET_RELEASES_S3_URL DYNET_RELEASES_PUBLIC_URL RELEASE_CHANNEL RELEASE_VERSION RELEASE_ROOT GITHUB_OUTPUT GITHUB_REPOSITORY GITHUB_SHA GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_WORKFLOW GITHUB_WORKSPACE; do
  if [ -z "${!name:-}" ]; then
    echo "$name is required" >&2
    exit 1
  fi
done

release_root="$RELEASE_ROOT"
public_url="${DYNET_RELEASES_PUBLIC_URL%/}"
version_prefix="$RELEASE_CHANNEL/versions/$RELEASE_VERSION"
latest_prefix="$RELEASE_CHANNEL/latest"
metadata_path="$release_root/metadata.json"

upload() {
  local file_path="$1"
  local object_key="$2"
  local content_type="$3"
  local cache_control="$4"
  if [ ! -f "$file_path" ]; then
    echo "expected upload file not found: $file_path" >&2
    exit 1
  fi
  AWS_ACCESS_KEY_ID="$DYNET_RELEASES_S3_AK" \
  AWS_SECRET_ACCESS_KEY="$DYNET_RELEASES_S3_SK" \
  AWS_DEFAULT_REGION=auto \
  AWS_EC2_METADATA_DISABLED=true \
  aws --endpoint-url "${DYNET_RELEASES_S3_URL%/}" s3api put-object \
    --bucket "$DYNET_RELEASES_S3_BUCKET" \
    --key "$object_key" \
    --body "$file_path" \
    --content-type "$content_type" \
    --cache-control "$cache_control" \
    --no-cli-pager >/dev/null
}

artifact_content_type() {
  case "$1" in
    *.tar.gz) printf '%s' "application/gzip" ;;
    *.zip) printf '%s' "application/zip" ;;
    *.json) printf '%s' "application/json; charset=utf-8" ;;
    *.txt) printf '%s' "text/plain; charset=utf-8" ;;
    *.sh) printf '%s' "text/x-shellscript; charset=utf-8" ;;
    *.ps1) printf '%s' "text/plain; charset=utf-8" ;;
    *) printf '%s' "application/octet-stream" ;;
  esac
}

for file_path in "$release_root"/dynet-*.tar.gz "$release_root"/dynet-*.zip "$release_root"/checksums.txt; do
  [ -f "$file_path" ] || continue
  name="$(basename "$file_path")"
  upload "$file_path" "$version_prefix/$name" "$(artifact_content_type "$name")" "public, max-age=31536000, immutable"
done

upload "$GITHUB_WORKSPACE/install.sh" "$version_prefix/install.sh" "text/x-shellscript; charset=utf-8" "public, max-age=31536000, immutable"
upload "$GITHUB_WORKSPACE/install.ps1" "$version_prefix/install.ps1" "text/plain; charset=utf-8" "public, max-age=31536000, immutable"
upload "$GITHUB_WORKSPACE/install.sh" "$latest_prefix/install.sh" "text/x-shellscript; charset=utf-8" "public, max-age=60, must-revalidate"
upload "$GITHUB_WORKSPACE/install.ps1" "$latest_prefix/install.ps1" "text/plain; charset=utf-8" "public, max-age=60, must-revalidate"

PUBLIC_URL="$public_url" \
VERSION_PREFIX="$version_prefix" \
LATEST_PREFIX="$latest_prefix" \
RELEASE_ROOT="$release_root" \
METADATA_PATH="$metadata_path" \
python3 <<'PY'
import json
import os
import re
from pathlib import Path

env = os.environ
root = Path(env["RELEASE_ROOT"])
public_url = env["PUBLIC_URL"]
version_prefix = env["VERSION_PREFIX"]
latest_prefix = env["LATEST_PREFIX"]

def artifact(name, content_type):
    path = root / name
    if not path.is_file():
        raise SystemExit(f"missing metadata source file: {path}")
    return {
        "contentType": content_type,
        "name": name,
        "size": path.stat().st_size,
        "url": f"{public_url}/{version_prefix}/{name}",
    }

metadata = {
    "version": 1,
    "channel": env["RELEASE_CHANNEL"],
    "releaseVersion": env["RELEASE_VERSION"],
    "generatedAt": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z"),
    "github": {
        "repository": env["GITHUB_REPOSITORY"],
        "commit": env["GITHUB_SHA"],
        "runId": int(env["GITHUB_RUN_ID"]),
        "runAttempt": int(env["GITHUB_RUN_ATTEMPT"]),
        "workflow": env["GITHUB_WORKFLOW"],
    },
    "r2": {
        "publicUrl": public_url,
        "latestMetadataUrl": f"{public_url}/{latest_prefix}/metadata.json",
        "versionMetadataUrl": f"{public_url}/{version_prefix}/metadata.json",
        "versionPrefix": version_prefix,
        "latestPrefix": latest_prefix,
    },
    "install": {
        "unix": f"{public_url}/{latest_prefix}/install.sh",
        "windows": f"{public_url}/{latest_prefix}/install.ps1",
    },
    "artifacts": {
        "linuxX64": artifact("dynet-x86_64-unknown-linux-gnu.tar.gz", "application/gzip"),
        "macArm64": artifact("dynet-aarch64-apple-darwin.tar.gz", "application/gzip"),
        "macX64": artifact("dynet-x86_64-apple-darwin.tar.gz", "application/gzip"),
        "winX64": artifact("dynet-x86_64-pc-windows-msvc.zip", "application/zip"),
        "checksums": artifact("checksums.txt", "text/plain; charset=utf-8"),
    },
}

if env["RELEASE_CHANNEL"] == "beta":
    match = re.match(r"^v?(\d+\.\d+\.\d+)-beta\.([1-9][0-9]*)$", env["RELEASE_VERSION"])
    if not match:
        raise SystemExit(f"invalid beta release version: {env['RELEASE_VERSION']}")
    base_version = env.get("BASE_VERSION") or match.group(1)
    beta_number = int(env.get("BETA_NUMBER") or match.group(2))
    if base_version != match.group(1):
        raise SystemExit(f"beta base mismatch: {base_version} != {match.group(1)}")
    if beta_number != int(match.group(2)):
        raise SystemExit(f"beta number mismatch: {beta_number} != {match.group(2)}")
    metadata["baseVersion"] = base_version
    metadata["betaNumber"] = beta_number
    metadata["betaVersion"] = env["RELEASE_VERSION"]
    metadata["stateSource"] = env.get("STATE_SOURCE") or "workflow input"

Path(env["METADATA_PATH"]).write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
PY

upload "$metadata_path" "$version_prefix/metadata.json" "application/json; charset=utf-8" "public, max-age=31536000, immutable"
upload "$metadata_path" "$latest_prefix/metadata.json" "application/json; charset=utf-8" "public, max-age=60, must-revalidate"

{
  echo "metadata_url=$public_url/$latest_prefix/metadata.json"
  echo "version_metadata_url=$public_url/$version_prefix/metadata.json"
  echo "version_prefix=$version_prefix"
} >> "$GITHUB_OUTPUT"
