#!/usr/bin/env sh
set -eu

RELEASE_VERSION=${1:-}
ARTIFACT_DIR=${2:-}

[ -n "$RELEASE_VERSION" ] || { printf '%s\n' 'missing release version' >&2; exit 1; }
[ -n "$ARTIFACT_DIR" ] || { printf '%s\n' 'missing artifact dir' >&2; exit 1; }
[ -d "$ARTIFACT_DIR" ] || { printf 'artifact dir missing: %s\n' "$ARTIFACT_DIR" >&2; exit 1; }

(
  cd "$ARTIFACT_DIR"
  printf 'VERSION: %s\n' "$RELEASE_VERSION" > checksums.txt
  for file in dynet-*.tar.gz dynet-*.zip; do
    [ -f "$file" ] || continue
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$file" >> checksums.txt
    else
      shasum -a 256 "$file" >> checksums.txt
    fi
  done
)
