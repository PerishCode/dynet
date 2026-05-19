#!/usr/bin/env sh
set -eu

MODE=${1:-}
RELEASE_VERSION=${2:-}
ARTIFACT_DIR=${3:-}

[ -n "$MODE" ] || { printf '%s\n' 'missing mode' >&2; exit 1; }
[ -n "$RELEASE_VERSION" ] || { printf '%s\n' 'missing release version' >&2; exit 1; }
[ -n "$ARTIFACT_DIR" ] || { printf '%s\n' 'missing artifact dir' >&2; exit 1; }
[ -d "$ARTIFACT_DIR" ] || { printf 'artifact dir missing: %s\n' "$ARTIFACT_DIR" >&2; exit 1; }

require_file() {
  [ -f "$ARTIFACT_DIR/$1" ] || { printf 'missing artifact: %s\n' "$1" >&2; exit 1; }
}

require_checksum_entry() {
  python3 - "$ARTIFACT_DIR/checksums.txt" "$1" <<'PY'
import pathlib
import sys

checksums = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
name = sys.argv[2]
for line in checksums[1:]:
    parts = line.split()
    if len(parts) >= 2 and parts[-1] == name:
        sys.exit(0)
sys.exit(1)
PY
}

check_archive_members() {
  python3 - "$ARTIFACT_DIR" <<'PY'
import pathlib
import sys
import tarfile
import zipfile

root = pathlib.Path(sys.argv[1])

def ensure_tar_contains(name, member):
    with tarfile.open(root / name, "r:gz") as tar:
        names = tar.getnames()
    if member not in names:
        raise SystemExit(f"missing {member} in {name}")

def ensure_zip_contains(name, member):
    with zipfile.ZipFile(root / name) as zf:
        names = zf.namelist()
    if member not in names:
        raise SystemExit(f"missing {member} in {name}")

ensure_tar_contains("dynet-x86_64-unknown-linux-gnu.tar.gz", "dynet")
ensure_tar_contains("dynet-aarch64-apple-darwin.tar.gz", "dynet")
ensure_tar_contains("dynet-x86_64-apple-darwin.tar.gz", "dynet")
ensure_zip_contains("dynet-x86_64-pc-windows-msvc.zip", "dynet.exe")
PY
}

case "$MODE" in
  accept)
    require_file checksums.txt
    require_file dynet-x86_64-unknown-linux-gnu.tar.gz
    require_file dynet-aarch64-apple-darwin.tar.gz
    require_file dynet-x86_64-apple-darwin.tar.gz
    require_file dynet-x86_64-pc-windows-msvc.zip
    version_line=$(sed -n 's/^VERSION: *//p' "$ARTIFACT_DIR/checksums.txt" | head -n 1)
    [ "$version_line" = "$RELEASE_VERSION" ] || {
      printf 'version mismatch: expected %s got %s\n' "$RELEASE_VERSION" "$version_line" >&2
      exit 1
    }
    for asset in \
      dynet-x86_64-unknown-linux-gnu.tar.gz \
      dynet-aarch64-apple-darwin.tar.gz \
      dynet-x86_64-apple-darwin.tar.gz \
      dynet-x86_64-pc-windows-msvc.zip
    do
      require_checksum_entry "$asset" || {
        printf 'missing checksum entry: %s\n' "$asset" >&2
        exit 1
      }
    done
    ;;
  verify)
    check_archive_members
    ;;
  *)
    printf 'unknown mode: %s\n' "$MODE" >&2
    exit 1
    ;;
esac
