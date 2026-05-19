#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)
VERSION=${1:-}
CHANNEL=${2:-stable}

[ -n "$VERSION" ] || { printf '%s\n' 'missing release version' >&2; exit 1; }
[ -n "${DYNET_RELEASES_PUBLIC_URL:-}" ] || { printf '%s\n' 'DYNET_RELEASES_PUBLIC_URL is required' >&2; exit 1; }

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT TERM

export HOME="$tmpdir/home"
export DYNET_INSTALL_ROOT="$tmpdir/install"
export DYNET_LOCAL_BIN_DIR="$tmpdir/bin"
mkdir -p "$HOME" "$DYNET_INSTALL_ROOT" "$DYNET_LOCAL_BIN_DIR"

sh "$ROOT/install.sh" install --channel "$CHANNEL" --version "$VERSION"
"$DYNET_LOCAL_BIN_DIR/dynet" --version
"$DYNET_LOCAL_BIN_DIR/dynet" check --root "$ROOT" --config "$ROOT/dynet.json"

if [ "${SMOKE_LATEST:-}" = "1" ]; then
  rm -f "$DYNET_LOCAL_BIN_DIR/dynet"
  rm -rf "$DYNET_INSTALL_ROOT/latest-smoke"
  sh "$ROOT/install.sh" install --channel "$CHANNEL" --install-root "$DYNET_INSTALL_ROOT/latest-smoke"
  "$DYNET_LOCAL_BIN_DIR/dynet" --version
  "$DYNET_LOCAL_BIN_DIR/dynet" check --root "$ROOT" --config "$ROOT/dynet.json"
fi
