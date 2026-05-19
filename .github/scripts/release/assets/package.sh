#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)
APP_DIR="$ROOT/crates/dynet-cli"
NAME=dynet
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$APP_DIR/Cargo.toml" | head -n 1)
RELEASE_VERSION=${1:-${RELEASE_VERSION:-v$VERSION}}
TARGET=${TARGET:-$(rustc -Vv | sed -n 's/^host: //p')}
DIST_DIR=${DIST_DIR:-"$ROOT/dist"}
ARTIFACT_DIR="$DIST_DIR/$RELEASE_VERSION"

mkdir -p "$ARTIFACT_DIR"

if [ -n "${TARGET:-}" ]; then
  DYNET_BUILD_VERSION="$RELEASE_VERSION" cargo build --release --locked -p dynet-cli --target "$TARGET"
  BIN="$ROOT/target/$TARGET/release/$NAME"
else
  DYNET_BUILD_VERSION="$RELEASE_VERSION" cargo build --release --locked -p dynet-cli
  BIN="$ROOT/target/release/$NAME"
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT TERM

cp "$BIN" "$tmpdir/$NAME"
chmod +x "$tmpdir/$NAME"

archive="$NAME-$TARGET.tar.gz"
tar -C "$tmpdir" -czf "$ARTIFACT_DIR/$archive" "$NAME"

printf '%s\n' "$ARTIFACT_DIR/$archive"
