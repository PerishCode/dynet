#!/usr/bin/env sh
set -eu

COMMAND=${1:-install}
[ $# -gt 0 ] && shift || true

CHANNEL=${DYNET_CHANNEL:-stable}
VERSION=${DYNET_VERSION:-}
PUBLIC_URL=${DYNET_RELEASES_PUBLIC_URL:-}
INSTALL_ROOT=${DYNET_INSTALL_ROOT:-"$HOME/.local/share/dynet"}
LOCAL_BIN_DIR=${DYNET_LOCAL_BIN_DIR:-"$HOME/.local/bin"}

while [ $# -gt 0 ]; do
  case "$1" in
    --channel)
      CHANNEL=${2:-}
      [ -n "$CHANNEL" ] || { echo "--channel requires a value" >&2; exit 1; }
      shift 2
      ;;
    --channel=*)
      CHANNEL=${1#--channel=}
      shift
      ;;
    --version)
      VERSION=${2:-}
      [ -n "$VERSION" ] || { echo "--version requires a value" >&2; exit 1; }
      shift 2
      ;;
    --version=*)
      VERSION=${1#--version=}
      shift
      ;;
    --public-url)
      PUBLIC_URL=${2:-}
      [ -n "$PUBLIC_URL" ] || { echo "--public-url requires a value" >&2; exit 1; }
      shift 2
      ;;
    --public-url=*)
      PUBLIC_URL=${1#--public-url=}
      shift
      ;;
    --install-root)
      INSTALL_ROOT=${2:-}
      [ -n "$INSTALL_ROOT" ] || { echo "--install-root requires a value" >&2; exit 1; }
      shift 2
      ;;
    --install-root=*)
      INSTALL_ROOT=${1#--install-root=}
      shift
      ;;
    --bin-dir)
      LOCAL_BIN_DIR=${2:-}
      [ -n "$LOCAL_BIN_DIR" ] || { echo "--bin-dir requires a value" >&2; exit 1; }
      shift 2
      ;;
    --bin-dir=*)
      LOCAL_BIN_DIR=${1#--bin-dir=}
      shift
      ;;
    -h|--help|help)
      cat <<'EOF'
dynet installer

Usage:
  install.sh install [--channel stable|beta] [--version vX.Y.Z] [--public-url <url>]
  install.sh upgrade [--channel stable|beta] [--version vX.Y.Z] [--public-url <url>]
  install.sh uninstall

Environment:
  DYNET_RELEASES_PUBLIC_URL
  DYNET_CHANNEL
  DYNET_VERSION
  DYNET_INSTALL_ROOT
  DYNET_LOCAL_BIN_DIR
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

need_public_url() {
  [ -n "$PUBLIC_URL" ] || {
    echo "DYNET_RELEASES_PUBLIC_URL or --public-url is required" >&2
    exit 1
  }
  PUBLIC_URL=${PUBLIC_URL%/}
}

platform_archive() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64) echo "dynet-x86_64-unknown-linux-gnu.tar.gz" ;;
    Darwin:arm64|Darwin:aarch64) echo "dynet-aarch64-apple-darwin.tar.gz" ;;
    Darwin:x86_64|Darwin:amd64) echo "dynet-x86_64-apple-darwin.tar.gz" ;;
    *) echo "unsupported platform: $os $arch" >&2; exit 1 ;;
  esac
}

latest_version() {
  metadata="$1"
  sed -n 's/.*"releaseVersion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$metadata" | head -n 1
}

install_dynet() {
  need_public_url
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  if [ -z "$VERSION" ]; then
    curl -fsSL "$PUBLIC_URL/$CHANNEL/latest/metadata.json" -o "$tmpdir/metadata.json"
    VERSION=$(latest_version "$tmpdir/metadata.json")
    [ -n "$VERSION" ] || { echo "failed to resolve latest dynet version" >&2; exit 1; }
  fi

  archive=$(platform_archive)
  archive_url="$PUBLIC_URL/$CHANNEL/versions/$VERSION/$archive"
  mkdir -p "$INSTALL_ROOT/$VERSION" "$LOCAL_BIN_DIR"
  curl -fsSL "$archive_url" -o "$tmpdir/$archive"
  tar -xzf "$tmpdir/$archive" -C "$INSTALL_ROOT/$VERSION"
  chmod +x "$INSTALL_ROOT/$VERSION/dynet"

  link="$LOCAL_BIN_DIR/dynet"
  rm -f "$link"
  ln -s "$INSTALL_ROOT/$VERSION/dynet" "$link"
  "$link" --version
  printf 'installed dynet to %s\n' "$link"
}

uninstall_dynet() {
  rm -f "$LOCAL_BIN_DIR/dynet"
  printf 'removed %s\n' "$LOCAL_BIN_DIR/dynet"
}

case "$COMMAND" in
  install|upgrade) install_dynet ;;
  uninstall) uninstall_dynet ;;
  *)
    echo "unknown command: $COMMAND" >&2
    exit 1
    ;;
esac
