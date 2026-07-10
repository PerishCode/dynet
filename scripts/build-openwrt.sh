#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${DYNET_MUSL_BUILD_IMAGE:-rust:1.96-bookworm}"
target="x86_64-unknown-linux-musl"
output="target/${target}/release/dynet"

docker run --rm \
  --env "HOST_UID=$(id -u)" \
  --env "HOST_GID=$(id -g)" \
  --volume "${root}:/work" \
  --workdir /work \
  "${image}" \
  bash -ceu '
    cleanup() {
      chown -R "${HOST_UID}:${HOST_GID}" /work/target 2>/dev/null || true
    }
    trap cleanup EXIT
    export DEBIAN_FRONTEND=noninteractive
    export CARGO_HOME=/work/target/openwrt-cargo-home
    apt-get update
    apt-get install -y --no-install-recommends musl-tools perl make ca-certificates
    rustup target add x86_64-unknown-linux-musl
    cargo build --locked --release --target x86_64-unknown-linux-musl --bin dynet
  '

file "${root}/${output}"
printf '%s\n' "${root}/${output}"
