#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


BOOTSTRAP_404_RETRY_SECONDS = 15
USER_AGENT = "dynet-release-stable/1.0"

STABLE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
TAGGED_STABLE_RE = re.compile(r"^v?(\d+\.\d+\.\d+)$")


def fail(message: str) -> None:
    print(f"[release-stable] {message}", file=sys.stderr)
    raise SystemExit(1)


def version_tuple(value: str) -> tuple[int, int, int]:
    match = STABLE_RE.match(value)
    if match is None:
        fail(f"expected stable x.y.z version, got {value}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def read_cargo_version() -> str:
    cargo_toml = Path("crates/dynet-cli/Cargo.toml")
    match = re.search(r'^version = "([^"]+)"$', cargo_toml.read_text(encoding="utf-8"), re.M)
    if match is None:
        fail(f"missing version in {cargo_toml}")
    version = match.group(1)
    version_tuple(version)
    return version


def parse_stable(value: str, source: str) -> str:
    match = TAGGED_STABLE_RE.match(value)
    if match is None:
        fail(f"{source} must look like vX.Y.Z, got {value}")
    return match.group(1)


def output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def _try_fetch(url: str) -> tuple[str | None, int | None]:
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode("utf-8"), None
    except urllib.error.HTTPError as error:
        return None, error.code
    except urllib.error.URLError as error:
        fail(f"failed to fetch R2 stable metadata: {error}")
        return None, None


def fetch_optional_text(url: str) -> str | None:
    text, code = _try_fetch(url)
    if text is not None:
        return text
    if code == 403:
        fail("R2 stable metadata returned HTTP 403; permission errors must not be treated as missing metadata")
    if code == 404:
        print(
            f"[release-stable] R2 stable metadata returned 404; retrying after "
            f"{BOOTSTRAP_404_RETRY_SECONDS}s to confirm absence"
        )
        time.sleep(BOOTSTRAP_404_RETRY_SECONDS)
        text, code = _try_fetch(url)
        if text is not None:
            return text
        if code == 403:
            fail("R2 stable metadata returned HTTP 403 on retry; refusing to bootstrap on permission error")
        if code == 404:
            return None
    fail(f"failed to fetch R2 stable metadata: HTTP {code}")
    return None


def read_metadata_stable(metadata: dict[str, object]) -> str:
    value = metadata.get("stableVersion") or metadata.get("releaseVersion")
    if isinstance(value, str) and value:
        return parse_stable(value, "R2 stable metadata")

    base_version = metadata.get("baseVersion")
    if isinstance(base_version, str):
        version_tuple(base_version)
        return base_version

    fail("R2 stable metadata must include stableVersion, releaseVersion, or baseVersion")


def next_stable(cargo_version: str) -> tuple[str, str, str]:
    public_url = os.environ.get("DYNET_RELEASES_PUBLIC_URL", "").rstrip("/")
    metadata_url = os.environ.get("DYNET_STABLE_METADATA_URL")
    if not metadata_url:
        if not public_url:
            fail("DYNET_RELEASES_PUBLIC_URL is required")
        metadata_url = f"{public_url}/stable/latest/metadata.json"

    print(f"[release-stable] metadata url: {metadata_url}")
    text = fetch_optional_text(metadata_url)
    if text is None:
        print(f"[release-stable] R2 stable metadata not found; releasing first stable v{cargo_version}")
        return cargo_version, f"v{cargo_version}", "missing R2 stable metadata"

    try:
        metadata = json.loads(text)
    except json.JSONDecodeError as error:
        fail(f"R2 stable metadata is invalid JSON: {error}")
    if not isinstance(metadata, dict):
        fail("R2 stable metadata must be a JSON object")

    prior_version = read_metadata_stable(metadata)
    ordering = (version_tuple(cargo_version) > version_tuple(prior_version)) - (
        version_tuple(cargo_version) < version_tuple(prior_version)
    )
    if ordering < 0:
        fail(f"Cargo version {cargo_version} regressed below prior stable {prior_version}")
    if ordering == 0:
        fail(
            f"Cargo version {cargo_version} matches the prior stable; bump "
            f"crates/dynet-cli/Cargo.toml before re-running"
        )
    return cargo_version, f"v{cargo_version}", f"R2 stable metadata v{prior_version}"


def main() -> None:
    cargo_version = read_cargo_version()
    override = os.environ.get("STABLE_VERSION_OVERRIDE", "").strip()
    if override:
        base_version = parse_stable(override, "STABLE_VERSION_OVERRIDE")
        if base_version != cargo_version:
            fail(f"override base {base_version} does not match Cargo version {cargo_version}")
        release_version = f"v{base_version}"
        state_source = "workflow override"
    else:
        base_version, release_version, state_source = next_stable(cargo_version)

    print("[release-stable] channel: stable")
    print(f"[release-stable] base version: {base_version}")
    print(f"[release-stable] release version: {release_version}")
    print(f"[release-stable] state source: {state_source}")

    output("base_version", base_version)
    output("release_version", release_version)
    output("state_source", state_source)


if __name__ == "__main__":
    main()
