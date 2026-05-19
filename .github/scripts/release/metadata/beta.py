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
USER_AGENT = "dynet-release-beta/1.0"

STABLE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
BETA_RE = re.compile(r"^v?(\d+\.\d+\.\d+)-beta\.([1-9][0-9]*)$")


def fail(message: str) -> None:
    print(f"[release-beta] {message}", file=sys.stderr)
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


def parse_beta(value: str, source: str) -> tuple[str, int, str]:
    match = BETA_RE.match(value)
    if match is None:
        fail(f"{source} must look like vX.Y.Z-beta.N, got {value}")
    base_version = match.group(1)
    beta_number = int(match.group(2))
    return base_version, beta_number, f"v{base_version}-beta.{beta_number}"


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
        fail(f"failed to fetch R2 beta metadata: {error}")
        return None, None


def fetch_optional_text(url: str) -> str | None:
    text, code = _try_fetch(url)
    if text is not None:
        return text
    if code == 403:
        fail("R2 beta metadata returned HTTP 403; permission errors must not be treated as missing metadata")
    if code == 404:
        print(
            f"[release-beta] R2 beta metadata returned 404; retrying after "
            f"{BOOTSTRAP_404_RETRY_SECONDS}s to confirm absence"
        )
        time.sleep(BOOTSTRAP_404_RETRY_SECONDS)
        text, code = _try_fetch(url)
        if text is not None:
            return text
        if code == 403:
            fail("R2 beta metadata returned HTTP 403 on retry; refusing to bootstrap on permission error")
        if code == 404:
            return None
    fail(f"failed to fetch R2 beta metadata: HTTP {code}")
    return None


def read_metadata_beta(metadata: dict[str, object]) -> tuple[str, int, str]:
    value = metadata.get("betaVersion") or metadata.get("releaseVersion")
    if isinstance(value, str) and value:
        return parse_beta(value, "R2 beta metadata")

    base_version = metadata.get("baseVersion")
    beta_number = metadata.get("betaNumber")
    if isinstance(base_version, str) and isinstance(beta_number, int):
        version_tuple(base_version)
        if beta_number < 1:
            fail(f"R2 beta metadata betaNumber must be >= 1, got {beta_number}")
        return base_version, beta_number, f"v{base_version}-beta.{beta_number}"

    fail("R2 beta metadata must include betaVersion or releaseVersion")


def next_beta(cargo_version: str) -> tuple[str, int, str, str]:
    public_url = os.environ.get("DYNET_RELEASES_PUBLIC_URL", "").rstrip("/")
    metadata_url = os.environ.get("DYNET_BETA_METADATA_URL")
    if not metadata_url:
        if not public_url:
            fail("DYNET_RELEASES_PUBLIC_URL is required")
        metadata_url = f"{public_url}/beta/latest/metadata.json"

    print(f"[release-beta] metadata url: {metadata_url}")
    text = fetch_optional_text(metadata_url)
    if text is None:
        print("[release-beta] R2 beta metadata not found; starting beta.1")
        return cargo_version, 1, f"v{cargo_version}-beta.1", "missing R2 beta metadata"

    try:
        metadata = json.loads(text)
    except json.JSONDecodeError as error:
        fail(f"R2 beta metadata is invalid JSON: {error}")
    if not isinstance(metadata, dict):
        fail("R2 beta metadata must be a JSON object")

    base_version, beta_number, beta_version = read_metadata_beta(metadata)
    ordering = (version_tuple(cargo_version) > version_tuple(base_version)) - (
        version_tuple(cargo_version) < version_tuple(base_version)
    )
    if ordering < 0:
        fail(f"Cargo version {cargo_version} regressed below beta base {base_version}")
    if ordering > 0:
        return cargo_version, 1, f"v{cargo_version}-beta.1", "R2 beta metadata base advanced"
    return cargo_version, beta_number + 1, f"v{cargo_version}-beta.{beta_number + 1}", (
        f"R2 beta metadata {beta_version}"
    )


def main() -> None:
    cargo_version = read_cargo_version()
    override = os.environ.get("BETA_VERSION_OVERRIDE", "").strip()
    if override:
        base_version, beta_number, beta_version = parse_beta(override, "BETA_VERSION_OVERRIDE")
        if base_version != cargo_version:
            fail(f"override base {base_version} does not match Cargo version {cargo_version}")
        state_source = "workflow override"
    else:
        base_version, beta_number, beta_version, state_source = next_beta(cargo_version)

    print("[release-beta] channel: beta")
    print(f"[release-beta] base version: {base_version}")
    print(f"[release-beta] beta number: {beta_number}")
    print(f"[release-beta] beta version: {beta_version}")
    print(f"[release-beta] state source: {state_source}")

    output("base_version", base_version)
    output("beta_number", str(beta_number))
    output("beta_version", beta_version)
    output("release_version", beta_version)
    output("state_source", state_source)


if __name__ == "__main__":
    main()
