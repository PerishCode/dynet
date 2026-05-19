#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise SystemExit(f"missing required tool: {name}")


def require_path(path: str) -> None:
    candidate = ROOT / path
    if not candidate.exists():
        raise SystemExit(f"missing required path: {candidate}")


def main() -> None:
    require_tool("cargo")
    require_tool("rustc")
    require_path("Cargo.toml")
    require_path("crates/dynet-cli/Cargo.toml")
    require_path("crates/dynet-core/Cargo.toml")
    require_path("scripts/vmctl.py")
    require_path("scripts/vm/capture.py")
    require_path("scripts/vm/check.py")
    require_path("scripts/vm/cleanup.py")
    require_path("scripts/vm/collect.py")
    require_path("scripts/vm/dev.py")
    require_path("scripts/vm/image.py")
    require_path("scripts/vm/net.py")
    require_path("scripts/vm/guest.py")
    require_path("scripts/vm/smoke.py")
    require_path("scripts/vm/snapshot.py")
    require_path("scripts/vm/setup.py")
    require_path("install.sh")
    require_path("install.ps1")

    subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    print("dynet checkout is ready")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
