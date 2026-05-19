#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {
    "capture": ROOT / "scripts" / "vm" / "capture.py",
    "check": ROOT / "scripts" / "vm" / "check.py",
    "cleanup": ROOT / "scripts" / "vm" / "cleanup.py",
    "collect": ROOT / "scripts" / "vm" / "collect.py",
    "image": ROOT / "scripts" / "vm" / "image.py",
    "guest": ROOT / "scripts" / "vm" / "guest.py",
    "setup": ROOT / "scripts" / "vm" / "setup.py",
    "net": ROOT / "scripts" / "vm" / "net.py",
    "snapshot": ROOT / "scripts" / "vm" / "snapshot.py",
}


def print_help() -> None:
    print("usage: python3 scripts/vmctl.py <command> [args...]")
    print()
    print("commands:")
    for name in sorted(COMMANDS):
        print(f"  {name}")
    print()
    print("examples:")
    print("  python3 scripts/vmctl.py image catalog")
    print("  python3 scripts/vmctl.py image --host fuisp list")
    print("  python3 scripts/vmctl.py guest --host fuisp status")


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print_help()
        return 0
    command = argv[0]
    script = COMMANDS.get(command)
    if script is None:
        print(f"unknown vm command: {command}", file=sys.stderr)
        print_help()
        return 2
    return subprocess.run([sys.executable, str(script), *argv[1:]]).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
