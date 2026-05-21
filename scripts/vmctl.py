#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VM_PATH = ROOT / "scripts" / "vm"
COMMANDS = {
    "capture": VM_PATH / "ops" / "capture.py",
    "check": VM_PATH / "ops" / "check.py",
    "cleanup": VM_PATH / "ops" / "cleanup.py",
    "collect": VM_PATH / "ops" / "collect.py",
    "dev": VM_PATH / "ops" / "dev.py",
    "image": VM_PATH / "image.py",
    "guest": VM_PATH / "guest.py",
    "setup": VM_PATH / "setup.py",
    "net": VM_PATH / "net.py",
    "private-probe": VM_PATH / "private_probe.py",
    "private-runtime": VM_PATH / "private_runtime.py",
    "smoke": VM_PATH / "smoke.py",
    "snapshot": VM_PATH / "snapshot.py",
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
    env = os.environ.copy()
    python_path = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(VM_PATH) if not python_path else str(VM_PATH) + os.pathsep + python_path
    )
    return subprocess.run([sys.executable, str(script), *argv[1:]], env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
