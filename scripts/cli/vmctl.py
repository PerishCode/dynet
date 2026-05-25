#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
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
    "probe-smoke": VM_PATH / "probe_smoke.py",
    "quality-gap-smoke": VM_PATH / "smokes" / "quality_gap.py",
    "smoke": VM_PATH / "smoke.py",
    "snapshot": VM_PATH / "snapshot.py",
}


def print_help() -> None:
    print("usage: uv --project scripts run python -m scripts.cli.vmctl <command> [args...]")
    print()
    print("commands:")
    for name in sorted(COMMANDS):
        print(f"  {name}")
    print()
    print("examples:")
    print("  uv --project scripts run python -m scripts.cli.vmctl image catalog")
    print("  uv --project scripts run python -m scripts.cli.vmctl image --host fuisp list")
    print("  uv --project scripts run python -m scripts.cli.vmctl guest --host fuisp status")


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
    local_paths = os.pathsep.join([str(ROOT), str(VM_PATH)])
    env["PYTHONPATH"] = (
        local_paths if not python_path else local_paths + os.pathsep + python_path
    )
    return subprocess.run([sys.executable, str(script), *argv[1:]], env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
