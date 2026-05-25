from __future__ import annotations

import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def scripts_root() -> Path:
    return Path(__file__).resolve().parents[1]


def add_path(path: Path) -> None:
    raw = str(path)
    if raw not in sys.path:
        sys.path.insert(0, raw)


def add_experiments_path() -> None:
    add_path(scripts_root() / "experiments")


def add_vm_path() -> None:
    add_path(scripts_root() / "vm")
