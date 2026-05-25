#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import posixpath
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HOST = os.environ.get("DYNET_LAB_HOST", "fuisp")
DEFAULT_LAB_ROOT = os.environ.get("DYNET_LAB_ROOT", "/home/dynet-lab")
DEFAULT_VM_USER = os.environ.get("DYNET_VM_USER", "ubuntu")
DEFAULT_LOG_LEVEL = os.environ.get("DYNET_VM_LOG_LEVEL", "info")
LOCAL_LAB_ROOT = ROOT / "dist" / "lab"
SSH_BASE_OPTS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=8")
GUEST_SSH_OPTS = (
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=8",
    "-o",
    "StrictHostKeyChecking=accept-new",
)
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
logger = logging.getLogger("dynet.vm")
_LOG_LEVELS = {
    "error": logging.ERROR,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "trace": logging.DEBUG,
}


def selected_log_level(level: str | None = None, *, verbose: bool = False) -> str:
    level_name = (level or DEFAULT_LOG_LEVEL).lower()
    if verbose and level is None:
        level_name = "debug"
    if level_name == "warn":
        level_name = "warning"
    if level_name not in _LOG_LEVELS:
        choices = ", ".join(["error", "warning", "info", "debug", "trace"])
        raise CommandError(f"unsupported log level: {level_name}; expected {choices}")
    return level_name


def _install_logger(level: int) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def configure_logging(level: str | None = None, *, verbose: bool = False) -> None:
    try:
        level_name = selected_log_level(level, verbose=verbose)
    except CommandError:
        _install_logger(logging.ERROR)
        raise
    log_level = _LOG_LEVELS[level_name]
    _install_logger(log_level)


def vmctl_command(*args: str) -> list[str]:
    return [sys.executable, "-m", "scripts.cli.vmctl", *args]


@dataclass(frozen=True)
class CloudImage:
    name: str
    url: str
    filename: str
    osinfo: str
    default_user: str
    note: str


IMAGE_CATALOG: dict[str, CloudImage] = {
    "ubuntu-24.04": CloudImage(
        name="ubuntu-24.04",
        url=(
            "https://mirrors.tuna.tsinghua.edu.cn/ubuntu-cloud-images/noble/current/"
            "noble-server-cloudimg-amd64.img"
        ),
        filename="ubuntu-24.04-noble-server-cloudimg-amd64.img",
        osinfo="ubuntu22.04",
        default_user="ubuntu",
        note="Ubuntu 24.04 LTS generic cloud image; osinfo falls back to ubuntu22.04 on Debian 12 libosinfo.",
    ),
    "debian-12": CloudImage(
        name="debian-12",
        url=(
            "https://cloud.debian.org/images/cloud/bookworm/latest/"
            "debian-12-genericcloud-amd64.qcow2"
        ),
        filename="debian-12-genericcloud-amd64.qcow2",
        osinfo="debian12",
        default_user="debian",
        note="Debian 12 genericcloud image.",
    ),
}


class CommandError(Exception):
    pass


@dataclass(frozen=True)
class ResourceLimit:
    warn_bytes: int
    fail_bytes: int
    warn_files: int | None = None
    fail_files: int | None = None


@dataclass(frozen=True)
class ResourceStat:
    label: str
    path: str
    bytes: int
    files: int
    dirs: int


GiB = 1024**3

RESOURCE_LIMITS: dict[str, ResourceLimit] = {
    "images": ResourceLimit(12 * GiB, 40 * GiB, warn_files=12, fail_files=40),
    "vms": ResourceLimit(120 * GiB, 400 * GiB, warn_files=60, fail_files=200),
    "seed": ResourceLimit(2 * GiB, 8 * GiB, warn_files=200, fail_files=1000),
    "incoming": ResourceLimit(8 * GiB, 40 * GiB, warn_files=100, fail_files=500),
    "collect": ResourceLimit(8 * GiB, 40 * GiB, warn_files=500, fail_files=5000),
    "pcap": ResourceLimit(8 * GiB, 40 * GiB, warn_files=200, fail_files=1000),
    "local-collect": ResourceLimit(4 * GiB, 16 * GiB, warn_files=200, fail_files=1000),
    "local-pcap": ResourceLimit(4 * GiB, 16 * GiB, warn_files=200, fail_files=1000),
    "cargo-target": ResourceLimit(20 * GiB, 80 * GiB, warn_files=100000, fail_files=400000),
}


def validate_name(value: str, label: str = "name") -> str:
    if not SAFE_NAME.match(value):
        raise CommandError(
            f"invalid {label}: {value!r}; use letters, digits, '_', '-', or '.'"
        )
    return value


def format_bytes(value: int) -> str:
    if value >= GiB:
        return f"{value / GiB:.1f} GiB"
    mib = 1024**2
    if value >= mib:
        return f"{value / mib:.1f} MiB"
    kib = 1024
    if value >= kib:
        return f"{value / kib:.1f} KiB"
    return f"{value} B"


def normalize_remote_root(root: str) -> str:
    if "\x00" in root:
        raise CommandError("remote lab root contains NUL")
    normalized = posixpath.normpath(root)
    if not normalized.startswith("/") or normalized == "/":
        raise CommandError(f"remote lab root must be an absolute non-root path: {root}")
    if any(part == ".." for part in normalized.split("/")):
        raise CommandError(f"remote lab root must not contain '..': {root}")
    return normalized


def _safe_remote_part(part: str) -> str:
    if "\x00" in part:
        raise CommandError("remote path part contains NUL")
    if any(ord(char) < 32 or ord(char) == 127 for char in part):
        raise CommandError(f"remote path part contains a control character: {part!r}")
    if not part:
        raise CommandError("remote path part must not be empty")
    if part.startswith("/"):
        raise CommandError(f"remote path part must be relative: {part}")
    if any(segment in {"", ".", ".."} for segment in part.split("/")):
        raise CommandError(f"unsafe remote path part: {part}")
    return part


def remote_join(root: str, *parts: str) -> str:
    normalized_root = normalize_remote_root(root)
    cleaned = [_safe_remote_part(str(part)) for part in parts]
    candidate = posixpath.normpath(posixpath.join(normalized_root, *cleaned))
    if candidate != normalized_root and not candidate.startswith(normalized_root + "/"):
        raise CommandError(f"remote path escapes lab root: {candidate}")
    return candidate


def assert_safe_remote_path(root: str, path: str) -> str:
    normalized_root = normalize_remote_root(root)
    if "\x00" in path:
        raise CommandError("remote path contains NUL")
    if not path.startswith("/"):
        raise CommandError(f"remote path must be absolute: {path}")
    if any(segment == ".." for segment in path.split("/")):
        raise CommandError(f"remote path must not contain '..': {path}")
    normalized = posixpath.normpath(path)
    if normalized != normalized_root and not normalized.startswith(normalized_root + "/"):
        raise CommandError(f"remote path escapes lab root: {path}")
    return normalized


def _reject_local_traversal(path: Path) -> None:
    text = str(path)
    if "\x00" in text:
        raise CommandError("local path contains NUL")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise CommandError(f"local path contains a control character: {path}")
    if any(part == ".." for part in path.parts):
        raise CommandError(f"local path must not contain '..': {path}")


def _assert_local_under(path: Path, base: Path) -> Path:
    _reject_local_traversal(path)
    resolved_base = base.resolve(strict=False)
    resolved_path = path.resolve(strict=False)
    if resolved_path != resolved_base and resolved_base not in resolved_path.parents:
        raise CommandError(f"local path escapes {resolved_base}: {path}")
    return resolved_path


def safe_local_lab_dir(value: str | None, *default_parts: str) -> Path:
    base = LOCAL_LAB_ROOT.resolve(strict=False)
    if value:
        raw = Path(value).expanduser()
        candidate = raw if raw.is_absolute() else ROOT / raw
    else:
        candidate = base.joinpath(*default_parts)
    return _assert_local_under(candidate, base)


def assert_local_lab_path(path: Path) -> Path:
    return _assert_local_under(path, LOCAL_LAB_ROOT.resolve(strict=False))


def assert_repo_path(path: Path) -> Path:
    return _assert_local_under(path, ROOT.resolve(strict=False))


def repo_path(*parts: str) -> Path:
    return ROOT.joinpath(*parts)


def q(value: str | os.PathLike[str]) -> str:
    return shlex.quote(str(value))


def join(argv: Sequence[str]) -> str:
    return shlex.join([str(item) for item in argv])


def add_lab_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"SSH host alias for the KVM lab host (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--lab-root",
        default=DEFAULT_LAB_ROOT,
        help=f"remote lab root (default: {DEFAULT_LAB_ROOT})",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="print commands without executing mutating remote actions",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug diagnostics, including commands before execution",
    )
    parser.add_argument(
        "--log-level",
        choices=["error", "warning", "info", "debug", "trace"],
        default=None,
        help=f"diagnostic log level (default: {DEFAULT_LOG_LEVEL}; --verbose implies debug)",
    )


@dataclass
class Lab:
    host: str = DEFAULT_HOST
    root: str = DEFAULT_LAB_ROOT
    dry_run: bool = False
    verbose: bool = False
    log_level: str = DEFAULT_LOG_LEVEL

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Lab":
        configure_logging(args.log_level, verbose=args.verbose)
        log_level = selected_log_level(args.log_level, verbose=args.verbose)
        return cls(
            host=args.host,
            root=normalize_remote_root(args.lab_root),
            dry_run=args.dry_run,
            verbose=args.verbose,
            log_level=log_level,
        )

    def path(self, *parts: str) -> str:
        return remote_join(self.root, *parts)

    def assert_path(self, path: str) -> str:
        return assert_safe_remote_path(self.root, path)

    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = True,
        capture: bool = False,
        input_text: str | None = None,
        dry_run_ok: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        if self.dry_run:
            logger.info("dry-run: %s", join(argv))
        else:
            logger.debug("run: %s", join(argv))
        if self.dry_run and dry_run_ok:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.run(
            list(argv),
            check=check,
            text=True,
            input=input_text,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )

    def ssh(
        self,
        command: str,
        *,
        check: bool = True,
        capture: bool = False,
        input_text: str | None = None,
        dry_run_ok: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            ["ssh", *SSH_BASE_OPTS, self.host, command],
            check=check,
            capture=capture,
            input_text=input_text,
            dry_run_ok=dry_run_ok,
        )

    def scp_to_host(self, local: Path, remote: str) -> None:
        remote = self.assert_path(remote)
        self.ssh(
            f"install -d -m 0755 {q(posixpath.dirname(remote))}", dry_run_ok=True
        )
        self.run(
            ["scp", *SSH_BASE_OPTS, str(local), f"{self.host}:{remote}"],
            dry_run_ok=True,
        )

    def scp_from_host(self, remote: str, local: Path) -> None:
        remote = self.assert_path(remote)
        local.parent.mkdir(parents=True, exist_ok=True)
        self.run(
            ["scp", *SSH_BASE_OPTS, f"{self.host}:{remote}", str(local)],
            dry_run_ok=True,
        )


def lab_cli_args(lab: Lab) -> list[str]:
    args = ["--host", lab.host, "--lab-root", lab.root]
    if lab.dry_run:
        args.append("--dry-run")
    if lab.verbose:
        args.append("--verbose")
    if lab.log_level != "info":
        args.extend(["--log-level", lab.log_level])
    return args


def require_catalog_image(name: str) -> CloudImage:
    try:
        return IMAGE_CATALOG[name]
    except KeyError as error:
        names = ", ".join(sorted(IMAGE_CATALOG))
        raise CommandError(f"unknown image {name!r}; available: {names}") from error


def print_lines(lines: Iterable[str]) -> None:
    for line in lines:
        print(line)


from lib.common_guest import (  # noqa: E402
    ensure_guest_key,
    guest_ip,
    guest_key_path,
    guest_known_hosts_path,
    guest_scp_from_host,
    guest_scp_to_host,
    guest_ssh,
    guest_ssh_command,
    read_guest_public_key,
    split_remote_command,
)
from lib.common_resources import (  # noqa: E402
    guard_local_resources,
    guard_remote_resources,
    guard_repo_resources,
    local_path_usage,
    local_resource_stats,
    local_tree_usage,
    remote_resource_lines,
    remote_resource_stats,
    report_resources,
)
