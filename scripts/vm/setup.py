#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from common import (
    DEFAULT_VM_USER,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guest_scp_from_host,
    guest_ssh,
    guard_remote_resources,
    q,
    split_remote_command,
    validate_name,
)


def stage(lab: Lab, local_path: Path) -> str:
    if not local_path.exists():
        raise CommandError(f"local artifact does not exist: {local_path}")
    remote = lab.path("artifacts", "incoming", local_path.name)
    guard_remote_resources(
        lab,
        "incoming artifact cache",
        [("incoming", lab.path("artifacts", "incoming"))],
        RESOURCE_LIMITS["incoming"],
    )
    lab.scp_to_host(local_path, remote)
    print(remote)
    return remote


def stage_command(lab: Lab, args: argparse.Namespace) -> None:
    stage(lab, Path(args.path).resolve())


def require_guest_elf(local_path: Path, *, allow_any_binary: bool) -> None:
    if allow_any_binary:
        return
    result = subprocess.run(
        ["file", "-b", str(local_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise CommandError(f"failed to inspect local binary with file(1): {result.stderr.strip()}")
    description = result.stdout.strip()
    print(f"local binary: {description}", file=sys.stderr)
    if "ELF" not in description:
        raise CommandError(
            "install-bin expects a Linux ELF artifact for the guest; "
            "build inside Linux or pass --allow-any-binary explicitly"
        )


def install_bin(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.guest, "guest")
    local = Path(args.path).resolve()
    require_guest_elf(local, allow_any_binary=args.allow_any_binary)
    remote = stage(lab, local)
    guest_tmp = f"/tmp/{local.name}"
    guest_scp_from_host(lab, name, remote, guest_tmp, user=args.user, source=args.source)
    guest_ssh(
        lab,
        name,
        (
            f"sudo install -m 0755 {q(guest_tmp)} {q(args.dest)} && "
            f"{q(args.dest)} version || true"
        ),
        user=args.user,
        source=args.source,
    )


def install_deb(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.guest, "guest")
    local = Path(args.path).resolve()
    remote = stage(lab, local)
    guest_tmp = f"/tmp/{local.name}"
    guest_scp_from_host(lab, name, remote, guest_tmp, user=args.user, source=args.source)
    guest_ssh(
        lab,
        name,
        f"sudo apt-get update && sudo apt-get install -y {q(guest_tmp)}",
        user=args.user,
        source=args.source,
    )


def run(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.guest, "guest")
    user, source, remote_command = split_remote_command(
        args.remote_command,
        user=args.user,
        source=args.source,
    )
    if not remote_command:
        raise CommandError("run requires a remote command")
    guest_ssh(
        lab,
        name,
        " ".join(remote_command),
        user=user,
        source=source,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stage and install dynet artifacts into lab guests."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    stage_parser = subparsers.add_parser("stage", help="copy a local artifact to host")
    stage_parser.add_argument("path")

    bin_parser = subparsers.add_parser("install-bin", help="install a binary in a guest")
    bin_parser.add_argument("guest")
    bin_parser.add_argument("path")
    bin_parser.add_argument("--dest", default="/usr/local/bin/dynet")
    bin_parser.add_argument(
        "--allow-any-binary",
        action="store_true",
        help="skip Linux ELF validation before installing into the guest",
    )
    bin_parser.add_argument("--user", default=DEFAULT_VM_USER)
    bin_parser.add_argument("--source", default="lease", choices=["lease", "agent"])

    deb_parser = subparsers.add_parser("install-deb", help="install a .deb in a guest")
    deb_parser.add_argument("guest")
    deb_parser.add_argument("path")
    deb_parser.add_argument("--user", default=DEFAULT_VM_USER)
    deb_parser.add_argument("--source", default="lease", choices=["lease", "agent"])

    run_parser = subparsers.add_parser("run", help="run a command in a guest")
    run_parser.add_argument("guest")
    run_parser.add_argument("--user", default=DEFAULT_VM_USER)
    run_parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    run_parser.add_argument("remote_command", nargs=argparse.REMAINDER)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {
        "stage": stage_command,
        "install-bin": install_bin,
        "install-deb": install_deb,
        "run": run,
    }
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
