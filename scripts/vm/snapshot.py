#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess

from common import (
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_remote_resources,
    logger,
    q,
    validate_name,
)


def disk_path(lab: Lab, guest: str) -> str:
    return lab.path("vms", f"{validate_name(guest, 'guest')}.qcow2")


def report_snapshot_inventory(lab: Lab, disk: str) -> None:
    result = lab.ssh(
        f"if test -s {q(disk)}; then qemu-img snapshot -l -U {q(disk)} || true; fi",
        capture=True,
    )
    logger.info("[resource] snapshot inventory")
    output = result.stdout.strip()
    if not output:
        logger.info("  %s: no disk or no snapshots reported", disk)
        return
    for line in output.splitlines():
        logger.info("  %s", line)


def wait_shutdown_script(name: str, timeout: int, force: bool) -> str:
    force_block = (
        f"echo 'guest did not shut down in time; forcing destroy: {name}' >&2; "
        f"virsh destroy {q(name)} >/dev/null; "
        if force
        else ""
    )
    return (
        f"state=$(virsh domstate {q(name)} 2>/dev/null || true); "
        'if [ "$state" = running ]; then '
        f"virsh shutdown --mode agent {q(name)} >/dev/null 2>&1 || "
        f"virsh shutdown {q(name)} >/dev/null; "
        f"for i in $(seq 1 {int(timeout)}); do "
        f"[ \"$(virsh domstate {q(name)} 2>/dev/null || true)\" = 'shut off' ] && break; "
        "sleep 1; "
        "done; "
        "fi; "
        f"[ \"$(virsh domstate {q(name)} 2>/dev/null || true)\" = 'shut off' ] || "
        f"({force_block}"
        f"[ \"$(virsh domstate {q(name)} 2>/dev/null || true)\" = 'shut off' ] || "
        f"(echo 'guest is not shut off: {name}' >&2; exit 1)); "
    )


def list_snapshots(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    disk = disk_path(lab, guest)
    command = (
        "set -e; "
        f"test -s {q(disk)} || (echo 'disk missing: {disk}' >&2; exit 1); "
        f"qemu-img snapshot -l -U {q(disk)}"
    )
    lab.ssh(command)


def create(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    snapshot = validate_name(args.snapshot, "snapshot")
    disk = disk_path(lab, guest)
    guard_remote_resources(
        lab,
        "vm snapshot storage",
        [("vms", lab.path("vms"))],
        RESOURCE_LIMITS["vms"],
    )
    report_snapshot_inventory(lab, disk)
    delete_existing = f"qemu-img snapshot -d {q(snapshot)} {q(disk)} >/dev/null 2>&1 || true; " if args.force else ""
    restart = "" if args.leave_off else f"virsh start {q(guest)} >/dev/null; "
    command = (
        "set -e; "
        f"test -s {q(disk)} || (echo 'disk missing: {disk}' >&2; exit 1); "
        + wait_shutdown_script(guest, args.timeout, args.force_destroy)
        + delete_existing
        + f"qemu-img snapshot -c {q(snapshot)} {q(disk)}; "
        + restart
        + f"qemu-img snapshot -l -U {q(disk)}"
    )
    lab.ssh(command, dry_run_ok=True)


def revert(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    snapshot = validate_name(args.snapshot, "snapshot")
    if not args.yes:
        raise CommandError("revert requires --yes")
    disk = disk_path(lab, guest)
    restart = "" if args.leave_off else f"virsh start {q(guest)} >/dev/null; "
    command = (
        "set -e; "
        f"test -s {q(disk)} || (echo 'disk missing: {disk}' >&2; exit 1); "
        + wait_shutdown_script(guest, args.timeout, args.force_destroy)
        + f"qemu-img snapshot -a {q(snapshot)} {q(disk)}; "
        + restart
        + f"qemu-img snapshot -l -U {q(disk)}"
    )
    lab.ssh(command, dry_run_ok=True)


def delete(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    snapshot = validate_name(args.snapshot, "snapshot")
    if not args.yes:
        raise CommandError("delete requires --yes")
    disk = disk_path(lab, guest)
    guard_remote_resources(
        lab,
        "vm snapshot storage",
        [("vms", lab.path("vms"))],
        RESOURCE_LIMITS["vms"],
        enforce=False,
    )
    report_snapshot_inventory(lab, disk)
    command = (
        "set -e; "
        f"test -s {q(disk)} || (echo 'disk missing: {disk}' >&2; exit 1); "
        f"qemu-img snapshot -d {q(snapshot)} {q(disk)}; "
        f"qemu-img snapshot -l -U {q(disk)}"
    )
    lab.ssh(command, dry_run_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage offline qcow2 snapshots for dynet lab guests."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list snapshots on guest disk")
    list_parser.add_argument("guest")

    create_parser = subparsers.add_parser(
        "create", help="shut down guest, create snapshot, then restart by default"
    )
    create_parser.add_argument("guest")
    create_parser.add_argument("snapshot")
    create_parser.add_argument("--timeout", type=int, default=60)
    create_parser.add_argument("--force", action="store_true", help="replace snapshot")
    create_parser.add_argument(
        "--force-destroy",
        action="store_true",
        help="force-stop guest if graceful shutdown times out",
    )
    create_parser.add_argument("--leave-off", action="store_true")

    revert_parser = subparsers.add_parser(
        "revert", help="shut down guest, revert snapshot, then restart by default"
    )
    revert_parser.add_argument("guest")
    revert_parser.add_argument("snapshot")
    revert_parser.add_argument("--yes", action="store_true", help="confirm revert")
    revert_parser.add_argument("--timeout", type=int, default=60)
    revert_parser.add_argument(
        "--force-destroy",
        action="store_true",
        help="force-stop guest if graceful shutdown times out",
    )
    revert_parser.add_argument("--leave-off", action="store_true")

    delete_parser = subparsers.add_parser("delete", help="delete a disk snapshot")
    delete_parser.add_argument("guest")
    delete_parser.add_argument("snapshot")
    delete_parser.add_argument("--yes", action="store_true", help="confirm delete")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {
        "list": list_snapshots,
        "create": create,
        "revert": revert,
        "delete": delete,
    }
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
