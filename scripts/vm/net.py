#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys

from common import CommandError, Lab, add_lab_options, q, validate_name


def list_networks(lab: Lab, _: argparse.Namespace) -> None:
    lab.ssh("virsh net-list --all")


def info(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "network")
    lab.ssh(f"virsh net-info {q(name)}")


def start(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "network")
    lab.ssh(f"virsh net-start {q(name)}", dry_run_ok=True)


def stop(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "network")
    if not args.yes:
        raise CommandError("stop requires --yes")
    lab.ssh(f"virsh net-destroy {q(name)}", dry_run_ok=True)


def autostart(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "network")
    disable = " --disable" if args.disable else ""
    lab.ssh(f"virsh net-autostart {q(name)}{disable}", dry_run_ok=True)


def host_view(lab: Lab, _: argparse.Namespace) -> None:
    command = (
        "set -e; "
        "printf 'networks\\n'; virsh net-list --all; "
        "printf '\\nvirbr0\\n'; ip addr show virbr0 2>/dev/null || true; "
        "printf '\\ndefault route\\n'; ip route show default; "
        "printf '\\nresolver\\n'; cat /etc/resolv.conf"
    )
    lab.ssh(command)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage dynet lab libvirt networks.")
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="list libvirt networks")
    subparsers.add_parser("host-view", help="show host network view relevant to lab")

    info_parser = subparsers.add_parser("info", help="show one network")
    info_parser.add_argument("name", default="default", nargs="?")

    start_parser = subparsers.add_parser("start", help="start a libvirt network")
    start_parser.add_argument("name", default="default", nargs="?")

    stop_parser = subparsers.add_parser("stop", help="stop a libvirt network")
    stop_parser.add_argument("name", default="default", nargs="?")
    stop_parser.add_argument("--yes", action="store_true", help="confirm network stop")

    autostart_parser = subparsers.add_parser(
        "autostart", help="enable or disable network autostart"
    )
    autostart_parser.add_argument("name", default="default", nargs="?")
    autostart_parser.add_argument(
        "--disable", action="store_true", help="disable autostart"
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {
        "list": list_networks,
        "info": info,
        "start": start,
        "stop": stop,
        "autostart": autostart,
        "host-view": host_view,
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
