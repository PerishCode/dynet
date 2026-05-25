from __future__ import annotations

import argparse
import re

from common import CommandError, Lab, guest_ssh, logger


SAFE_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def resolve_trojan_interface(lab: Lab, guest: str, args: argparse.Namespace) -> None:
    value = str(getattr(args, "trojan_interface_name", "") or "").strip()
    if value != "auto":
        if value:
            validate_interface_name(value)
        return
    if lab.dry_run:
        args.trojan_interface_name = "eth0"
        return
    command = (
        "ip -o route get 1.1.1.1 | "
        "awk '{ for (i=1; i<=NF; i++) if ($i == \"dev\") { print $(i+1); exit } }'"
    )
    result = guest_ssh(
        lab,
        guest,
        command,
        user=args.user,
        source=args.source,
        check=False,
        capture=True,
    )
    interface_name = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if result.returncode != 0 or not interface_name:
        raise CommandError(
            "could not resolve guest default egress interface for Trojan interface binding"
        )
    validate_interface_name(interface_name)
    args.trojan_interface_name = interface_name
    logger.info("resolved Trojan interface binding to guest interface %s", interface_name)


def validate_interface_name(value: str) -> None:
    if not SAFE_INTERFACE_NAME.match(value):
        raise CommandError(f"invalid Trojan interface name: {value!r}")
