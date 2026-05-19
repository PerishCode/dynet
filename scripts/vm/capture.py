#!/usr/bin/env python3
from __future__ import annotations

import argparse
import posixpath
import re
import subprocess
from datetime import datetime, timezone

from common import (
    DEFAULT_VM_USER,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_local_resources,
    guard_remote_resources,
    guest_scp_to_host,
    guest_ssh,
    guest_ssh_command,
    join,
    logger,
    q,
    safe_local_lab_dir,
    validate_name,
)


HOST_CAPTURE_IFACE = re.compile(r"^vnet[0-9]+$")
GUEST_CAPTURE_IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def capture_name(guest: str, label: str, scope: str) -> str:
    return f"{guest}-{label}-{scope}-{stamp()}.pcap"


def remote_pcap_path(lab: Lab, filename: str) -> str:
    return lab.path("artifacts", "pcap", filename)


def fetch_if_needed(
    lab: Lab,
    remote: str,
    local_dir,
    args: argparse.Namespace,
) -> None:
    print(remote)
    if local_dir is None:
        return
    local_path = local_dir / posixpath.basename(remote)
    lab.scp_from_host(remote, local_path)
    print(local_path)


def host_iface(lab: Lab, guest: str) -> str:
    result = lab.ssh(
        f"virsh domiflist {q(guest)} | awk 'NR > 2 && $1 ~ /^vnet[0-9]+$/ {{ print $1; exit }}'",
        capture=True,
    )
    iface = result.stdout.strip()
    if not HOST_CAPTURE_IFACE.match(iface):
        raise CommandError(
            f"could not resolve a safe vnet interface for guest {guest!r}"
        )
    return iface


def host_capture(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    label = validate_name(args.label, "label")
    filename = capture_name(guest, label, "host")
    remote = remote_pcap_path(lab, filename)
    local_dir = None if args.no_fetch else safe_local_lab_dir(args.output, "pcap")
    guard_remote_resources(
        lab,
        "remote packet capture cache",
        [("pcap", lab.path("artifacts", "pcap"))],
        RESOURCE_LIMITS["pcap"],
    )
    if local_dir is not None:
        guard_local_resources(
            "local packet capture cache",
            [("pcap", local_dir)],
            RESOURCE_LIMITS["local-pcap"],
        )
    iface = host_iface(lab, guest)
    tcpdump_filter = args.filter or ""
    tcpdump = (
        f"timeout {int(args.duration)} tcpdump -i {q(iface)} -s 0 -U "
        f"-w {q(remote)}"
        + (f" {tcpdump_filter}" if tcpdump_filter else "")
    )
    probe = ""
    if args.probe:
        probe_cmd = join(
            guest_ssh_command(
                lab,
                guest,
                user=args.user,
                source=args.source,
                command=args.probe,
            )
        )
        probe = f"sleep {int(args.warmup)}; {probe_cmd} >/dev/null 2>&1 || true; "
    empty_check = "" if args.allow_empty else f"test -s {q(remote)}; "
    command = (
        "set -e; "
        f"install -d -m 0755 {q(posixpath.dirname(remote))}; "
        f"rm -f {q(remote)}; "
        f"({tcpdump}) & cap=$!; "
        f"{probe}"
        "set +e; wait $cap; code=$?; set -e; "
        "[ \"$code\" = 0 ] || [ \"$code\" = 124 ]; "
        f"{empty_check}"
        f"ls -lh {q(remote)}"
    )
    lab.ssh(command, dry_run_ok=True)
    fetch_if_needed(lab, remote, local_dir, args)


def guest_capture(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    label = validate_name(args.label, "label")
    iface = args.iface
    if not GUEST_CAPTURE_IFACE.match(iface):
        raise CommandError(f"invalid guest interface: {iface!r}")
    filename = capture_name(guest, label, "guest")
    guest_tmp = f"/tmp/{filename}"
    remote = remote_pcap_path(lab, filename)
    local_dir = None if args.no_fetch else safe_local_lab_dir(args.output, "pcap")
    guard_remote_resources(
        lab,
        "remote packet capture cache",
        [("pcap", lab.path("artifacts", "pcap"))],
        RESOURCE_LIMITS["pcap"],
    )
    if local_dir is not None:
        guard_local_resources(
            "local packet capture cache",
            [("pcap", local_dir)],
            RESOURCE_LIMITS["local-pcap"],
        )
    tcpdump_filter = args.filter or ""
    tcpdump = (
        f"sudo timeout {int(args.duration)} tcpdump -i {q(iface)} -s 0 -U "
        f"-w {q(guest_tmp)}"
        + (f" {tcpdump_filter}" if tcpdump_filter else "")
    )
    probe = f"sleep {int(args.warmup)}; {args.probe} >/dev/null 2>&1 || true; " if args.probe else ""
    empty_check = "" if args.allow_empty else f"sudo test -s {q(guest_tmp)}; "
    guest_command = (
        "set -e; "
        f"sudo rm -f {q(guest_tmp)}; "
        f"({tcpdump}) & cap=$!; "
        f"{probe}"
        "set +e; wait $cap; code=$?; set -e; "
        "[ \"$code\" = 0 ] || [ \"$code\" = 124 ]; "
        f"{empty_check}"
        f"sudo chmod 0644 {q(guest_tmp)}; "
        f"ls -lh {q(guest_tmp)}"
    )
    guest_ssh(
        lab,
        guest,
        guest_command,
        user=args.user,
        source=args.source,
    )
    guest_scp_to_host(
        lab,
        guest,
        guest_tmp,
        remote,
        user=args.user,
        source=args.source,
    )
    guest_ssh(
        lab,
        guest,
        f"sudo rm -f {q(guest_tmp)}",
        user=args.user,
        source=args.source,
    )
    fetch_if_needed(lab, remote, local_dir, args)


def add_capture_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("guest")
    parser.add_argument("--label", default="capture")
    parser.add_argument("--duration", type=int, default=8)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--filter", default="")
    parser.add_argument("--probe", help="command used to generate traffic")
    parser.add_argument("--allow-empty", action="store_true")
    parser.add_argument("--output", help="local output directory")
    parser.add_argument("--no-fetch", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture packets for dynet lab guests with scoped interfaces."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    host_parser = subparsers.add_parser(
        "host",
        help="capture on the host vnet interface attached to a guest",
    )
    add_capture_options(host_parser)
    host_parser.add_argument("--user", default=DEFAULT_VM_USER)
    host_parser.add_argument("--source", default="lease", choices=["lease", "agent"])

    guest_parser = subparsers.add_parser(
        "guest",
        help="capture inside the guest on a guest interface",
    )
    add_capture_options(guest_parser)
    guest_parser.add_argument("--iface", default="any")
    guest_parser.add_argument("--user", default=DEFAULT_VM_USER)
    guest_parser.add_argument("--source", default="lease", choices=["lease", "agent"])

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {
        "host": host_capture,
        "guest": guest_capture,
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
