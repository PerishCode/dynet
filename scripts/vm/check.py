#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass

from common import (
    DEFAULT_VM_USER,
    CommandError,
    Lab,
    add_lab_options,
    guest_ip,
    guest_ssh,
    logger,
    q,
    validate_name,
)


@dataclass
class CheckResult:
    label: str
    ok: bool
    detail: str = ""


def report(result: CheckResult) -> None:
    status = "pass" if result.ok else "fail"
    detail = f" - {result.detail}" if result.detail else ""
    print(f"[{status}] {result.label}{detail}")


def host_check(lab: Lab, label: str, command: str) -> CheckResult:
    result = lab.ssh(command, check=False, capture=True)
    detail = ((result.stdout or "") + (result.stderr or "")).strip().splitlines()
    return CheckResult(
        label=label,
        ok=result.returncode == 0,
        detail=detail[-1] if detail else "",
    )


def guest_check(
    lab: Lab,
    guest: str,
    label: str,
    command: str,
    *,
    user: str,
    source: str,
) -> CheckResult:
    try:
        result = guest_ssh(
            lab,
            guest,
            command,
            user=user,
            source=source,
            capture=True,
        )
    except subprocess.CalledProcessError as error:
        detail = ((error.stdout or "") + (error.stderr or "")).strip().splitlines()
        return CheckResult(label=label, ok=False, detail=detail[-1] if detail else "")
    detail = ((result.stdout or "") + (result.stderr or "")).strip().splitlines()
    return CheckResult(label=label, ok=True, detail=detail[-1] if detail else "")


def guest_network_checks(
    lab: Lab,
    guest: str,
    *,
    user: str,
    source: str,
    dns_name: str,
    https_url: str,
) -> list[CheckResult]:
    return [
        guest_check(
            lab,
            guest,
            "guest default route",
            "ip -4 route show default | head -n1 | grep -q . && "
            "ip -4 route show default | head -n1",
            user=user,
            source=source,
        ),
        guest_check(
            lab,
            guest,
            "guest resolver config",
            "test -s /etc/resolv.conf && "
            "awk 'NF && $1 !~ /^#/ { print; exit }' /etc/resolv.conf",
            user=user,
            source=source,
        ),
        guest_check(
            lab,
            guest,
            f"guest DNS resolve {dns_name}",
            f"getent ahostsv4 {q(dns_name)} | awk 'NR==1 {{ print $1; exit }}' | grep -q . && "
            f"getent ahostsv4 {q(dns_name)} | awk 'NR==1 {{ print $1; exit }}'",
            user=user,
            source=source,
        ),
        guest_check(
            lab,
            guest,
            f"guest HTTPS {https_url}",
            "curl -fsS --connect-timeout 5 --max-time 15 --retry 1 "
            f"-o /dev/null -w 'http=%{{http_code}} remote=%{{remote_ip}}\\n' {q(https_url)}",
            user=user,
            source=source,
        ),
    ]


def check_guest(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    network = validate_name(args.network, "network")
    snapshot = validate_name(args.snapshot, "snapshot") if args.snapshot else ""
    disk = lab.path("vms", f"{guest}.qcow2")
    results: list[CheckResult] = []

    results.append(
        host_check(
            lab,
            f"network {network} active",
            f"virsh net-info {q(network)} | grep -q '^Active:.*yes'",
        )
    )
    results.append(
        host_check(
            lab,
            f"domain {guest} running",
            f"test \"$(virsh domstate {q(guest)} 2>/dev/null)\" = running",
        )
    )
    if snapshot:
        results.append(
            host_check(
                lab,
                f"snapshot {snapshot}",
                f"qemu-img snapshot -l -U {q(disk)} | awk '{{print $2}}' | grep -qx {q(snapshot)}",
            )
        )

    try:
        address = guest_ip(lab, guest, source=args.source)
        results.append(CheckResult("guest IPv4", True, address))
    except CommandError as error:
        results.append(CheckResult("guest IPv4", False, str(error)))

    if results[-1].ok:
        results.extend(
            [
                guest_check(
                    lab,
                    guest,
                    "guest SSH",
                    "true",
                    user=args.user,
                    source=args.source,
                ),
                guest_check(
                    lab,
                    guest,
                    "cloud-init done",
                    "cloud-init status | grep -q 'status: done'",
                    user=args.user,
                    source=args.source,
                ),
                guest_check(
                    lab,
                    guest,
                    "qemu guest agent",
                    "test \"$(systemctl is-active qemu-guest-agent)\" = active",
                    user=args.user,
                    source=args.source,
                ),
                *guest_network_checks(
                    lab,
                    guest,
                    user=args.user,
                    source=args.source,
                    dns_name=args.dns_name,
                    https_url=args.https_url,
                ),
                guest_check(
                    lab,
                    guest,
                    "dynet version",
                    "dynet version",
                    user=args.user,
                    source=args.source,
                ),
                guest_check(
                    lab,
                    guest,
                    "dynet check",
                    "dynet check --format json >/dev/null",
                    user=args.user,
                    source=args.source,
                ),
            ]
        )

    for result in results:
        report(result)
    if not all(result.ok for result in results):
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run high-level dynet lab checks.")
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    guest_parser = subparsers.add_parser("guest", help="check one guest baseline")
    guest_parser.add_argument("guest")
    guest_parser.add_argument("--network", default="default")
    guest_parser.add_argument("--snapshot", default="dynet-installed")
    guest_parser.add_argument("--user", default=DEFAULT_VM_USER)
    guest_parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest_parser.add_argument("--dns-name", default="example.com")
    guest_parser.add_argument("--https-url", default="https://example.com/")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {"guest": check_guest}
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
