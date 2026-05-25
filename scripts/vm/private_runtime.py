#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess

from common import DEFAULT_VM_USER, CommandError, Lab, add_lab_options, logger
from private_runtime_lib.orchestrate import command_guest
from private_runtime_lib.reporting import add_reporting_commands


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run dynet Private cascade runtime acceptance inside a disposable VM guest."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_guest_command(subparsers)
    add_reporting_commands(subparsers)

    return parser


def add_guest_command(subparsers: argparse._SubParsersAction) -> None:
    guest = subparsers.add_parser("guest")
    guest.add_argument("guest")
    guest.add_argument("--label")
    guest.add_argument("--output-dir")
    guest.add_argument("--user", default=DEFAULT_VM_USER)
    guest.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest.add_argument("--dns-name", action="append")
    guest.add_argument("--quality-state")
    guest.add_argument("--skip-install", action="store_true")
    guest.add_argument("--artifact")
    guest.add_argument("--target", default="x86_64-unknown-linux-gnu")
    guest.add_argument("--release", action="store_true")
    guest.add_argument("--dynet-bin", default="/usr/local/bin/dynet")
    guest.add_argument("--timeout", type=int, default=30)
    guest.add_argument("--dns-timeout", type=int, default=35)
    guest.add_argument("--upstream-dns", default="8.8.8.8:53")
    guest.add_argument(
        "--runtime-udp-dns",
        action="store_true",
        help="use --upstream-dns as dynet run's plain UDP diagnostic DNS chain",
    )
    add_tcp_options(guest)
    guest.add_argument("--udp-forward", action="store_true")
    guest.add_argument("--udp-direct-probe", action="store_true")
    guest.add_argument("--udp-target", default="1.1.1.1:123")
    guest.add_argument("--ipv6-no-leak", action="store_true")
    guest.add_argument("--ipv6-target", default="[2606:4700:4700::1111]:443")
    add_workload_options(guest)
    guest.add_argument("--repeat", type=int, default=1)
    guest.add_argument("--tun-target", default="203.0.113.10")
    guest.add_argument("--tunnel-name", default="Tunnel")
    guest.add_argument("--filter")
    guest.add_argument("--limit", type=int, default=4)
    guest.add_argument("--candidate-offset", type=int, default=0)
    guest.add_argument("--strategy-key", default="cascade-quality")
    guest.add_argument(
        "--trojan-interface-name",
        help="Trojan outbound interface binding; use `auto` to bind to the guest default egress interface",
    )
    guest.add_argument("--poison-first-bound-candidate", action="store_true")
    guest.add_argument(
        "--poison-bound-only",
        action="store_true",
        help="replace the tunnel bound plan with one local poison candidate",
    )
    guest.add_argument(
        "--force-bound-candidate",
        help="restrict the temporary tunnel plan to one existing bound candidate tag, e.g. tunnel-004",
    )
    guest.add_argument(
        "--force-private-downstream-failure",
        action="store_true",
        help="poison the temporary private target so bound succeeds but downstream cascade stops",
    )
    guest.add_argument(
        "--no-resolve-tunnel-server",
        action="store_false",
        dest="resolve_tunnel_server",
        help="do not resolve airport server bootstrap IPs into the temporary secret config",
    )
    guest.add_argument("--domain", action="append", default=[])
    guest.add_argument("--domain-suffix", action="append", default=[])
    guest.add_argument("--supported-type", action="append")
    guest.set_defaults(resolve_tunnel_server=True)
    guest.set_defaults(workload_respect_schedule=True)
    guest.set_defaults(tcp_probe=True)
    guest.set_defaults(handler=command_guest)


def add_tcp_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tcp-forward", action="store_true")
    parser.add_argument("--no-tcp-probe", action="store_false", dest="tcp_probe")
    parser.add_argument(
        "--tcp-route-plan-private",
        action="store_true",
        help="route TUN TCP private domains through explicit routes instead of hard user rules",
    )
    parser.add_argument(
        "--tcp-route-direct-fallback",
        action="store_true",
        help="diagnostic route plan: try private-via-tunnel first, then direct",
    )
    parser.add_argument(
        "--tcp-route-non-direct-fallback",
        action="store_true",
        help="diagnostic route plan: try a poisoned private dialer, then private-via-tunnel",
    )
    parser.add_argument("--tcp-listen-slots-per-port", type=int)
    parser.add_argument("--outbound-tcp-connect-timeout-ms", type=int, default=8000)
    parser.add_argument("--outbound-tcp-read-write-timeout-ms", type=int, default=8000)


def add_workload_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workload-manifest")
    parser.add_argument("--workload-min-success-rate", type=float, default=0.75)
    parser.add_argument(
        "--workload-require-all-success",
        action="store_true",
        help="fail the VM runtime acceptance if any workload manifest entry fails",
    )
    parser.add_argument(
        "--no-workload-respect-schedule",
        action="store_false",
        dest="workload_respect_schedule",
        help="ignore workload manifest scheduled offsets inside the VM runtime probe",
    )
    parser.add_argument(
        "--workload-concurrency-limit",
        type=int,
        help="limit concurrent workload entries when the workload manifest is parallel",
    )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    args.handler(lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
