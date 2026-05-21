#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess

from common import DEFAULT_VM_USER, CommandError, Lab, add_lab_options, logger
from private_runtime_lib.orchestrate import command_guest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run dynet Private cascade runtime acceptance inside a disposable VM guest."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

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
    guest.add_argument("--tcp-forward", action="store_true")
    guest.add_argument("--udp-forward", action="store_true")
    guest.add_argument("--udp-direct-probe", action="store_true")
    guest.add_argument("--udp-target", default="1.1.1.1:123")
    guest.add_argument("--ipv6-no-leak", action="store_true")
    guest.add_argument("--ipv6-target", default="[2606:4700:4700::1111]:443")
    guest.add_argument("--workload-manifest")
    guest.add_argument("--workload-min-success-rate", type=float, default=0.75)
    guest.add_argument(
        "--no-workload-respect-schedule",
        action="store_false",
        dest="workload_respect_schedule",
        help="ignore workload manifest scheduled offsets inside the VM runtime probe",
    )
    guest.add_argument("--repeat", type=int, default=1)
    guest.add_argument("--tun-target", default="203.0.113.10")
    guest.add_argument("--tunnel-name", default="Tunnel")
    guest.add_argument("--filter", default="Basic-美国")
    guest.add_argument("--limit", type=int, default=4)
    guest.add_argument("--strategy-key", default="cascade-quality")
    guest.add_argument(
        "--no-resolve-tunnel-server",
        action="store_false",
        dest="resolve_tunnel_server",
        help="do not resolve airport server bootstrap IPs into the temporary secret config",
    )
    guest.add_argument("--domain", action="append", default=[])
    guest.add_argument("--domain-suffix", action="append", default=[])
    guest.add_argument("--supported-type", action="append", default=["vmess", "trojan"])
    guest.set_defaults(resolve_tunnel_server=True)
    guest.set_defaults(workload_respect_schedule=True)
    guest.set_defaults(handler=command_guest)

    return parser

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
