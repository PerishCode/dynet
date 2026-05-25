from __future__ import annotations

import argparse
from typing import Callable

from common import DEFAULT_VM_USER, add_lab_options


Handler = Callable[..., object]


def build_parser(
    *,
    guest_handler: Handler,
    paired_handler: Handler,
    paired_selection_handler: Handler,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run dynet Private cascade probes inside a disposable VM guest."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_guest_command(subparsers, guest_handler)
    add_paired_command(subparsers, paired_handler)
    add_paired_selection_command(subparsers, paired_selection_handler)
    return parser


def add_guest_command(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    guest = subparsers.add_parser("guest")
    guest.add_argument("guest")
    add_run_options(guest)
    guest.add_argument("--target-url", action="append")
    guest.add_argument("--limit", type=int, default=4)
    guest.add_argument("--candidate-offset", type=int, default=0)
    guest.add_argument("--quality-ttl-seconds", type=int, default=300)
    guest.add_argument("--quality-window-seconds", type=int, default=1800)
    guest.add_argument("--resolve-tunnel-server", action="store_true")
    add_private_config_options(guest)
    guest.set_defaults(handler=handler)


def add_paired_command(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    paired = subparsers.add_parser("paired")
    paired.add_argument("guest")
    paired.add_argument("--manifest", required=True)
    add_run_options(paired)
    paired.add_argument("--candidate-limit", type=int, default=4)
    add_private_config_options(paired)
    paired.add_argument("--entry-limit", type=int)
    paired.add_argument("--bucket", action="append")
    paired.add_argument("--behavior", action="append")
    paired.add_argument("--probe-type", action="append")
    paired.add_argument("--timeout-seconds", type=float, default=8.0)
    paired.add_argument("--spacing-ms", type=int, default=250)
    paired.add_argument("--schedule-scale", type=float, default=1.0)
    paired.add_argument("--no-respect-schedule", action="store_false", dest="respect_schedule")
    paired.add_argument("--side-order", choices=["alternate", "clash-first", "dynet-first"], default="alternate")
    paired.add_argument("--side-mode", choices=["sequential", "parallel"], default="sequential")
    paired.add_argument("--parallel-side-stagger-ms", type=int, default=0)
    paired.add_argument("--dynet-protocol", choices=["source", "tcp-connect", "https-head", "tls-handshake"], default="source")
    paired.add_argument("--clash-environment", default="local-clash-vm-private-paired")
    paired.set_defaults(resolve_tunnel_server=True)
    paired.set_defaults(respect_schedule=True)
    paired.set_defaults(handler=handler)


def add_paired_selection_command(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    paired_selection = subparsers.add_parser("paired-selection")
    paired_selection.add_argument("--label", default="paired-selection")
    paired_selection.add_argument("--output-dir", required=True)
    paired_selection.add_argument("--pressure-summary")
    paired_selection.add_argument("input", nargs="+")
    paired_selection.set_defaults(handler=handler)


def add_run_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--label")
    parser.add_argument("--output-dir")
    parser.add_argument("--user", default=DEFAULT_VM_USER)
    parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    parser.add_argument("--quality-state")
    parser.add_argument("--skip-install", action="store_true")
    parser.add_argument("--artifact")
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu")
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--dynet-bin", default="/usr/local/bin/dynet")
    parser.add_argument("--tunnel-name", default="Tunnel")
    parser.add_argument("--filter")
    parser.add_argument("--strategy-key", default="cascade-quality")


def add_private_config_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--trojan-interface-name")
    parser.add_argument("--domain", action="append", default=[])
    parser.add_argument("--domain-suffix", action="append", default=[])
    parser.add_argument("--supported-type", action="append")
