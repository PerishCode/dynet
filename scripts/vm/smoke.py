#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys

from common import (
    DEFAULT_VM_USER,
    ROOT,
    CommandError,
    Lab,
    add_lab_options,
    guest_ssh,
    join,
    q,
    validate_name,
)


COLD_START_CONFIG = """{
  "log": { "level": "info" },
  "inbounds": [
    { "tag": "mixed-in", "type": "mixed" }
  ],
  "outbounds": [
    { "tag": "direct", "type": "direct" }
  ],
  "routes": [
    { "inbound": "mixed-in", "outbound": "direct" }
  ]
}
"""


def api_health_command(port: int) -> str:
    return (
        "set -e; "
        f"port={int(port)}; "
        "out=/tmp/dynet-api-health.json; "
        "log=/tmp/dynet-api-serve.log; "
        "err=/tmp/dynet-api-serve.err; "
        "rm -f \"$out\" \"$log\" \"$err\"; "
        "(dynet api serve --bind 127.0.0.1:${port} --once >\"$log\" 2>\"$err\") & pid=$!; "
        "for i in $(seq 1 40); do "
        "if curl -fsS \"http://127.0.0.1:${port}/health\" >\"$out\"; then "
        "wait \"$pid\"; cat \"$out\"; printf \"\\n\"; exit 0; "
        "fi; "
        "sleep 0.25; "
        "done; "
        "kill \"$pid\" >/dev/null 2>&1 || true; "
        "wait \"$pid\" >/dev/null 2>&1 || true; "
        "cat \"$err\" >&2; "
        "exit 1"
    )


def guest(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.guest, "guest")
    label = validate_name(args.label, "label")
    config_path = f"/tmp/dynet-{label}.json"
    write_config = (
        f"cat > {q(config_path)} <<'EOF_DYNET_CONFIG'\n"
        f"{COLD_START_CONFIG}EOF_DYNET_CONFIG"
    )
    guest_ssh(lab, name, write_config, user=args.user, source=args.source)

    commands = [
        "dynet version",
        f"dynet check --config {q(config_path)} --format json",
        f"dynet doctor --config {q(config_path)} --format json",
        f"dynet plan --config {q(config_path)} --format json",
        "dynet api capabilities --format json",
    ]
    if not args.no_api_serve:
        commands.append(api_health_command(args.api_port))
    for command in commands:
        print(f"[smoke] {command}", flush=True)
        guest_ssh(lab, name, command, user=args.user, source=args.source)

    if args.collect:
        run_local(
            lab,
            [
                "collect",
                "--host",
                lab.host,
                "--lab-root",
                lab.root,
                *lab_flags(lab),
                "guest",
                name,
                "--label",
                label,
                "--user",
                args.user,
                "--source",
                args.source,
            ]
        )
    if args.capture:
        run_local(
            lab,
            [
                "capture",
                "--host",
                lab.host,
                "--lab-root",
                lab.root,
                *lab_flags(lab),
                "host",
                name,
                "--label",
                label,
                "--duration",
                str(args.capture_duration),
                "--filter",
                "icmp or arp",
                "--probe",
                "ping -c 1 192.168.122.1",
                "--user",
                args.user,
                "--source",
                args.source,
            ]
        )


def lab_flags(lab: Lab) -> list[str]:
    flags: list[str] = []
    if lab.dry_run:
        flags.append("--dry-run")
    if lab.verbose:
        flags.append("--verbose")
    return flags


def run_local(lab: Lab, args: list[str]) -> None:
    script = ROOT / "scripts" / "vmctl.py"
    command = [sys.executable, str(script), *args]
    print("+ " + join(command), file=sys.stderr)
    subprocess.run(command, check=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run dynet cold-start smoke checks in guests.")
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    guest_parser = subparsers.add_parser("guest", help="run cold-start checks in a guest")
    guest_parser.add_argument("guest")
    guest_parser.add_argument("--label", default="cold-start")
    guest_parser.add_argument("--user", default=DEFAULT_VM_USER)
    guest_parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest_parser.add_argument("--no-api-serve", action="store_true")
    guest_parser.add_argument("--api-port", type=int, default=19977)
    guest_parser.add_argument("--collect", action="store_true")
    guest_parser.add_argument("--capture", action="store_true")
    guest_parser.add_argument("--capture-duration", type=int, default=4)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {"guest": guest}
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
