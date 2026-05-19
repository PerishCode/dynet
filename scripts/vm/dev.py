#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from common import (
    DEFAULT_VM_USER,
    ROOT,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_repo_resources,
    join,
    validate_name,
)
from setup import require_guest_elf


DEFAULT_TARGET = "x86_64-unknown-linux-gnu"


def artifact_path(target: str, release: bool) -> Path:
    profile = "release" if release else "debug"
    return ROOT / "target" / target / profile / "dynet"


def require_local_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise CommandError(f"missing required local tool: {name}")


def build_artifact(lab: Lab, args: argparse.Namespace) -> Path:
    target = args.target
    release = args.release
    artifact = artifact_path(target, release)
    guard_repo_resources(
        "local cargo target cache",
        [("target", ROOT / "target")],
        RESOURCE_LIMITS["cargo-target"],
    )
    if not lab.dry_run:
        require_local_tool("cargo")
        require_local_tool("cargo-zigbuild")
        require_local_tool("zig")
    command = [
        "cargo",
        "zigbuild",
        "--locked",
        "--target",
        target,
        "-p",
        "dynet-cli",
    ]
    if release:
        command.append("--release")
    if lab.verbose or lab.dry_run:
        print("+ " + join(command), file=sys.stderr)
    if not lab.dry_run:
        subprocess.run(command, cwd=ROOT, check=True)
        require_guest_elf(artifact, allow_any_binary=False)
    print(artifact, flush=True)
    return artifact


def build_command(lab: Lab, args: argparse.Namespace) -> None:
    build_artifact(lab, args)


def guest_command(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    label = validate_name(args.label, "label")
    guest_touched = False
    try:
        if args.artifact:
            artifact = Path(args.artifact).expanduser().resolve()
            if not lab.dry_run:
                require_guest_elf(artifact, allow_any_binary=args.allow_any_binary)
        else:
            artifact = build_artifact(lab, args)

        if not args.no_install:
            guest_touched = True
            run_vmctl(
                lab,
                [
                    "setup",
                    *lab_args(lab),
                    "install-bin",
                    guest,
                    str(artifact),
                    "--user",
                    args.user,
                    "--source",
                    args.source,
                ]
                + (["--allow-any-binary"] if args.allow_any_binary else []),
            )

        if not args.no_smoke:
            guest_touched = True
            smoke_args = [
                "smoke",
                *lab_args(lab),
                "guest",
                guest,
                "--label",
                label,
                "--user",
                args.user,
                "--source",
                args.source,
            ]
            if args.collect:
                smoke_args.append("--collect")
            if args.capture:
                smoke_args.append("--capture")
            run_vmctl(lab, smoke_args)

        if not args.no_check:
            guest_touched = True
            run_vmctl(lab, ["check", *lab_args(lab), "guest", guest])
    except subprocess.CalledProcessError as error:
        collect_failure_evidence(lab, args, guest, label, guest_touched)
        raise error


def lab_args(lab: Lab) -> list[str]:
    args = ["--host", lab.host, "--lab-root", lab.root]
    if lab.dry_run:
        args.append("--dry-run")
    if lab.verbose:
        args.append("--verbose")
    return args


def failure_label(label: str) -> str:
    suffix = "-failure"
    return f"{label[: 63 - len(suffix)]}{suffix}"


def collect_failure_evidence(
    lab: Lab,
    args: argparse.Namespace,
    guest: str,
    label: str,
    guest_touched: bool,
) -> None:
    if lab.dry_run or not guest_touched:
        return
    if args.no_collect_on_failure and not args.capture_on_failure:
        return
    evidence_label = validate_name(args.failure_label or failure_label(label), "label")
    print(
        f"[dev] guest loop failed; collecting failure evidence with label {evidence_label}",
        file=sys.stderr,
    )
    if not args.no_collect_on_failure:
        run_vmctl(
            lab,
            [
                "collect",
                *lab_args(lab),
                "guest",
                guest,
                "--label",
                evidence_label,
                "--user",
                args.user,
                "--source",
                args.source,
            ],
            check=False,
        )
    if args.capture_on_failure:
        run_vmctl(
            lab,
            [
                "capture",
                *lab_args(lab),
                "host",
                guest,
                "--label",
                evidence_label,
                "--duration",
                str(args.failure_capture_duration),
                "--filter",
                "icmp or arp",
                "--probe",
                "ping -c 1 192.168.122.1",
                "--user",
                args.user,
                "--source",
                args.source,
                "--allow-empty",
            ],
            check=False,
        )


def run_vmctl(lab: Lab, args: list[str], *, check: bool = True) -> None:
    command = [sys.executable, str(ROOT / "scripts" / "vmctl.py"), *args]
    print("+ " + join(command), file=sys.stderr)
    if lab.dry_run:
        return
    result = subprocess.run(command, check=check)
    if not check and result.returncode != 0:
        print(
            f"[dev] evidence command failed with exit code {result.returncode}: {join(command)}",
            file=sys.stderr,
        )


def add_build_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--release", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run high-frequency dynet VM developer loops."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="build a Linux guest artifact")
    add_build_options(build_parser)

    guest_parser = subparsers.add_parser(
        "guest",
        help="build, install, smoke, and check dynet in a guest",
    )
    guest_parser.add_argument("guest")
    add_build_options(guest_parser)
    guest_parser.add_argument("--artifact", help="use an existing Linux guest artifact")
    guest_parser.add_argument("--label", default="cold-start")
    guest_parser.add_argument("--user", default=DEFAULT_VM_USER)
    guest_parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest_parser.add_argument("--no-install", action="store_true")
    guest_parser.add_argument("--no-smoke", action="store_true")
    guest_parser.add_argument("--no-check", action="store_true")
    guest_parser.add_argument("--collect", action="store_true")
    guest_parser.add_argument("--capture", action="store_true")
    guest_parser.add_argument("--failure-label")
    guest_parser.add_argument(
        "--no-collect-on-failure",
        action="store_true",
        help="do not collect host/guest evidence when install, smoke, or check fails",
    )
    guest_parser.add_argument("--capture-on-failure", action="store_true")
    guest_parser.add_argument("--failure-capture-duration", type=int, default=4)
    guest_parser.add_argument(
        "--allow-any-binary",
        action="store_true",
        help="skip Linux ELF validation before installing into the guest",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {"build": build_command, "guest": guest_command}
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
