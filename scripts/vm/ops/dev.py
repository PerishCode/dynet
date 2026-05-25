#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
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
    lab_cli_args,
    logger,
    validate_name,
    vmctl_command,
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
    logger.debug("run: %s", join(command))
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
        artifact = resolve_artifact(lab, args)
        guest_touched = run_guest_loop(lab, args, guest, label, artifact)
    except subprocess.CalledProcessError as error:
        collect_failure_evidence(lab, args, guest, label, guest_touched)
        raise error


def resolve_artifact(lab: Lab, args: argparse.Namespace) -> Path:
    if not args.artifact:
        return build_artifact(lab, args)
    artifact = Path(args.artifact).expanduser().resolve()
    if not lab.dry_run:
        require_guest_elf(artifact, allow_any_binary=args.allow_any_binary)
    return artifact


def run_guest_loop(
    lab: Lab,
    args: argparse.Namespace,
    guest: str,
    label: str,
    artifact: Path,
) -> bool:
    touched = False
    if not args.no_install:
        touched = True
        install_guest_artifact(lab, args, guest, artifact)
    if not args.no_smoke:
        touched = True
        run_guest_smoke(lab, args, guest, label)
    if not args.no_check:
        touched = True
        run_vmctl(lab, ["check", *lab_args(lab), "guest", guest])
    return touched


def install_guest_artifact(
    lab: Lab, args: argparse.Namespace, guest: str, artifact: Path
) -> None:
    command = [
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
    if args.allow_any_binary:
        command.append("--allow-any-binary")
    run_vmctl(lab, command)


def run_guest_smoke(lab: Lab, args: argparse.Namespace, guest: str, label: str) -> None:
    command = [
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
        command.append("--collect")
    if args.capture:
        command.append("--capture")
    run_vmctl(lab, command)


def lab_args(lab: Lab) -> list[str]:
    return lab_cli_args(lab)


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
    logger.warning(
        "guest loop failed; collecting failure evidence with label %s",
        evidence_label,
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
    command = vmctl_command(*args)
    logger.info("run vmctl: %s", join(command))
    if lab.dry_run:
        return
    result = subprocess.run(command, cwd=ROOT, check=check)
    if not check and result.returncode != 0:
        logger.error(
            "evidence command failed with exit code %s: %s",
            result.returncode,
            join(command),
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
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
