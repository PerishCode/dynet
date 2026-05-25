#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import (
    DEFAULT_VM_USER,
    ROOT,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_remote_resources,
    guard_repo_resources,
    guest_scp_to_host,
    guest_ssh,
    join,
    logger,
    q,
    validate_name,
    vmctl_command,
)
from lib.probe_smoke_artifact import (
    extract_tar,
    load_json,
    rewrite_summary_report_paths,
    write_verification,
)


DEFAULT_TARGET = "x86_64-unknown-linux-gnu"
SMOKE_SCRIPT = ROOT / "scripts" / "experiments" / "probe_smoke" / "non_direct.py"
SINKS_SCRIPT = ROOT / "scripts" / "experiments" / "probe_smoke" / "sinks.py"


def task_output_dir(raw: str | None, label: str) -> Path:
    base = (ROOT / ".task" / "resources").resolve(strict=False)
    if raw:
        path = Path(raw).expanduser()
        candidate = path if path.is_absolute() else ROOT / path
    else:
        candidate = base / "vm-probe-smoke" / label
    resolved = candidate.resolve(strict=False)
    if resolved != base and base not in resolved.parents:
        raise CommandError(f"output must stay under .task/resources: {candidate}")
    return resolved


def lab_args(lab: Lab) -> list[str]:
    args = ["--host", lab.host, "--lab-root", lab.root]
    if lab.dry_run:
        args.append("--dry-run")
    if lab.verbose:
        args.append("--verbose")
    if lab.log_level != "info":
        args.extend(["--log-level", lab.log_level])
    return args


def build_artifact(lab: Lab, args: argparse.Namespace) -> Path:
    if args.artifact:
        return Path(args.artifact).expanduser().resolve()
    command = vmctl_command(
        "dev",
        *lab_args(lab),
        "build",
        "--target",
        args.target,
    )
    if args.release:
        command.append("--release")
    logger.info("build guest artifact: %s", join(command))
    if lab.dry_run:
        profile = "release" if args.release else "debug"
        return ROOT / "target" / args.target / profile / "dynet"
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise CommandError("dev build did not print an artifact path")
    return Path(lines[-1]).resolve()


def install_artifact(lab: Lab, guest: str, artifact: Path, args: argparse.Namespace) -> None:
    command = vmctl_command(
        "setup",
        *lab_args(lab),
        "install-bin",
        guest,
        str(artifact),
        "--user",
        args.user,
        "--source",
        args.source,
        "--dest",
        args.dynet_bin,
    )
    logger.info("install guest artifact: %s", join(command))
    if not lab.dry_run:
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)


def write_guest_file(
    lab: Lab,
    guest: str,
    path: str,
    content: str,
    *,
    user: str,
    source: str,
) -> None:
    guest_ssh(
        lab,
        guest,
        f"umask 077 && cat > {q(path)}",
        user=user,
        source=source,
        input_text=content,
    )


def run_guest_smoke(
    lab: Lab,
    guest: str,
    label: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    remote_source = f"/tmp/dynet-{label}-probe-smoke-src"
    remote_script = f"{remote_source}/non_direct.py"
    remote_sinks = f"{remote_source}/sinks.py"
    remote_output = f"/tmp/dynet-{label}-non-direct-smoke"
    guest_ssh(
        lab,
        guest,
        f"rm -rf {q(remote_source)} && install -d -m 0700 {q(remote_source)}",
        user=args.user,
        source=args.source,
    )
    write_guest_file(
        lab,
        guest,
        remote_script,
        SMOKE_SCRIPT.read_text(),
        user=args.user,
        source=args.source,
    )
    write_guest_file(
        lab,
        guest,
        remote_sinks,
        SINKS_SCRIPT.read_text(),
        user=args.user,
        source=args.source,
    )
    command = [
        "python3",
        remote_script,
        "--output-dir",
        remote_output,
        "--dynet-bin",
        args.dynet_bin,
    ]
    logger.info("run guest non-direct probe smoke: %s", join(command))
    result = guest_ssh(
        lab,
        guest,
        join(command),
        user=args.user,
        source=args.source,
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        raise CommandError(
            f"guest probe smoke failed with exit code {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CommandError(f"guest probe smoke returned invalid JSON: {error}") from error
    return {"remoteOutput": remote_output, "stdout": parsed}


def collect_guest_output(
    lab: Lab,
    guest: str,
    label: str,
    remote_output: str,
    output_dir: Path,
    args: argparse.Namespace,
) -> None:
    remote_tar = f"/tmp/dynet-{label}-non-direct-smoke.tar.gz"
    host_tar = lab.path("artifacts", "collect", f"{guest}-{label}-non-direct-smoke.tar.gz")
    local_tar = output_dir.with_suffix(".tar.gz")
    guard_remote_resources(
        lab,
        "remote VM probe smoke cache",
        [("collect", lab.path("artifacts", "collect"))],
        RESOURCE_LIMITS["collect"],
    )
    guest_ssh(
        lab,
        guest,
        f"tar -C {q(remote_output)} -czf {q(remote_tar)} .",
        user=args.user,
        source=args.source,
    )
    guest_scp_to_host(
        lab,
        guest,
        remote_tar,
        host_tar,
        user=args.user,
        source=args.source,
    )
    lab.scp_from_host(host_tar, local_tar)
    extract_tar(local_tar, output_dir)


def run_local_pipeline(output_dir: Path, args: argparse.Namespace) -> None:
    rewrite_summary_report_paths(output_dir)
    run_local(
        [
            sys.executable,
            str(ROOT / "scripts" / "experiments" / "dynet_trace_attribution.py"),
            "probe-manifest",
            "--summary",
            str(output_dir / "summary.json"),
            "--output-json",
            str(output_dir / "attribution.json"),
            "--output-md",
            str(output_dir / "attribution.md"),
        ]
    )
    run_local(
        [
            sys.executable,
            str(ROOT / "scripts" / "experiments" / "dynet_trace_attribution.py"),
            "probe-batch",
            "--attribution",
            str(output_dir / "attribution.json"),
            "--output-json",
            str(output_dir / "probe-batch.json"),
            "--output-md",
            str(output_dir / "probe-batch.md"),
        ]
    )
    build_quality(output_dir, "observe")
    build_quality(output_dir, "penalize")
    if not args.skip_plan:
        run_plan(output_dir, args)
    write_verification(output_dir, require_plan=not args.skip_plan)


def run_plan(output_dir: Path, args: argparse.Namespace) -> None:
    dynet = Path(args.local_dynet_bin)
    if not dynet.is_absolute():
        dynet = ROOT / dynet
    if not dynet.exists():
        raise CommandError(
            f"local dynet binary does not exist: {dynet}; "
            "build it or pass --skip-plan"
        )
    run_plan_one(dynet, output_dir, "candidate.example", "plan-candidate.json")
    run_plan_one(
        dynet,
        output_dir,
        "candidate-vmess.example",
        "plan-candidate-vmess.json",
    )
    run_plan_one(
        dynet,
        output_dir,
        "candidate-trojan.example",
        "plan-candidate-trojan.json",
    )


def run_plan_one(dynet: Path, output_dir: Path, domain: str, filename: str) -> None:
    result = run_local(
        [
            str(dynet),
            "plan",
            "--config",
            str(output_dir / "dynet.json"),
            "--quality-state",
            str(output_dir / "quality-observe.json"),
            "--context",
            plan_context(domain),
            "--format",
            "json",
        ],
        capture=True,
    )
    (output_dir / filename).write_text(result.stdout)


def plan_context(domain: str) -> str:
    return json.dumps({"destinationDomain": domain}, sort_keys=True)


def run_local(
    command: list[str],
    *,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    logger.info("run local: %s", join(command))
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=capture,
        text=True,
    )


def build_quality(output_dir: Path, mode: str) -> None:
    run_local(
        [
            sys.executable,
            str(ROOT / "scripts" / "experiments" / "dynet_probe_quality.py"),
            "build",
            str(output_dir),
            "--probe-batch",
            str(output_dir / "probe-batch.json"),
            "--output-json",
            str(output_dir / f"quality-{mode}.json"),
            "--output-md",
            str(output_dir / f"quality-{mode}.md"),
            "--quality-gap-mode",
            mode,
            "--ttl-seconds",
            "300",
            "--window-seconds",
            "1800",
        ]
    )


def prepare_output_dir(output_dir: Path, overwrite: bool) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        if not overwrite:
            raise CommandError(f"output directory is not empty: {output_dir}")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def cleanup_guest_files(
    lab: Lab,
    guest: str,
    label: str,
    *,
    user: str,
    source: str,
) -> None:
    paths = [
        f"/tmp/dynet-{label}-probe-smoke-src",
        f"/tmp/dynet-{label}-non-direct-smoke",
        f"/tmp/dynet-{label}-non-direct-smoke.tar.gz",
    ]
    guest_ssh(
        lab,
        guest,
        "rm -rf " + " ".join(q(path) for path in paths),
        user=user,
        source=source,
        check=False,
    )


def command_guest(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    label = args.label or datetime.now(timezone.utc).strftime("probe-smoke-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    guard_repo_resources(
        "VM probe smoke artifacts",
        [("vm-probe-smoke", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    if lab.dry_run:
        print(
            json.dumps(
                {
                    "outputDir": str(output_dir),
                    "guest": guest,
                    "label": label,
                    "dryRun": True,
                },
                sort_keys=True,
            )
        )
        return
    prepare_output_dir(output_dir, args.overwrite)

    if not args.skip_install:
        artifact = build_artifact(lab, args)
        install_artifact(lab, guest, artifact, args)

    try:
        guest_result = run_guest_smoke(lab, guest, label, args)
        collect_guest_output(
            lab,
            guest,
            label,
            guest_result["remoteOutput"],
            output_dir,
            args,
        )
        if not args.skip_local_pipeline:
            run_local_pipeline(output_dir, args)
        summary = load_json(output_dir / "summary.json")
        result = {
            "outputDir": str(output_dir),
            "attempted": summary.get("totals", {}).get("attempted"),
            "passed": summary.get("totals", {}).get("passed"),
            "failed": summary.get("totals", {}).get("failed"),
            "verification": "skipped"
            if args.skip_local_pipeline
            else load_json(output_dir / "verification.json").get("status"),
        }
        print(json.dumps(result, sort_keys=True))
    finally:
        cleanup_guest_files(
            lab,
            guest,
            label,
            user=args.user,
            source=args.source,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run sanitized non-direct dynet probe smokes inside a VM guest."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    guest = subparsers.add_parser("guest")
    guest.add_argument("guest")
    guest.add_argument("--label")
    guest.add_argument("--output-dir")
    guest.add_argument("--user", default=DEFAULT_VM_USER)
    guest.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest.add_argument("--skip-install", action="store_true")
    guest.add_argument("--artifact")
    guest.add_argument("--target", default=DEFAULT_TARGET)
    guest.add_argument("--release", action="store_true")
    guest.add_argument("--dynet-bin", default="/usr/local/bin/dynet")
    guest.add_argument("--local-dynet-bin", default="target/debug/dynet")
    guest.add_argument("--skip-local-pipeline", action="store_true")
    guest.add_argument("--skip-plan", action="store_true")
    guest.add_argument("--overwrite", action="store_true")
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
