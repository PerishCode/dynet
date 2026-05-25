#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
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
)
from lib.probe_smoke_artifact import extract_tar
from probe_smoke import (
    DEFAULT_TARGET,
    build_artifact,
    install_artifact,
    prepare_output_dir,
    run_local,
    write_guest_file,
)


SMOKE_SCRIPT = ROOT / "scripts" / "experiments" / "probe_smoke" / "quality_gap.py"
PIPELINE_SCRIPT = ROOT / "scripts" / "experiments" / "probe_smoke" / "quality_gap_pipeline.py"
SINKS_SCRIPT = ROOT / "scripts" / "experiments" / "probe_smoke" / "sinks.py"


def task_output_dir(raw: str | None, label: str) -> Path:
    base = (ROOT / ".task" / "resources").resolve(strict=False)
    if raw:
        path = Path(raw).expanduser()
        candidate = path if path.is_absolute() else ROOT / path
    else:
        candidate = base / "vm-quality-gap-smoke" / label
    resolved = candidate.resolve(strict=False)
    if resolved != base and base not in resolved.parents:
        raise CommandError(f"output must stay under .task/resources: {candidate}")
    return resolved


def run_guest_smoke(
    lab: Lab,
    guest: str,
    label: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    remote_source = f"/tmp/dynet-{label}-quality-gap-src"
    remote_script = f"{remote_source}/quality_gap.py"
    remote_pipeline = f"{remote_source}/quality_gap_pipeline.py"
    remote_sinks = f"{remote_source}/sinks.py"
    remote_output = f"/tmp/dynet-{label}-quality-gap-smoke"
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
        remote_pipeline,
        PIPELINE_SCRIPT.read_text(),
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
        "--skip-pipeline",
    ]
    logger.info("run guest quality-gap probe smoke: %s", join(command))
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
            f"guest quality-gap smoke failed with exit code {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CommandError(f"guest quality-gap smoke returned invalid JSON: {error}") from error
    return {"remoteOutput": remote_output, "stdout": parsed}


def collect_guest_output(
    lab: Lab,
    guest: str,
    label: str,
    remote_output: str,
    output_dir: Path,
    args: argparse.Namespace,
) -> None:
    remote_tar = f"/tmp/dynet-{label}-quality-gap-smoke.tar.gz"
    host_tar = lab.path("artifacts", "collect", f"{guest}-{label}-quality-gap-smoke.tar.gz")
    local_tar = output_dir.with_suffix(".tar.gz")
    guard_remote_resources(
        lab,
        "remote VM quality-gap smoke cache",
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
    dynet = Path(args.local_dynet_bin)
    if not dynet.is_absolute():
        dynet = ROOT / dynet
    if not dynet.exists():
        raise CommandError(
            f"local dynet binary does not exist: {dynet}; "
            "build it or pass --skip-local-pipeline"
        )
    run_local([
        sys.executable,
        str(SMOKE_SCRIPT),
        "--output-dir",
        str(output_dir),
        "--dynet-bin",
        str(dynet),
        "--pipeline-only",
    ])


def cleanup_guest_files(
    lab: Lab,
    guest: str,
    label: str,
    *,
    user: str,
    source: str,
) -> None:
    paths = [
        f"/tmp/dynet-{label}-quality-gap-src",
        f"/tmp/dynet-{label}-quality-gap-smoke",
        f"/tmp/dynet-{label}-quality-gap-smoke.tar.gz",
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
    label = args.label or datetime.now(timezone.utc).strftime("quality-gap-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    guard_repo_resources(
        "VM quality-gap smoke artifacts",
        [("vm-quality-gap-smoke", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    if lab.dry_run:
        print(json.dumps({"outputDir": str(output_dir), "guest": guest, "dryRun": True}))
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
        result = result_summary(output_dir, args.skip_local_pipeline)
        print(json.dumps(result, sort_keys=True))
    finally:
        cleanup_guest_files(
            lab,
            guest,
            label,
            user=args.user,
            source=args.source,
        )


def result_summary(output_dir: Path, skipped: bool) -> dict[str, Any]:
    summary = json.loads((output_dir / "summary.json").read_text())
    result = {
        "outputDir": str(output_dir),
        "attempted": summary.get("totals", {}).get("attempted"),
        "passed": summary.get("totals", {}).get("passed"),
        "failed": summary.get("totals", {}).get("failed"),
        "verification": "skipped",
    }
    if not skipped:
        verification = json.loads((output_dir / "verification.json").read_text())
        result["verification"] = verification.get("status")
        result["qualityRefresh"] = quality_refresh_summary(verification)
    return result


def quality_refresh_summary(verification: dict[str, Any]) -> dict[str, Any]:
    refresh = verification.get("qualityRefresh", {})
    entry = refresh.get("entry", {}) if isinstance(refresh, dict) else {}
    plan_quality = refresh.get("planQuality", {}) if isinstance(refresh, dict) else {}
    return {
        "attempts": entry.get("attempts"),
        "confidence": entry.get("confidence"),
        "score": plan_quality.get("score"),
        "stale": plan_quality.get("stale"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run sanitized repeated quality-gap dynet smokes inside a VM guest."
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
