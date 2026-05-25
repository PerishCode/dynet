#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_json, write_json


DEFAULT_OUTPUT_DIR = ".task/resources/manifest-quality-refresh-smoke/latest"
DOMAIN = "example.com"


def config_json() -> dict[str, Any]:
    return {
        "inbounds": [{"tag": "mixed-in", "type": "mixed"}],
        "outbounds": [
            {"tag": "direct", "type": "direct"},
            {
                "tag": "auto-direct",
                "type": "plan",
                "capabilities": ["tcp", "ip-target", "domain-target", "probeable"],
                "payload": {
                    "strategy": {
                        "source": "internal",
                        "key": "cascade-quality",
                        "version": "",
                        "options": {},
                    },
                    "selection": {"edges": [{"type": "candidate", "to": "direct"}]},
                },
            },
        ],
        "routes": [
            {"inbound": "mixed-in", "outbound": "auto-direct"},
            {"outbound": "direct"},
        ],
    }


def manifest_json() -> dict[str, Any]:
    return {
        "schema": "dynet-real-access-manifest/v1alpha1",
        "entries": [
            manifest_entry("0001", 0),
            manifest_entry("0002", 100),
        ],
    }


def manifest_entry(entry_id: str, offset_ms: int) -> dict[str, Any]:
    return {
        "id": entry_id,
        "bucket": "control-global",
        "behavior": "repeat",
        "groupId": f"repeat-{DOMAIN}",
        "domain": DOMAIN,
        "port": 443,
        "probe": "tls-handshake",
        "scheduledOffsetMs": offset_ms,
        "timeoutMs": 5000,
    }


def run_window(
    args: argparse.Namespace,
    output_dir: Path,
    manifest_path: Path,
    config_path: Path,
    quality_state: Path | None = None,
    previous_state: Path | None = None,
    previous_attr: Path | None = None,
) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "scripts.cli.dynet_probe_manifest",
        "--manifest",
        str(manifest_path),
        "--config",
        str(config_path),
        "--output-dir",
        str(output_dir),
        "--dynet-bin",
        args.dynet_bin,
        "--inbound",
        "mixed-in",
        "--build-quality-state",
        "--dynet-protocol",
        "source",
        "--quality-gap-mode",
        "observe",
        "--quality-ttl-seconds",
        str(args.quality_ttl_seconds),
        "--quality-window-seconds",
        str(args.quality_window_seconds),
    ]
    if quality_state:
        command.extend(["--quality-state", str(quality_state)])
    if previous_state:
        command.extend(["--previous-quality-state", str(previous_state)])
    if previous_attr:
        command.extend(["--previous-attribution", str(previous_attr)])
    result = subprocess.run(command, capture_output=True, check=False, text=True)
    command_result = parse_command_result(result)
    write_json(output_dir / "command.json", command_result)
    if result.returncode != 0:
        raise SystemExit(
            f"manifest window failed with exit code {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    return command_result


def parse_command_result(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        parsed = {"rawStdout": result.stdout}
    return {
        "returnCode": result.returncode,
        "stdout": parsed,
        "stderr": result.stderr.strip(),
    }


def verify(output_dir: Path) -> dict[str, Any]:
    errors: list[str] = []
    first = load_json(output_dir / "window-a" / "summary.json")
    second = load_json(output_dir / "window-b" / "summary.json")
    state = load_json(output_dir / "window-b" / "quality-state.json")
    pipeline = load_json(output_dir / "window-b" / "quality-pipeline.json")
    attribution = load_json(output_dir / "window-b" / "attribution.json")
    entry = quality_entry(state, "direct", "plan-candidate", DOMAIN)

    if first["totals"].get("failed") != 0 or second["totals"].get("failed") != 0:
        errors.append("expected both manifest windows to pass")
    if pipeline.get("previousQualityStates") != 1:
        errors.append("expected second window to retain one previous quality state")
    if pipeline.get("previousAttributions") != 1:
        errors.append("expected second window to batch one previous attribution")
    if state["source"].get("retainedPreviousStates") != 1:
        errors.append("expected refreshed state to retain the first window state")
    if state["source"].get("retainedPreviousEntries", 0) <= 0:
        errors.append("expected refreshed state to retain prior entries")
    if state["source"].get("currentEntries", 0) <= 0:
        errors.append("expected refreshed state to include current entries")
    if not entry or int(entry.get("attempts") or 0) < 4:
        errors.append("expected example.com direct plan-candidate attempts to merge")
    if entry and entry.get("confidence") != "medium":
        errors.append("expected merged example.com confidence to be medium")
    if pipeline.get("plannerFeedback", {}).get("penaltyObservations") != 0:
        errors.append("observe mode should not emit penalty observations")
    quality = attribution.get("candidateQuality", {})
    if int(quality.get("withQuality") or 0) < 2:
        errors.append("expected second window attribution to carry candidate quality")
    if int(quality.get("selectedBehind") or 0) != 0:
        errors.append("expected no selected-vs-best gap in direct control smoke")

    result = {
        "schema": "dynet-manifest-quality-refresh-smoke-verification/v1alpha1",
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "firstWindow": first["totals"],
        "secondWindow": second["totals"],
        "qualityPipeline": {
            "previousQualityStates": pipeline.get("previousQualityStates"),
            "previousAttributions": pipeline.get("previousAttributions"),
            "plannerFeedback": pipeline.get("plannerFeedback", {}),
        },
        "qualityState": {
            "source": state.get("source", {}),
            "entry": entry_summary(entry),
        },
        "candidateQuality": quality,
    }
    write_json(output_dir / "verification.json", result)
    return result


def quality_entry(
    state: dict[str, Any],
    outbound: str,
    scope: str,
    target_family: str,
) -> dict[str, Any] | None:
    for item in state.get("outbounds", []):
        if (
            item.get("outbound") == outbound
            and item.get("scope") == scope
            and item.get("targetFamily") == target_family
        ):
            return item
    return None


def entry_summary(entry: dict[str, Any] | None) -> dict[str, Any]:
    if not entry:
        return {}
    return {
        "outbound": entry.get("outbound"),
        "scope": entry.get("scope"),
        "targetFamily": entry.get("targetFamily"),
        "attempts": entry.get("attempts"),
        "successes": entry.get("successes"),
        "failures": entry.get("failures"),
        "confidence": entry.get("confidence"),
    }


def command_run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    config_path = output_dir / "dynet.json"
    write_json(manifest_path, manifest_json())
    write_json(config_path, config_json())

    run_window(args, output_dir / "window-a", manifest_path, config_path)
    first_state = output_dir / "window-a" / "quality-state.json"
    first_attr = output_dir / "window-a" / "attribution.json"
    run_window(
        args,
        output_dir / "window-b",
        manifest_path,
        config_path,
        quality_state=first_state,
        previous_state=first_state,
        previous_attr=first_attr,
    )
    verification = verify(output_dir)
    print(json.dumps({
        "outputDir": str(output_dir),
        "status": verification["status"],
        "firstWindow": verification["firstWindow"],
        "secondWindow": verification["secondWindow"],
        "qualityState": verification["qualityState"],
    }, sort_keys=True))
    return 0 if verification["status"] == "pass" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run repeated manifest windows through quality-state refresh."
    )
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dynet-bin", default="target/debug/dynet")
    parser.add_argument("--quality-ttl-seconds", type=int, default=3600)
    parser.add_argument("--quality-window-seconds", type=int, default=3600)
    parser.set_defaults(handler=command_run)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
