#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_json, write_json

try:
    from probe_smoke.manifest_quality_refresh import run_window
    from probe_smoke.non_direct import config_json, smoke_entries
    from probe_smoke.sinks import TcpSink, TlsSink, combined_server_summary
except ModuleNotFoundError:
    from manifest_quality_refresh import run_window
    from non_direct import config_json, smoke_entries
    from sinks import TcpSink, TlsSink, combined_server_summary


DEFAULT_OUTPUT_DIR = ".task/resources/non-direct-manifest-refresh-smoke/latest"
PLAN_CANDIDATES = {
    "private-ss": "candidate.example",
    "private-vmess": "candidate-vmess.example",
    "private-trojan": "candidate-trojan.example",
}


def manifest_json() -> dict[str, Any]:
    return {
        "schema": "dynet-real-access-manifest/v1alpha1",
        "entries": [
            {
                "id": entry["id"],
                "bucket": entry["bucket"],
                "behavior": entry["behavior"],
                "groupId": f"repeat-{entry['behavior']}",
                "domain": entry["domain"],
                "port": 443,
                "probe": entry["probe"],
                "scheduledOffsetMs": index * 100,
                "timeoutMs": 5000,
            }
            for index, entry in enumerate(smoke_entries())
        ],
    }


def verify(output_dir: Path) -> dict[str, Any]:
    errors: list[str] = []
    first = load_json(output_dir / "window-a" / "summary.json")
    second = load_json(output_dir / "window-b" / "summary.json")
    state = load_json(output_dir / "window-b" / "quality-state.json")
    pipeline = load_json(output_dir / "window-b" / "quality-pipeline.json")
    attribution = load_json(output_dir / "window-b" / "attribution.json")
    server = load_json(output_dir / "server.json")

    attempted = len(smoke_entries())
    if first["totals"].get("failed") != 0 or second["totals"].get("failed") != 0:
        errors.append("expected both non-direct manifest windows to pass")
    if first["totals"].get("attempted") != attempted:
        errors.append("expected first window to attempt all non-direct entries")
    if second["totals"].get("attempted") != attempted:
        errors.append("expected second window to attempt all non-direct entries")
    if server.get("connections") != attempted * 2:
        errors.append("expected protocol sink connections across both windows")
    if server.get("rawPayloadStored") is not False:
        errors.append("server artifact must not store raw payload")
    if int(server.get("totalBytes") or 0) <= 0:
        errors.append("expected encrypted protocol bytes to reach sinks")
    if pipeline.get("previousQualityStates") != 1:
        errors.append("expected second window to retain one previous quality state")
    if pipeline.get("previousAttributions") != 1:
        errors.append("expected second window to batch one previous attribution")
    if pipeline.get("plannerFeedback", {}).get("penaltyObservations") != 0:
        errors.append("observe mode should not emit penalty observations")
    if state.get("source", {}).get("retainedPreviousStates") != 1:
        errors.append("expected refreshed state to retain first window state")
    if int(state.get("source", {}).get("retainedPreviousEntries") or 0) <= 0:
        errors.append("expected refreshed state to retain previous entries")
    if int(state.get("source", {}).get("currentEntries") or 0) <= 0:
        errors.append("expected refreshed state to include current entries")
    for outbound, family in PLAN_CANDIDATES.items():
        entry = quality_entry(state, outbound, family)
        if not entry or int(entry.get("attempts") or 0) < 2:
            errors.append(f"expected refreshed quality for {outbound}")
    quality = attribution.get("candidateQuality", {})
    if int(quality.get("withQuality") or 0) < attempted:
        errors.append("expected candidate quality on every second-window path")
    if int(quality.get("selectedBehind") or 0) != 0:
        errors.append("expected no selected-vs-best gap in non-direct control")

    result = {
        "schema": "dynet-non-direct-manifest-refresh-verification/v1alpha1",
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "firstWindow": first["totals"],
        "secondWindow": second["totals"],
        "server": {
            "connections": server.get("connections"),
            "totalBytes": server.get("totalBytes"),
            "rawPayloadStored": server.get("rawPayloadStored"),
        },
        "qualityPipeline": {
            "previousQualityStates": pipeline.get("previousQualityStates"),
            "previousAttributions": pipeline.get("previousAttributions"),
            "plannerFeedback": pipeline.get("plannerFeedback", {}),
        },
        "qualityState": {
            "source": state.get("source", {}),
            "planCandidates": {
                outbound: entry_summary(quality_entry(state, outbound, family))
                for outbound, family in PLAN_CANDIDATES.items()
            },
        },
        "candidateQuality": quality,
    }
    write_json(output_dir / "verification.json", result)
    return result


def quality_entry(
    state: dict[str, Any],
    outbound: str,
    target_family: str,
) -> dict[str, Any] | None:
    for item in state.get("outbounds", []):
        if (
            item.get("outbound") == outbound
            and item.get("scope") == "plan-candidate"
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
    entries = smoke_entries()
    raw_expected = sum(1 for entry in entries if "trojan" not in entry["behavior"]) * 2
    tls_expected = (len(entries) * 2) - raw_expected
    with TcpSink(expected=raw_expected) as raw_server, TlsSink(expected=tls_expected) as tls_server:
        manifest_path = output_dir / "manifest.json"
        config_path = output_dir / "dynet.json"
        write_json(manifest_path, manifest_json())
        write_json(config_path, config_json(raw_server.port, tls_server.port))

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
        server_summary = combined_server_summary(raw_server.summary(), tls_server.summary())
    write_json(output_dir / "server.json", server_summary)
    verification = verify(output_dir)
    print(json.dumps({
        "outputDir": str(output_dir),
        "status": verification["status"],
        "firstWindow": verification["firstWindow"],
        "secondWindow": verification["secondWindow"],
        "server": verification["server"],
        "qualityState": verification["qualityState"],
    }, sort_keys=True))
    return 0 if verification["status"] == "pass" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run repeated non-direct manifest windows with quality refresh."
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
