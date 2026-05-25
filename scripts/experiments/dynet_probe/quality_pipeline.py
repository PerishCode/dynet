from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from scripts.cli import dynet_probe_quality
from dynet_trace.probe import build_probe_attribution, write_probe_attribution_report
from dynet_trace.probe_batch import build_probe_batch, write_probe_batch_report
from dynet_trace.quality_feedback import write_quality_report


def build_quality_pipeline(output_dir: Path, args: Any) -> dict[str, Any]:
    summary_path = output_dir / "summary.json"
    attribution_path = output_path(args.attribution_output_json, output_dir, "attribution.json")
    attribution_md = output_path(args.attribution_output_md, output_dir, "attribution.md")
    batch_path = output_path(args.probe_batch_output_json, output_dir, "probe-batch.json")
    batch_md = output_path(args.probe_batch_output_md, output_dir, "probe-batch.md")
    quality_path = output_path(args.quality_output_json, output_dir, "quality-state.json")
    quality_md = output_path(args.quality_output_md, output_dir, "quality-state.md")

    attribution = build_probe_attribution(summary_path)
    dynet_probe_quality.write_json(attribution_path, attribution)
    write_probe_attribution_report(attribution_md, attribution)

    attribution_inputs = [Path(path) for path in args.previous_attribution or []]
    attribution_inputs.append(attribution_path)
    probe_batch = build_probe_batch(attribution_inputs, args.min_repeat_runs)
    dynet_probe_quality.write_json(batch_path, probe_batch)
    write_probe_batch_report(batch_md, probe_batch)

    state = dynet_probe_quality.build_state(
        SimpleNamespace(
            input=[str(output_dir)],
            now_unix_ms=args.quality_now_unix_ms,
            window_seconds=args.quality_window_seconds,
            ttl_seconds=args.quality_ttl_seconds,
            previous_state=args.previous_quality_state or [],
            probe_batch=[str(batch_path)],
            quality_gap_mode=args.quality_gap_mode,
            quality_gap_promotion_proof=getattr(args, "quality_gap_promotion_proof", None) or [],
            quality_gap_promotion_context=getattr(args, "quality_gap_promotion_context", None) or [],
        )
    )
    dynet_probe_quality.write_json(quality_path, state)
    write_quality_report(quality_md, state)

    pipeline = {
        "schema": "dynet-probe-manifest-quality-pipeline/v1alpha1",
        "status": "complete",
        "attribution": str(attribution_path),
        "probeBatch": str(batch_path),
        "qualityState": str(quality_path),
        "qualityReport": str(quality_md),
        "previousAttributions": len(args.previous_attribution or []),
        "previousQualityStates": len(args.previous_quality_state or []),
        "qualityGapMode": args.quality_gap_mode,
        "qualityGapPromotion": state.get("plannerFeedback", {}).get("promotion", {}),
        "qualityGapPromotionContexts": (
            state.get("plannerFeedback", {})
            .get("promotion", {})
            .get("contexts", 0)
        ),
        "minRepeatRuns": args.min_repeat_runs,
        "outbounds": len(state.get("outbounds", [])),
        "signals": len(state.get("signals", [])),
        "plannerFeedback": state.get("plannerFeedback", {}),
        "source": state.get("source", {}),
    }
    dynet_probe_quality.write_json(output_dir / "quality-pipeline.json", pipeline)
    return pipeline


def output_path(raw: str | None, output_dir: Path, default_name: str) -> Path:
    if not raw:
        return output_dir / default_name
    path = Path(raw)
    return path if path.is_absolute() else output_dir / path
