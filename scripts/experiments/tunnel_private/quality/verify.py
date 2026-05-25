from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tunnel_private_config import write_json


def verify(
    output_dir: Path,
    *,
    require_pass: bool = True,
    probe_mode: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    mode = probe_mode or verified_mode(output_dir)
    first = load_json(output_dir / "window-a" / "summary.json")
    second = load_json(output_dir / "window-b" / "summary.json")
    state = load_json(output_dir / "window-b" / "quality-state.json")
    first_pipeline = load_json(output_dir / "window-a" / "quality-pipeline.json")
    pipeline = load_json(output_dir / "window-b" / "quality-pipeline.json")
    attribution = load_json(output_dir / "window-b" / "attribution.json")
    plan_entries = quality_entries(state, "plan-candidate")
    bound_entries = quality_entries(state, "dialer-bound")
    mode_entries = plan_entries if mode == "candidate" else bound_entries

    if require_pass and (
        first["totals"].get("failed") != 0 or second["totals"].get("failed") != 0
    ):
        errors.append("expected both Tunnel/Private refresh windows to pass")
    if pipeline.get("previousQualityStates") != 1:
        errors.append("expected window B to retain one previous quality state")
    if pipeline.get("previousAttributions") != 1:
        errors.append("expected window B to batch one previous attribution")
    if pipeline.get("plannerFeedback", {}).get("penaltyObservations") != 0:
        errors.append("observe mode should not emit penalty observations")
    if state.get("source", {}).get("retainedPreviousStates") != 1:
        errors.append("expected refreshed state to retain window A state")
    if int(state.get("source", {}).get("retainedPreviousEntries") or 0) <= 0:
        errors.append("expected refreshed state to retain previous entries")
    if int(state.get("source", {}).get("currentEntries") or 0) <= 0:
        errors.append("expected refreshed state to include current entries")
    if not mode_entries:
        errors.append(f"expected refreshed {mode_quality_scope(mode)} Tunnel candidate quality")
    quality = attribution.get("candidateQuality", {})
    bound = bound_selection_summary(second)
    if mode == "private":
        verify_private_refresh(errors, quality, bound, second)

    result = {
        "schema": "dynet-tunnel-private-quality-refresh-verification/v1alpha1",
        "status": "pass" if not errors else "fail",
        "probeMode": mode,
        "requirePass": require_pass,
        "errors": errors,
        "firstWindow": first["totals"],
        "secondWindow": second["totals"],
        "failureScopes": {
            "windowA": failure_scope_counts(first),
            "windowB": failure_scope_counts(second),
        },
        "readFailures": {
            "windowA": read_failure_counts(first),
            "windowB": read_failure_counts(second),
        },
        "failures": {
            "windowA": failure_rows(first),
            "windowB": failure_rows(second),
        },
        "qualityPipeline": {
            "previousQualityStates": pipeline.get("previousQualityStates"),
            "previousAttributions": pipeline.get("previousAttributions"),
            "plannerFeedback": pipeline.get("plannerFeedback", {}),
        },
        "windowPipelines": {
            "windowA": pipeline_summary(first_pipeline),
            "windowB": pipeline_summary(pipeline),
        },
        "qualityState": {
            "source": state.get("source", {}),
            "planCandidate": [entry_summary(item) for item in plan_entries],
            "dialerBound": [entry_summary(item) for item in bound_entries],
        },
        "candidateQuality": quality,
        "boundSelection": {
            "windowA": bound_selection_summary(first),
            "windowB": bound,
        },
    }
    write_json(output_dir / "verification.json", result)
    return result


def verify_private_refresh(
    errors: list[str],
    quality: dict[str, Any],
    bound: dict[str, Any],
    second: dict[str, Any],
) -> None:
    attempted = int(second["totals"].get("attempted") or 0)
    if int(quality.get("withQuality") or 0) < attempted:
        errors.append("expected candidate quality on every window-B probe")
    if int(bound.get("withBoundSelected") or 0) < attempted:
        errors.append("expected every window-B probe to select a bound candidate")
    if int(bound.get("selectedWithQuality") or 0) < attempted:
        errors.append("expected selected bound candidate quality on every window-B probe")
    if int(bound.get("selectedBehind") or 0) > 0:
        errors.append("expected selected bound candidates not to trail best quality")


def verified_mode(output_dir: Path) -> str:
    meta_path = output_dir / "meta.json"
    if not meta_path.exists():
        return "private"
    meta = load_json(meta_path)
    return str(meta.get("probeMode") or "private")


def mode_quality_scope(mode: str) -> str:
    if mode == "candidate":
        return "plan-candidate"
    return "dialer-bound"


def pipeline_summary(pipeline: dict[str, Any]) -> dict[str, Any]:
    return {
        "previousQualityStates": pipeline.get("previousQualityStates"),
        "previousAttributions": pipeline.get("previousAttributions"),
        "plannerFeedback": pipeline.get("plannerFeedback", {}),
    }


def failure_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in summary.get("items", []):
        if not isinstance(item, dict) or item.get("status") == "pass":
            continue
        row = {
            "id": item.get("id"),
            "status": item.get("status"),
            "failureScope": item.get("failureScope"),
            "selectedOutbound": item.get("selectedOutbound"),
            "failedStage": item.get("failedStage"),
        }
        if item.get("readFailure"):
            row["readFailure"] = item["readFailure"]
        rows.append(row)
    return rows


def failure_scope_counts(summary: dict[str, Any]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in failure_rows(summary):
        key = str(item.get("failureScope") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def read_failure_summary(report: dict[str, Any]) -> dict[str, Any]:
    event = failed_read_event(report)
    if not event:
        return {}
    fields = event.get("fields")
    if not isinstance(fields, dict):
        return {}
    marker = protocol_read_marker(fields)
    return {
        "stage": fields.get("stage"),
        "outbound": fields.get("outbound"),
        "status": fields.get("status"),
        "errorType": fields.get("errorType"),
        "marker": marker,
        "protocolStage": fields.get("protocolReadStage"),
        "context": protocol_read_context(marker, fields),
        "disposition": protocol_read_disposition(marker, fields),
        "pendingRetries": int_or_none(fields.get("pendingRetries")),
        "pendingBudgetMs": int_or_none(fields.get("pendingBudgetMs")),
    }


def read_failure_counts(summary: dict[str, Any]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in failure_rows(summary):
        read_failure = item.get("readFailure")
        if not isinstance(read_failure, dict) or not read_failure:
            continue
        key = str(
            read_failure.get("disposition")
            or read_failure.get("marker")
            or read_failure.get("stage")
            or "unknown"
        )
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def failed_read_event(report: dict[str, Any]) -> dict[str, Any]:
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("kind") != "outbound-stage-finished":
            continue
        fields = event.get("fields")
        if not isinstance(fields, dict):
            continue
        if fields.get("stage") == "stream-first-read" and fields.get("status") == "failed":
            return event
    return {}


def protocol_read_marker(fields: dict[str, Any]) -> str | None:
    marker = fields.get("protocolReadMarker")
    if marker:
        return str(marker)
    error = str(fields.get("error") or "")
    if "VMess response header length is not ready" in error:
        return "vmess-response-header-length-pending"
    if "failed to read VMess response header length: unexpected EOF" in error:
        return "vmess-response-header-length-eof"
    if "failed to read VMess response header length" in error:
        return "vmess-response-header-length-read"
    return None


def protocol_read_disposition(marker: str | None, fields: dict[str, Any]) -> str | None:
    value = fields.get("protocolReadDisposition")
    if value:
        return str(value)
    if marker == "vmess-response-header-length-pending" and pending_budget_exhausted(fields):
        return "pending-budget-exhausted"
    if marker == "vmess-response-header-length-eof":
        return "remote-eof"
    if marker == "vmess-response-header-length-read":
        return "read-error"
    return None


def protocol_read_context(marker: str | None, fields: dict[str, Any]) -> str | None:
    value = fields.get("protocolReadContext")
    if value:
        return str(value)
    error = str(fields.get("error") or "")
    if "Shadowsocks response salt" in error:
        return "shadowsocks-response-salt"
    if "Shadowsocks chunk length" in error:
        return "shadowsocks-chunk-length"
    if "Shadowsocks chunk payload" in error:
        return "shadowsocks-chunk-payload"
    if marker:
        return str(fields.get("protocolReadStage") or marker)
    return None


def pending_budget_exhausted(fields: dict[str, Any]) -> bool:
    pending_retries = int_or_none(fields.get("pendingRetries"))
    pending_budget_ms = int_or_none(fields.get("pendingBudgetMs"))
    return (
        str(fields.get("status") or "") == "failed"
        and pending_retries is not None
        and pending_retries > 0
        and pending_budget_ms is not None
        and pending_budget_ms > 0
    )


def int_or_none(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def bound_selection_summary(summary: dict[str, Any]) -> dict[str, Any]:
    rows = [item.get("boundSelection", {}) for item in summary.get("items", [])]
    rows = [row for row in rows if isinstance(row, dict)]
    attempted = int(summary.get("totals", {}).get("attempted") or 0)
    return {
        "attempted": attempted,
        "withBoundSelected": sum(1 for row in rows if row.get("selected")),
        "selectedWithQuality": sum(1 for row in rows if row.get("selectedHasQuality")),
        "selectedBest": sum(1 for row in rows if row.get("selectedBest")),
        "selectedBehind": sum(1 for row in rows if row.get("selectedBehind")),
        "bySelected": aggregate_bound_selection(rows),
    }


def aggregate_bound_selection(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get("selected") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return [{"key": key, "count": counts[key]} for key in sorted(counts)]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def quality_entries(state: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    return [
        item
        for item in state.get("outbounds", [])
        if isinstance(item, dict) and item.get("scope") == scope
    ]


def entry_summary(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "outbound": entry.get("outbound"),
        "scope": entry.get("scope"),
        "targetFamily": entry.get("targetFamily"),
        "attempts": entry.get("attempts"),
        "successes": entry.get("successes"),
        "failures": entry.get("failures"),
        "confidence": entry.get("confidence"),
    }
