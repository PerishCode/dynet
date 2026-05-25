from __future__ import annotations

from typing import Any

from dynet_clash.gap.followups import current_read_followup, isolated_current_followup
from dynet_clash.gap.paired_pressure import fresh_paired_clean, paired_pressure_brief
from dynet_clash.gap.protocol_retry import protocol_retry_brief


def isolated_current_brief(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"present": False}
    conclusion = summary.get("conclusion") or {}
    report = summary.get("reportEvidence") or {}
    sources = report.get("sources") or []
    read_failures = [
        source.get("readFailure")
        for source in sources
        if isinstance(source, dict) and isinstance(source.get("readFailure"), dict)
    ]
    return {
        "present": True,
        "status": conclusion.get("status"),
        "sourceCount": int(summary.get("sourceCount") or len(sources)),
        "readFailureCount": int(report.get("readFailureCount") or 0),
        "readFailureUnclassifiedCount": int(
            report.get("readFailureUnclassifiedCount") or 0
        ),
        "classificationClean": bool(
            conclusion.get("readFailureClassificationClean")
        ),
        "surfaces": surface_counts(read_failures),
    }


def has_read_failures(summary: dict[str, Any] | None) -> bool:
    brief = isolated_current_brief(summary)
    return bool(brief["present"]) and int(brief["readFailureCount"]) > 0


def quality_refresh_brief(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"present": False}
    quality = summary.get("qualityState") or {}
    dialer_bound = quality.get("dialerBound") or []
    bound = summary.get("boundSelection") or {}
    window_b = bound.get("windowB") or {}
    return {
        "present": True,
        "status": summary.get("status"),
        "clean": quality_refresh_clean(summary),
        "firstWindow": summary.get("firstWindow") or {},
        "secondWindow": summary.get("secondWindow") or {},
        "dialerBoundCount": len(dialer_bound) if isinstance(dialer_bound, list) else 0,
        "windowBSelectedWithQuality": int(
            window_b.get("selectedWithQuality") or 0
        ),
        "windowBSelectedBest": int(window_b.get("selectedBest") or 0),
        "windowBSelected": window_b.get("bySelected") or [],
    }


def quality_refresh_clean(summary: dict[str, Any] | None) -> bool:
    if not isinstance(summary, dict):
        return False
    quality = summary.get("qualityState") or {}
    dialer_bound = quality.get("dialerBound") or []
    bound = summary.get("boundSelection") or {}
    window_b = bound.get("windowB") or {}
    attempted = int(window_b.get("attempted") or 0)
    selected_with_quality = int(window_b.get("selectedWithQuality") or 0)
    selected_best = int(window_b.get("selectedBest") or 0)
    return (
        summary.get("status") == "pass"
        and isinstance(dialer_bound, list)
        and len(dialer_bound) > 0
        and attempted > 0
        and selected_with_quality == attempted
        and selected_best == attempted
    )


def fresh_config_brief(
    summary: dict[str, Any] | None,
    followup: dict[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {"present": False}
    totals = summary.get("totals") or {}
    report = followup.get("reportEvidence") if isinstance(followup, dict) else {}
    conclusion = followup.get("conclusion") if isinstance(followup, dict) else {}
    return {
        "present": True,
        "clean": fresh_config_clean(summary, followup),
        "attempted": int(totals.get("attempted") or 0),
        "passed": int(totals.get("passed") or 0),
        "failed": int(totals.get("failed") or 0),
        "readFailureCount": int((report or {}).get("readFailureCount") or 0),
        "readStageFailures": int(
            (conclusion or {}).get("currentReadStageFailures") or 0
        ),
        "status": (conclusion or {}).get("status"),
    }


def fresh_config_clean(
    summary: dict[str, Any] | None,
    followup: dict[str, Any] | None,
) -> bool:
    if not isinstance(summary, dict) or not isinstance(followup, dict):
        return False
    totals = summary.get("totals") or {}
    conclusion = followup.get("conclusion") or {}
    attempted = int(totals.get("attempted") or 0)
    return (
        attempted > 0
        and int(totals.get("passed") or 0) == attempted
        and int(totals.get("failed") or 0) == 0
        and int(conclusion.get("readFailureCount") or 0) == 0
        and int(conclusion.get("currentReadStageFailures") or 0) == 0
    )


def observe_saved_config_drift(
    gap: dict[str, Any],
    drilldown: dict[str, Any],
    protocol_retry: dict[str, Any],
    isolated_current: dict[str, Any],
    isolated_quality: dict[str, Any] | None,
    fresh_config_summary: dict[str, Any],
    fresh_config_followup: dict[str, Any],
    paired_surface: dict[str, Any] | None = None,
) -> dict[str, Any]:
    conclusion = gap.get("conclusion", {})
    totals = drilldown.get("totals", {})
    product_repeat_clean = fresh_paired_clean(paired_surface)
    return {
        "status": saved_config_status(product_repeat_clean),
        "action": saved_config_action(product_repeat_clean),
        "plannerFeedback": "none",
        "qualityFeedback": "none",
        "runtimePolicy": "do-not-change-from-this-artifact-alone",
        "probePolicy": "no-product-retry-from-this-artifact-alone",
        "reason": saved_config_reason(product_repeat_clean),
        "superiorDeltaGap": conclusion.get("superiorDeltaGap"),
        "additionalNetSuccessesForSuperior": (
            conclusion.get("additionalNetSuccessesForSuperior")
        ),
        "retainedRows": totals.get("rows"),
        "protocolReadSurfaceCounts": drilldown.get("protocolReadSurfaceCounts", []),
        "protocolRetry": protocol_retry_brief(protocol_retry),
        "isolatedCurrent": isolated_current_brief(isolated_current),
        "isolatedQuality": quality_refresh_brief(isolated_quality),
        "freshConfig": fresh_config_brief(fresh_config_summary, fresh_config_followup),
        "pairedPressure": paired_pressure_brief(paired_surface),
    }


def saved_config_status(product_repeat_clean: bool) -> str:
    if product_repeat_clean:
        return "observe-saved-config-drift-repeat-clean"
    return "observe-saved-config-drift-experiment-shape"


def saved_config_action(product_repeat_clean: bool) -> str:
    if product_repeat_clean:
        return "exclude-stale-config-controls-from-pressure-bisection"
    return "regenerate-config-and-repeat-product-window"


def saved_config_reason(product_repeat_clean: bool) -> str:
    if product_repeat_clean:
        return (
            "the saved-config isolated replay has structured protocol-read "
            "failures, but freshly generated current config is clean in both "
            "isolated manifest replay and paired product windows; treat stale "
            "saved-config controls as experiment-shape/config drift instead of "
            "planner, quality, runtime, product retry, or timing-boundary "
            "evidence"
        )
    return (
        "the saved-config isolated replay has structured protocol-read "
        "failures, but the same manifest with a freshly generated current "
        "config passes cleanly; classify the saved-config failure as "
        "experiment-shape/config drift before changing planner, quality, "
        "runtime, or product retry policy"
    )


def observe_current_isolated(
    gap: dict[str, Any],
    drilldown: dict[str, Any],
    protocol_retry: dict[str, Any],
    isolated_current: dict[str, Any],
    paired_surface: dict[str, Any] | None = None,
    isolated_quality: dict[str, Any] | None = None,
) -> dict[str, Any]:
    conclusion = gap.get("conclusion", {})
    totals = drilldown.get("totals", {})
    refreshed = quality_refresh_clean(isolated_quality)
    return {
        "status": current_status(refreshed),
        "action": current_action(refreshed),
        "plannerFeedback": "none",
        "qualityFeedback": "observe-only",
        "runtimePolicy": "do-not-change-from-this-artifact-alone",
        "probePolicy": "no-product-retry-from-this-artifact-alone",
        "followUp": current_followup(refreshed),
        "reason": current_reason(refreshed),
        "superiorDeltaGap": conclusion.get("superiorDeltaGap"),
        "additionalNetSuccessesForSuperior": (
            conclusion.get("additionalNetSuccessesForSuperior")
        ),
        "retainedRows": totals.get("rows"),
        "protocolReadSurfaceCounts": drilldown.get("protocolReadSurfaceCounts", []),
        "protocolRetry": protocol_retry_brief(protocol_retry),
        "isolatedCurrent": isolated_current_brief(isolated_current),
        "isolatedQuality": quality_refresh_brief(isolated_quality),
        "pairedPressure": paired_pressure_brief(paired_surface),
    }


def current_status(refreshed: bool) -> str:
    if refreshed:
        return "observe-protocol-read-current-isolated-repeat"
    return "observe-protocol-read-current-isolated"


def current_action(refreshed: bool) -> str:
    if refreshed:
        return "classify-current-isolated-protocol-read-degradation"
    return "refresh-current-quality-and-repeat-isolated"


def current_followup(refreshed: bool) -> dict[str, Any]:
    if refreshed:
        return current_read_followup()
    return isolated_current_followup()


def current_reason(refreshed: bool) -> str:
    if refreshed:
        return (
            "fresh isolated quality refresh selected a quality-backed bound "
            "candidate, but current isolated dynet replay still has structured "
            "protocol-read failures; classify this as current isolated "
            "protocol-read degradation before changing planner, quality, or "
            "runtime policy"
        )
    return (
        "a current isolated dynet control also has structured protocol-read "
        "failures, so the evidence is no longer specific to paired product-window "
        "pressure; refresh or repeat current isolated quality evidence before "
        "changing planner, quality, or runtime policy"
    )


def surface_counts(read_failures: list[Any]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str, str], int] = {}
    for failure in read_failures:
        if not isinstance(failure, dict):
            continue
        key = (
            str(failure.get("marker") or ""),
            str(failure.get("disposition") or ""),
            str(failure.get("context") or ""),
            str(failure.get("outbound") or ""),
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "marker": marker,
            "disposition": disposition,
            "context": context,
            "outbound": outbound,
            "count": count,
        }
        for (marker, disposition, context, outbound), count in sorted(counts.items())
    ]
