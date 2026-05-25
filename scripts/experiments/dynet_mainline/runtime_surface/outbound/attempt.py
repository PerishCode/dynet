from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.lib.jsonio import load_summary
from scripts.lib.nv import count_keys, merge_items
from scripts.lib.privacy import (
    empty_surface_privacy_flags as empty_privacy_flags,
)


OUTBOUND_ATTEMPT_SCHEMA = "dynet-vm-private-runtime-outbound-attempt-surface/v1alpha1"
COUNT_FIELDS = """
runs cleanRuns failedRuns eventReports runtimePass events
attemptStarts attemptFinishes attemptPairs finishWithoutStart startWithoutFinish
attemptOrderViolations attemptStatusMissing attemptInvalidStatus
attemptProtocolMissing attemptInvalidProtocol attemptTransportMissing
attemptInvalidTransport attemptReferenceMissing attemptOutboundMissing
attemptFinishElapsedMissing failedAttemptErrorTypeMissing
failedAttemptDispositionMissing successfulAttempts failedAttempts
sessionTcpAttempts sessionTcpAttemptsMissingRoute attemptsWithStage
attemptsMissingStage cascadeStarts cascadeFinishes cascadePairs
cascadeFinishWithoutStart cascadeStartWithoutFinish cascadeOrderViolations
cascadeStatusMissing cascadeInvalidStatus cascadeReferenceMissing
cascadeAttemptMissing cascadeFailureScopeMissing cascadeFailureRetryAllowedMissing
cascadeFailureRetryStopReasonMissing cascadeWithOutboundAttempt
cascadeMissingOutboundAttempt
""".split()


def runtime_outbound_attempt_source(path: Path) -> dict[str, Any]:
    summary = load_summary(path)
    totals = summary.get("totals") or {}
    conclusion = summary.get("conclusion") or {}
    source = {
        "path": str(path),
        "schema": str(summary.get("schema") or ""),
        "label": str(summary.get("label") or ""),
        "status": str(conclusion.get("status") or ""),
        **{field: int(totals.get(field) or 0) for field in COUNT_FIELDS},
        "classifications": count_keys(totals.get("classifications")),
        "attemptProtocols": count_keys(totals.get("attemptProtocols")),
        "attemptTransports": count_keys(totals.get("attemptTransports")),
        "attemptStatuses": count_keys(totals.get("attemptStatuses")),
        "cascadeStatuses": count_keys(totals.get("cascadeStatuses")),
        "privacy": empty_privacy_flags(),
    }
    source["clean"] = runtime_outbound_attempt_clean(source)
    return source


def runtime_outbound_attempt_summary(sources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sourceCount": len(sources),
        "clean": bool(sources) and all(source["clean"] for source in sources),
        "statuses": sorted({source["status"] for source in sources if source["status"]}),
        **{field: sum(source[field] for source in sources) for field in COUNT_FIELDS},
        "classifications": merge_items(sources, "classifications"),
        "attemptProtocols": merge_items(sources, "attemptProtocols"),
        "attemptTransports": merge_items(sources, "attemptTransports"),
        "attemptStatuses": merge_items(sources, "attemptStatuses"),
        "cascadeStatuses": merge_items(sources, "cascadeStatuses"),
        "sources": sources,
    }


def runtime_outbound_attempt_clean(source: dict[str, Any]) -> bool:
    return (
        source["schema"] == OUTBOUND_ATTEMPT_SCHEMA
        and source["status"] == "clean"
        and source["runs"] > 0
        and source["cleanRuns"] == source["runs"]
        and source["failedRuns"] == 0
        and source["eventReports"] == source["runs"]
        and source["runtimePass"] == source["runs"]
        and source["attemptFinishes"] > 0
        and source["classifications"] == ["clean"]
        and all(source[field] == 0 for field in blocker_fields())
        and not any(source["privacy"].values())
    )


def blocker_fields() -> list[str]:
    return """
finishWithoutStart startWithoutFinish attemptOrderViolations
attemptStatusMissing attemptInvalidStatus attemptProtocolMissing
attemptInvalidProtocol attemptTransportMissing attemptInvalidTransport
attemptReferenceMissing attemptOutboundMissing attemptFinishElapsedMissing
failedAttemptErrorTypeMissing failedAttemptDispositionMissing
sessionTcpAttemptsMissingRoute attemptsMissingStage cascadeFinishWithoutStart
cascadeStartWithoutFinish cascadeOrderViolations cascadeStatusMissing
cascadeInvalidStatus cascadeReferenceMissing cascadeAttemptMissing
cascadeFailureScopeMissing cascadeFailureRetryAllowedMissing
cascadeFailureRetryStopReasonMissing cascadeMissingOutboundAttempt
""".split()
