from __future__ import annotations

from pathlib import Path

from tests.tunnel_private.quality.support.mainline_baseline import write_json


def write_cascade_stop(
    root: Path,
    failed: bool = False,
    no_stop: bool = False,
) -> Path:
    totals = {
        "sourceCount": 1, "roundGapRuns": 2, "stoppedRows": 1, "boundExhaustedRows": 1,
        "nonBoundRows": 0, "candidateExhaustedRows": 1, "matchedFailedWorkloadRows": 1,
        "attemptCount": 4, "failedAttemptCount": 4, "retryableFailureCount": 3,
        "missingRequiredFields": 1 if failed else 0,
        "boundOrderLengthMismatches": 0, "failedOrderLengthMismatches": 0,
        "retryableOrderLengthMismatches": 0, "uniqueCandidateCountMismatches": 0,
        "lastCandidateMismatches": 0, "finalFailureAccountingMismatches": 0,
        "exhaustedFlagMismatches": 0, "scopeStopMismatches": 0, "emptyBoundOrderRows": 0,
        "classifications": [{"key": "cascade-stop-field-missing" if failed else "clean", "count": 1}],
        "stopReasons": [{"key": "bound-candidates-exhausted", "count": 1}],
        "failureScopes": [{"key": "bound", "count": 1}],
        "stageSurfaces": [{"key": "trojan-tls-handshake:trojan", "count": 1}],
        "pendingWaitClasses": [{"key": "socket-read-timeout", "count": 1}],
        "failureStagePendingWaitClasses": [
            {"key": "socket-read-timeout", "count": 1},
        ],
    }
    status = "cascade-stop-shape-needs-evidence" if failed else "cascade-stop-shape-clean"
    if no_stop:
        totals.update({
            "stoppedRows": 0, "boundExhaustedRows": 0, "candidateExhaustedRows": 0,
            "matchedFailedWorkloadRows": 0, "attemptCount": 0, "failedAttemptCount": 0,
            "retryableFailureCount": 0, "classifications": [
                {"key": "no-cascade-stop-evidence", "count": 1},
            ],
            "stopReasons": [], "failureScopes": [], "stageSurfaces": [],
            "pendingWaitClasses": [], "failureStagePendingWaitClasses": [],
        })
        status = "no-cascade-stop-evidence"
    return write_json(root / "cascade-stop.json", {
        "schema": "dynet-vm-private-runtime-cascade-stop-surface/v1alpha1",
        "label": "cascade-stop",
        "totals": totals,
        "conclusion": {
            "status": status,
            "nextAction": "continue-stage-hardening-with-sanitized-bound-exhaustion-shape",
            "plannerPenaltySafe": False, "qualityPenaltySafe": False,
        }, "policy": {"plannerPenaltySafe": False, "qualityPenaltySafe": False}})
