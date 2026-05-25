from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.briefs import selection_brief
from tests.private_runtime_fixtures import candidate


def candidate_set(flow_id: str, selected: str, candidates: list[dict[str, object]]) -> dict[str, object]:
    return {
        "kind": "outbound-candidate-set",
        "fields": {
            "scope": "dialer-bound",
            "plan": "tunnel",
            "session": flow_id.rsplit("-", 1)[-1],
            "flowId": flow_id,
            "candidateCount": str(len(candidates)),
            "selected": selected,
            "candidatesJson": json.dumps(candidates, sort_keys=True),
        },
    }


class PrivateRuntimeSelectionTest(unittest.TestCase):
    def test_bound_fallback(self) -> None:
        brief = selection_brief({
            "events": [
                candidate_set("tcp-session-1", "tunnel-001", [
                    candidate("tunnel-001", 6000),
                    candidate("tunnel-002", 0, matches=False),
                ]),
                candidate_set("tcp-session-1", "tunnel-002", [
                    candidate("tunnel-001", 6000),
                    candidate("tunnel-002", 0, matches=False),
                ]),
            ],
        })

        bound = brief["boundSelection"]

        self.assertEqual(bound["candidateSets"], 1)
        self.assertEqual(bound["attemptCandidateSets"], 2)
        self.assertEqual(bound["fallbackCandidateSets"], 1)
        self.assertEqual(bound["selectedWithQuality"], 1)
        self.assertEqual(bound["selectedBehind"], 0)
        self.assertEqual(bound["fallbackSelectedWithQuality"], 0)
        self.assertEqual(bound["fallbackSelectedBehind"], 1)

    def test_cascade_attempts(self) -> None:
        brief = selection_brief({
            "events": [
                cascade_finished("tcp-session-1", "tunnel-004", 1, "failed", "bound", "pending-timeout", "true"),
                cascade_finished("tcp-session-1", "tunnel-001", 2, "success", "none", "", ""),
                cascade_finished("dns-query-1", "tunnel-002", 1, "failed", "downstream", "protocol-invalid", "false"),
            ],
        })

        cascade = brief["cascadeAttempts"]

        self.assertEqual(cascade["finishedAttempts"], 3)
        self.assertEqual(cascade["failedAttempts"], 2)
        self.assertEqual(cascade["retryableFailures"], 1)
        self.assertEqual(cascade["stoppedFailures"], 1)
        self.assertEqual(cascade["stoppedFlows"], 1)
        self.assertEqual(cascade["stoppedFlowByStopReason"], [
            {"count": 1, "key": "non-bound-failure"},
        ])
        self.assertEqual(cascade["recoveredFlows"], 1)
        self.assertEqual(cascade["failedByScope"], [
            {"count": 1, "key": "bound"},
            {"count": 1, "key": "downstream"},
        ])
        self.assertEqual(cascade["failedByDisposition"], [
            {"count": 1, "key": "pending-timeout"},
            {"count": 1, "key": "protocol-invalid"},
        ])
        self.assertEqual(cascade["failedByStage"], [
            {"count": 1, "key": "private-trojan-connect"},
            {"count": 1, "key": "trojan-tls-handshake"},
        ])
        self.assertEqual(cascade["failedByStageSurface"], [
            {"count": 1, "key": "private-trojan-connect:trojan"},
            {"count": 1, "key": "trojan-tls-handshake:trojan"},
        ])
        self.assertEqual(cascade["failedByStageDisposition"], [
            {"count": 1, "key": "pending-timeout"},
            {"count": 1, "key": "protocol-invalid"},
        ])
        self.assertEqual(cascade["stoppedRows"][0]["flowId"], "dns-query-1")
        self.assertEqual(cascade["stoppedRows"][0]["failureStageSurface"], "private-trojan-connect:trojan")

    def test_bound_exhaustion_rows(self) -> None:
        brief = selection_brief({
            "events": [
                cascade_finished("tcp-session-1", "tunnel-004", 1, "failed", "bound", "pending-timeout", "true"),
                cascade_finished("tcp-session-1", "tunnel-001", 2, "failed", "bound", "pending-timeout", "true"),
                cascade_finished(
                    "tcp-session-1",
                    "tunnel-002",
                    3,
                    "failed",
                    "bound",
                    "pending-timeout",
                    "false",
                    stop_reason="bound-candidates-exhausted",
                    candidate_count=3,
                ),
            ],
        })

        cascade = brief["cascadeAttempts"]
        stopped = cascade["stoppedRows"][0]

        self.assertEqual(cascade["stoppedFlows"], 1)
        self.assertEqual(cascade["stoppedBoundExhaustedFlows"], 1)
        self.assertEqual(cascade["stoppedFlowByAttemptCount"], [{"count": 1, "key": "3"}])
        self.assertTrue(stopped["candidateExhausted"])
        self.assertEqual(stopped["failedSelectedSequence"], ["tunnel-004", "tunnel-001", "tunnel-002"])
        self.assertEqual(stopped["stopReason"], "bound-candidates-exhausted")

    def test_cascade_stage_inference(self) -> None:
        brief = selection_brief({
            "events": [
                stage_failed(10, "dns-query-1", "tunnel-004", "trojan-tls-handshake", "trojan", "reset"),
                cascade_finished_without_stage(
                    12,
                    "dns-query-1",
                    "tunnel-004",
                    1,
                    "bound",
                    "reset",
                    "true",
                ),
                stage_failed(
                    20,
                    "dns-query-1",
                    "private",
                    "private-trojan-connect",
                    "trojan",
                    "protocol-invalid",
                ),
                cascade_finished_without_stage(
                    21,
                    "dns-query-1",
                    "tunnel-001",
                    2,
                    "downstream",
                    "protocol-invalid",
                    "false",
                ),
            ],
        })

        cascade = brief["cascadeAttempts"]

        self.assertEqual(cascade["failedByStageSurface"], [
            {"count": 1, "key": "private-trojan-connect:trojan"},
            {"count": 1, "key": "trojan-tls-handshake:trojan"},
        ])


def cascade_finished(
    flow_id: str,
    selected: str,
    attempt: int,
    status: str,
    scope: str,
    disposition: str,
    retry_allowed: str,
    stop_reason: str | None = None,
    candidate_count: int = 4,
) -> dict[str, object]:
    return {
        "kind": "dialer-cascade-attempt-finished",
        "fields": {
            "flowId": flow_id,
            "dialer": "private-via-tunnel",
            "boundSelected": selected,
            "attempt": str(attempt),
            "candidateCount": str(candidate_count),
            "status": status,
            "failureScope": scope,
            "errorDisposition": disposition,
            "failureStage": (
                "trojan-tls-handshake" if scope == "bound" else "private-trojan-connect"
            ),
            "failureStageOutbound": selected if scope == "bound" else "private-trojan",
            "failureStageKind": "trojan",
            "failureStageDisposition": disposition,
            "retryAllowed": retry_allowed,
            "retryStopReason": stop_reason
            or ("non-bound-failure" if retry_allowed == "false" else ""),
        },
    }


def cascade_finished_without_stage(
    sequence: int,
    flow_id: str,
    selected: str,
    attempt: int,
    scope: str,
    disposition: str,
    retry_allowed: str,
) -> dict[str, object]:
    event = cascade_finished(
        flow_id,
        selected,
        attempt,
        "failed",
        scope,
        disposition,
        retry_allowed,
    )
    event["sequence"] = sequence
    fields = event["fields"]
    for key in [
        "failureStage",
        "failureStageOutbound",
        "failureStageKind",
        "failureStageDisposition",
        "failureStageErrorType",
    ]:
        fields.pop(key, None)
    return event


def stage_failed(
    sequence: int,
    flow_id: str,
    outbound: str,
    stage: str,
    kind: str,
    disposition: str,
) -> dict[str, object]:
    return {
        "kind": "outbound-stage-finished",
        "sequence": sequence,
        "fields": {
            "flowId": flow_id,
            "outbound": outbound,
            "stage": stage,
            "kind": kind,
            "status": "failed",
            "errorType": kind,
            "errorDisposition": disposition,
        },
    }


if __name__ == "__main__":
    unittest.main()
