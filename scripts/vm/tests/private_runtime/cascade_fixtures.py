from __future__ import annotations


def cascade_stage_report() -> dict:
    return {
        "events": [
            cascade_stage_event(10, "dns-query-1", "tunnel-004", "trojan-tls-handshake", "reset"),
            cascade_attempt_event(12, "dns-query-1", "tunnel-004", 1, "bound", "reset", "true"),
            cascade_stage_event(
                20,
                "dns-query-1",
                "private",
                "private-trojan-connect",
                "protocol-invalid",
            ),
            cascade_attempt_event(
                21,
                "dns-query-1",
                "tunnel-001",
                2,
                "downstream",
                "protocol-invalid",
                "false",
            ),
        ]
    }


def cascade_stage_event(
    sequence: int,
    flow_id: str,
    outbound: str,
    stage: str,
    disposition: str,
) -> dict:
    return {
        "kind": "outbound-stage-finished",
        "sequence": sequence,
        "fields": {
            "flowId": flow_id,
            "outbound": outbound,
            "kind": "trojan",
            "stage": stage,
            "status": "failed",
            "errorType": "trojan",
            "errorDisposition": disposition,
        },
    }


def cascade_attempt_event(
    sequence: int,
    flow_id: str,
    selected: str,
    attempt: int,
    scope: str,
    disposition: str,
    retry_allowed: str,
) -> dict:
    return {
        "kind": "dialer-cascade-attempt-finished",
        "sequence": sequence,
        "fields": {
            "flowId": flow_id,
            "dialer": "private-via-tunnel",
            "boundSelected": selected,
            "attempt": str(attempt),
            "candidateCount": "4",
            "status": "failed",
            "failureScope": scope,
            "errorDisposition": disposition,
            "retryAllowed": retry_allowed,
            "retryStopReason": "non-bound-failure" if retry_allowed == "false" else "",
        },
    }


def stale_cascade_summary() -> dict:
    return {
        "label": "stale-cascade",
        "totals": {"failed": 0},
        "checks": [],
        "runtime": {},
        "selection": {
            "boundSelection": {},
            "cascadeAttempts": {
                "failedAttempts": 2,
                "failedByDisposition": [{"key": "reset", "count": 2}],
            },
        },
        "stability": {},
        "workloadProbe": {},
        "tcpFlow": {},
        "workloadFlow": {},
    }
