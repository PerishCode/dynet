from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EXPERIMENTS = ROOT / "scripts" / "experiments"
sys.path.insert(0, str(EXPERIMENTS))

import tunnel_private_config as config


def report_with_failure(outbound: str) -> dict[str, object]:
    return {
        "status": "deny",
        "events": [
            {
                "kind": "dialer-cascade-attempt-finished",
                "fields": {"boundSelected": "tunnel-001", "status": "failed"},
            },
            {
                "kind": "outbound-stage-finished",
                "fields": {
                    "outbound": outbound,
                    "stage": "tcp-connect",
                    "status": "failed",
                },
            },
        ],
    }


def argparse_like(**values: object) -> object:
    return type("Args", (), values)()


def config_inputs_stub() -> config.ConfigInputs:
    private = {
        "name": "Private",
        "type": "ss",
        "server": "private.example.com",
        "port": 443,
        "cipher": "aes-128-gcm",
        "password": "private-password",
    }
    return config.ConfigInputs(
        group={"name": "Tunnel", "type": "select", "use": []},
        all_candidates=[],
        supported_candidates=[],
        selected_candidates=[],
        candidates=[],
        private=private,
        resolution={"skipped": 0},
    )


def plan_report_stub(selected_score: int = 5400, best_score: int | None = None) -> dict[str, object]:
    best_score = selected_score if best_score is None else best_score
    selected_quality = quality_stub(selected_score)
    best_quality = quality_stub(best_score)
    candidates = [
        {
            "to": "tunnel-001",
            "type": "vmess",
            "edgeType": "candidate",
            "quality": selected_quality,
        }
    ]
    if best_score != selected_score:
        candidates.append(
            {
                "to": "tunnel-002",
                "type": "vmess",
                "edgeType": "candidate",
                "quality": best_quality,
            }
        )
    return {
        "_exitCode": 0,
        "verdict": {
            "status": "accept",
            "action": {"type": "use-outbound", "tag": "private-via-tunnel"},
            "outbound": {"tag": "private-via-tunnel", "type": "dialer"},
        },
        "outboundPath": {
            "requested": "private-via-tunnel",
            "selected": "private-via-tunnel",
            "hops": [{"tag": "private-via-tunnel", "type": "dialer"}],
            "decisions": [],
        },
        "dialerBoundPath": {
            "requested": "tunnel",
            "selected": "tunnel-001",
            "hops": [{"tag": "tunnel", "type": "plan"}, {"tag": "tunnel-001", "type": "vmess"}],
            "decisions": [
                {
                    "plan": "tunnel",
                    "selected": "tunnel-001",
                    "selectedEdgeType": "candidate",
                    "candidates": candidates,
                }
            ],
        },
    }


def quality_stub(score: int) -> dict[str, object]:
    return {
        "stale": False,
        "targetFamily": "chatgpt.com",
        "score": score,
        "reason": "exact-and-overall-quality",
        "matches": [
            {
                "scope": "dialer-bound",
                "targetFamily": "chatgpt.com",
                "transport": "tcp",
                "verdict": "healthy",
                "attempts": 8,
                "successes": 8,
                "failures": 0,
                "confidence": "medium",
                "weightedScore": 4640,
            }
        ],
    }


def write_refresh_fixture(root: Path) -> None:
    summary = {
        "totals": {"attempted": 1, "failed": 1, "passed": 0},
        "items": [
            {
                "id": "0001",
                "status": "deny",
                "failureScope": "downstream",
                "selectedOutbound": "private-via-tunnel",
                "boundSelection": {
                    "selected": "tunnel-001",
                    "candidateCount": 1,
                    "selectedScore": 1000,
                    "bestScore": 1000,
                    "selectedBest": True,
                    "selectedBehind": False,
                    "selectedHasQuality": True,
                    "selectedReason": "overall-quality",
                },
                "failedStage": "private-via-tunnel:stream-first-read",
            }
        ],
    }
    config.write_json(root / "window-a" / "summary.json", summary)
    config.write_json(root / "window-b" / "summary.json", summary)
    config.write_json(
        root / "window-a" / "quality-pipeline.json",
        {
            "previousQualityStates": 0,
            "previousAttributions": 0,
            "plannerFeedback": {"penaltyObservations": 0},
        },
    )
    config.write_json(
        root / "window-b" / "quality-state.json",
        {
            "source": {
                "retainedPreviousStates": 1,
                "retainedPreviousEntries": 1,
                "currentEntries": 1,
            },
            "outbounds": [
                {
                    "outbound": "tunnel-001",
                    "scope": "dialer-bound",
                    "attempts": 2,
                    "successes": 2,
                    "failures": 0,
                    "confidence": "low",
                }
            ],
        },
    )
    config.write_json(
        root / "window-b" / "quality-pipeline.json",
        {
            "previousQualityStates": 1,
            "previousAttributions": 1,
            "plannerFeedback": {"penaltyObservations": 0},
        },
    )
    config.write_json(
        root / "window-b" / "attribution.json",
        {"candidateQuality": {"withQuality": 1}},
    )


def case_summary(
    label: str,
    mode: str,
    protocol: str,
    status: str,
    scope: str,
) -> dict[str, object]:
    return {
        "matrixCase": label,
        "probeMode": mode,
        "protocol": protocol,
        "metadata": {"privacy": {"rawSecretsStored": False}},
        "report": {
            "status": status,
            "reason": None,
            "boundSelected": None,
            "failedStage": None,
            "failureScope": scope,
            "reportPath": f"/tmp/{label}.json",
        },
    }


def compare_matrix(target: str) -> dict[str, object]:
    return {
        "_path": f"/tmp/{target.strip('/').replace(':', '_')}.json",
        "targetUrl": target,
        "metadata": {"counts": {"usable": 2}},
        "totals": {"attempted": 5, "passed": 3, "failed": 1},
        "cases": [
            {
                "label": "private-direct",
                "protocol": "https-head",
                "status": "pass",
                "failureScope": "none",
                "failedStage": None,
                "reason": "ok",
            },
            {
                "label": "candidate-direct",
                "protocol": "https-head",
                "status": "pass",
                "failureScope": "none",
                "failedStage": None,
                "reason": "ok",
            },
            {
                "label": "tunnel-private-tcp",
                "protocol": "tcp-connect",
                "status": "pass",
                "failureScope": "none",
                "failedStage": None,
                "reason": "ok",
            },
            {
                "label": "tunnel-private-tls",
                "protocol": "tls-handshake",
                "status": "deny",
                "failureScope": "downstream",
                "failedStage": "private-via-tunnel:stream-first-read",
                "cascadeAttemptCount": 2,
                "cascadeAttemptTags": ["tunnel-001", "tunnel-002"],
                "cascadeFailedAttempts": 2,
                "cascadeFailedTags": ["tunnel-001", "tunnel-002"],
                "reason": (
                    "Shadowsocks response salt is not ready: "
                    "VMess response header length is not ready"
                ),
            },
        ],
    }


def observer_summary(usable: int, target_connections: int) -> dict[str, object]:
    return {
        "metadata": {"counts": {"usable": usable}},
        "cases": [
            {
                "label": "tunnel-private-echo",
                "expectedConnections": usable,
                "probe": {
                    "failedStage": "private-via-tunnel:stream-first-read",
                    "failureScope": "downstream",
                },
                "signals": {
                    "connections": target_connections,
                    "tlsClientHelloLikeConnections": target_connections,
                },
            }
        ],
    }


def owned_summary(usable: int, target_connections: int) -> dict[str, object]:
    return {
        "metadata": {"counts": {"usable": usable}},
        "cases": [
            {
                "label": "tunnel-owned-private",
                "expectedPrivateConnections": usable,
                "expectedTargetConnections": usable,
                "probe": {
                    "failedStage": "private-via-tunnel:tls-handshake",
                    "failureScope": "downstream",
                },
                "signals": {
                    "privateDecodedConnections": usable,
                    "privateResponseConnections": usable,
                    "targetConnections": target_connections,
                    "targetTlsClientHelloLikeConnections": target_connections,
                },
            }
        ],
    }


def adapter_matrix_compare_summary(failures: int = 2) -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-matrix-compare/v1alpha1",
        "totals": {"matrices": 3, "targets": 1, "failures": failures, "signatures": 1 if failures else 0},
        "matrices": [
            {"path": "/tmp/a", "targetUrl": "https://api.github.com/", "failed": failures},
            {"path": "/tmp/b", "targetUrl": "https://api.github.com/", "failed": 0},
            {"path": "/tmp/c", "targetUrl": "https://api.github.com/", "failed": 0},
        ],
        "failureSignatures": [
            {"targets": ["https://api.github.com/"], "markers": ["trojan-tls-handshake-eof"]}
        ] if failures else [],
        "markerSummary": {"trojan-tls-handshake-eof": failures} if failures else {},
    }


def adapter_matrix_summary(failures: int = 0) -> dict[str, object]:
    passed = 5 - failures
    cases = [
        {"label": "private-direct", "status": "pass"},
        {"label": "candidate-direct", "status": "pass"},
        {"label": "tunnel-private-tcp", "status": "pass"},
        {"label": "tunnel-private-tls", "status": "pass"},
        {"label": "tunnel-private-https", "status": "pass" if failures == 0 else "deny"},
    ]
    return {
        "schema": "dynet-tunnel-private-matrix/v1alpha1",
        "targetUrl": "https://chatgpt.com/",
        "totals": {"attempted": 5, "passed": passed, "failed": failures},
        "cases": cases,
    }


def adapter_vm_private_summary(failures: int = 0) -> dict[str, object]:
    reports = [
        {
            "targetUrl": "https://www.cloudflare.com/",
            "status": "pass",
            "failedStage": None,
            "failureScope": "none",
        },
        {
            "targetUrl": "https://api.github.com/",
            "status": "deny" if failures else "pass",
            "failedStage": "tunnel-001:tcp-connect" if failures else None,
            "failureScope": "bound" if failures else "none",
        },
    ]
    return {
        "schema": "dynet-vm-private-cascade-run/v1alpha1",
        "totals": {"attempted": 2, "passed": 2 - failures, "failed": failures},
        "reports": reports,
    }


def write_transport_summary(path: Path, check: str, outcome_counts: dict[str, int]) -> None:
    path.write_text(json.dumps({
        "schema": "dynet-tunnel-private-transport-evidence/v1alpha1",
        "check": check,
        "candidateCount": sum(outcome_counts.values()),
        "outcomeCounts": outcome_counts,
        "privacy": {"rawSecretsStored": False, "rawLogsStored": False, "rawCurlErrorStored": False},
    }))


def write_adapter_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data))


def adapter_sweep_summary() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-quality-sweep-summary/v1alpha1",
        "status": "pass",
        "strictStatus": "fail",
        "limits": {
            "candidateOffsets": [2, 4],
            "targets": ["https://api.github.com/", "https://www.cloudflare.com/"],
        },
        "totals": {
            "runs": 4,
            "passed": 4,
            "failed": 0,
            "strictPassed": 3,
            "strictFailed": 1,
            "matrixFailures": 1,
            "selectedBehindMax": 0,
        },
        "markerSummary": {"vmess-response-header-length-eof": 1},
        "runs": [],
    }


def adapter_regression_summary(
    *,
    gate_mode: str,
    status: str = "pass",
    strict_status: str = "pass",
) -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-quality-regression/v1alpha1",
        "status": status,
        "strictStatus": strict_status,
        "gateMode": gate_mode,
        "refreshProbeMode": "candidate" if gate_mode == "direct" else "private",
        "planQualityScope": "plan-candidate" if gate_mode == "direct" else "dialer-bound",
        "targetUrl": "https://api.github.com/",
        "gates": [
            {"name": "quality-refresh-command", "passed": status == "pass", "required": True},
            {"name": "matrix-candidate-direct-pass", "passed": strict_status == "pass", "required": gate_mode == "direct"},
        ],
        "plan": {"quality": {"selectedBehind": 0}},
        "matrix": {"totals": {"attempted": 5, "passed": 5, "failed": 0}},
        "compare": {"markerSummary": {}},
    }


def blocked_transport_summary() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-transport-evidence/v1alpha1",
        "sourceCount": 10,
        "surfaces": [],
        "conclusion": {
            "recommendedUse": "controller-health-is-weak-signal-not-product-proof",
            "productE2eEvidence": True,
            "productE2ePass": False,
            "controllerContradictsProductE2e": True,
            "plannerPenaltySafe": False,
        },
    }


def product_transport_summary() -> dict[str, object]:
    return {
        "schema": "dynet-tunnel-private-transport-evidence/v1alpha1",
        "sourceCount": 2,
        "surfaces": [],
        "conclusion": {
            "recommendedUse": "product-e2e-baseline-present",
            "productE2eEvidence": True,
            "productE2ePass": True,
            "plannerPenaltySafe": False,
        },
    }


def runtime_run_summary(fallback_sets: int, fallback_quality: int, fallback_behind: int) -> dict[str, object]:
    return {
        "tcpClosedSessions": 1,
        "tcpSessionFailures": 0,
        "tcpUpstreamBytes": 719,
        "tcpDownstreamBytes": 5503,
        "boundSelection": {
            "fallbackCandidateSets": fallback_sets,
            "fallbackSelectedWithQuality": fallback_quality,
            "fallbackSelectedBehind": fallback_behind,
        },
    }


def runtime_summary() -> dict[str, object]:
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "totals": {
            "runs": 2,
            "passedRuns": 2,
            "failedRuns": 0,
            "workloadFailedRuns": 0,
            "workloadAttempted": 4,
            "workloadSuccess": 4,
            "workloadFailure": 0,
            "workloadFlowEntries": 4,
            "workloadFlowMatchedEntries": 4,
            "workloadFlowCoveredEntries": 4,
            "qualityBoundCandidateSets": 4,
            "qualityBoundSelectedWithQuality": 4,
            "qualityBoundSelectedBehind": 0,
            "tcpFlowRouteGraphSelected": 4,
            "tcpFlowPathComplete": 4,
            "tcpFlowPayloadBidirectional": 4,
            "tcpFlowFailed": 0,
        },
        "runs": [
            runtime_run_summary(1, 1, 1),
            runtime_run_summary(0, 0, 0),
        ],
    }
