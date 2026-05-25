from __future__ import annotations

import argparse
import json
from pathlib import Path


def runtime_report() -> dict[str, object]:
    return {
        "status": "pass",
        "events": [
            {
                "kind": "outbound-candidate-set",
                "fields": {
                    "scope": "dialer-bound",
                    "plan": "tunnel",
                    "session": "1",
                    "flowId": "tcp-session-1",
                    "candidateCount": "3",
                    "selected": "tunnel-001",
                    "candidatesJson": json.dumps(
                        [
                            candidate("tunnel-001", 6000),
                            candidate("tunnel-002", 0, matches=False),
                            candidate("tunnel-003", 0, matches=False),
                        ],
                        sort_keys=True,
                    ),
                },
            }
        ],
    }


def tcp_identity_report() -> dict[str, object]:
    return {
        "tcpSessions": 1,
        "tcpUpstreamBytes": 12,
        "tcpDownstreamBytes": 24,
        "tcpSessionFailures": 0,
        "tcpListenCapacity": 16,
        "tcpSlotPressureEvents": 0,
        "events": tcp_identity_events(),
    }


def tcp_identity_events() -> list[dict[str, object]]:
    return tcp_identity_target_events() + tcp_identity_path_events() + tcp_identity_payload_events()


def tcp_identity_target_events() -> list[dict[str, object]]:
    return [
        tcp_event("tcp-session-started", {"target": "104.18.32.47:443", "clientPort": "45678"}),
        tcp_event(
            "tcp-session-attributed",
            {"target": "104.18.32.47:443", "domain": "chatgpt.com", "outbound": "private"},
        ),
        tcp_event(
            "tcp-session-outbound-connecting",
            {
                "target": "104.18.32.47:443",
                "connectTarget": "chatgpt.com:443",
                "identityDomain": "chatgpt.com",
                "targetAddressSource": "dns-reverse-rule-domain",
            },
        ),
        tcp_event(
            "outbound-stage-finished",
            {
                "outbound": "private",
                "kind": "ss",
                "stage": "private-ss-connect",
                "status": "success",
                "target": "104.18.32.47:443",
                "adapterTarget": "chatgpt.com:443",
                "adapterTargetKind": "domain",
            },
        ),
        tcp_event(
            "tcp-session-established",
            {"target": "104.18.32.47:443", "connectTarget": "chatgpt.com:443"},
        ),
    ]


def tcp_identity_path_events() -> list[dict[str, object]]:
    return [
        tcp_event("rule-matched", {"target": "104.18.32.47:443", "outbound": "private-via-tunnel"}),
        tcp_event("plan-bypassed", {"target": "104.18.32.47:443", "outbound": "private-via-tunnel"}),
        tcp_event(
            "outbound-candidate-set",
            {"scope": "dialer-bound", "selected": "tunnel-001"},
        ),
        tcp_event(
            "outbound-graph-selected",
            {"scope": "dialer-bound", "selected": "tunnel-001"},
        ),
        tcp_event(
            "dialer-cascade-selected",
            {"boundSelected": "tunnel-001", "private": "private"},
        ),
        tcp_event("outbound-attempt-started", {"outbound": "tunnel-001"}),
        tcp_event("outbound-attempt-finished", {"outbound": "tunnel-001", "status": "success"}),
    ]


def route_plan_events() -> list[dict[str, object]]:
    return [
        tcp_event("route-matched", {"target": "104.18.32.47:443", "outbound": "private-via-tunnel"}),
        tcp_event(
            "outbound-graph-selected",
            {"scope": "tcp-route", "selected": "private-via-tunnel"},
        ),
        tcp_event(
            "outbound-candidate-set",
            {"scope": "dialer-bound", "selected": "tunnel-001"},
        ),
        tcp_event(
            "outbound-graph-selected",
            {"scope": "dialer-bound", "selected": "tunnel-001"},
        ),
        tcp_event(
            "dialer-cascade-selected",
            {"boundSelected": "tunnel-001", "private": "private"},
        ),
        tcp_event("outbound-attempt-started", {"outbound": "tunnel-001"}),
        tcp_event("outbound-attempt-finished", {"outbound": "tunnel-001", "status": "success"}),
    ]


def tcp_identity_payload_events() -> list[dict[str, object]]:
    return [
        tcp_event("tcp-session-payload-first-write", {"target": "104.18.32.47:443", "bytes": "517"}),
        tcp_event("tcp-session-payload-received", {"target": "104.18.32.47:443", "bytes": "2048"}),
        tcp_event(
            "tcp-session-closed",
            {
                "target": "104.18.32.47:443",
                "upstreamBytes": "517",
                "downstreamBytes": "2048",
                "clientPort": "45678",
                "reason": "outbound-eof",
            },
        ),
    ]


def tcp_event(kind: str, fields: dict[str, str]) -> dict[str, object]:
    return {"kind": kind, "fields": {"flowId": "tcp-session-1", **fields}}


def event_by_kind(report: dict[str, object], kind: str) -> dict[str, object]:
    return next(event for event in report["events"] if event["kind"] == kind)


def event_by_stage(report: dict[str, object], stage: str) -> dict[str, object]:
    return next(event for event in report["events"] if event["fields"].get("stage") == stage)


def duplicate_close_report() -> dict[str, object]:
    return {
        "events": [
            {"kind": "tcp-session-started", "fields": {"flowId": "tcp-session-1"}},
            {"kind": "tcp-session-closed", "fields": {"flowId": "tcp-session-1"}},
            {"kind": "tcp-session-closed", "fields": {"flowId": "tcp-session-1"}},
        ]
    }


def candidate(tag: str, score: int, matches: bool = True) -> dict[str, object]:
    quality = {
        "stale": False,
        "targetFamily": "chatgpt.com",
        "score": score,
        "reason": "exact-and-overall-quality" if matches else "no-quality-evidence",
    }
    if matches:
        quality["matches"] = [
            {
                "scope": "dialer-bound",
                "targetFamily": "chatgpt.com",
                "transport": "tcp",
                "verdict": "healthy",
                "attempts": 10,
                "successes": 10,
                "failures": 0,
                "confidence": "high",
                "weightedScore": score,
            }
        ]
    return {"to": tag, "type": "vmess", "quality": quality}


def lifecycle_report() -> dict[str, object]:
    return {"checks": [{"name": "apply-engine", "status": "pass"}, {"name": "uninstall-engine", "status": "pass"}]}


def runtime_args(tcp_forward: bool) -> argparse.Namespace:
    values = {
        "upstream_dns": "8.8.8.8:53",
        "runtime_udp_dns": False,
        "timeout": 30,
        "tcp_forward": tcp_forward,
        "tcp_probe": True,
        "tcp_route_plan_private": False,
        "tcp_route_direct_fallback": False,
        "tcp_route_non_direct_fallback": False,
        "udp_forward": False,
        "udp_direct_probe": False,
        "udp_target": "1.1.1.1:123",
        "ipv6_no_leak": False,
        "ipv6_target": "[2606:4700:4700::1111]:443",
        "dns_timeout": 35,
        "workload_respect_schedule": True,
        "workload_require_all_success": False,
        "workload_concurrency_limit": None,
        "force_bound_candidate": None,
        "poison_first_bound_candidate": False,
        "poison_bound_only": False,
        "tun_target": "203.0.113.10",
        "dynet_bin": "/usr/local/bin/dynet",
        "tcp_listen_slots_per_port": None,
        "outbound_tcp_connect_timeout_ms": 8000,
        "outbound_tcp_read_write_timeout_ms": 8000,
    }
    return argparse.Namespace(**values)


def round_gap_batch(label: str, runs: list[dict]) -> dict:
    from private_runtime_lib.reporting import round_gap

    rows = [
        round_gap.round_gap_row(Path(f"/tmp/round-gap-run-{index:02d}"), run)
        for index, run in enumerate(runs)
    ]
    by_gap = [
        round_gap.gap_summary(gap_ms, gap_rows)
        for gap_ms, gap_rows in round_gap.group_by_gap(rows)
    ]
    totals = round_gap.round_gap_totals(rows, by_gap)
    reason = round_gap.penalty_reason(rows)
    return {
        "schema": round_gap.ROUND_GAP_SCHEMA,
        "label": label,
        "outputDir": "/tmp/round-gap",
        "runs": rows,
        "byGap": by_gap,
        "totals": totals,
        "conclusion": round_gap.round_gap_conclusion(rows, totals, reason),
        "policy": {
            "plannerPenaltySafe": False,
            "qualityPenaltySafe": False,
            "reason": reason,
        },
    }


def gap_runtime(
    label: str,
    gap_ms: int,
    workload_success: int = 8,
    terminal: int = 0,
    stage_failures: int = 0,
    lag: int = 0,
) -> dict:
    workload_failure = 8 - workload_success
    failed = workload_failure or stage_failures
    workload = gap_workload(gap_ms, workload_success, lag)
    return {
        "label": label,
        "totals": {"failed": 0 if not failed else 1},
        "checks": [{"name": "runtime-pass", "passed": not failed}],
        "runtime": {
            "tcpSessionFailures": stage_failures,
            "tcpActiveSlotsMax": 5,
            "tcpSlotPressureEvents": 0,
        },
        "selection": {
            "boundSelection": {
                "candidateSets": workload_success,
                "selectedWithQuality": workload_success,
                "selectedBehind": 0,
                "selectedBest": workload_success,
            },
            "cascadeAttempts": cascade_attempts(stage_failures),
        },
        "stability": {
            "workloadErrors": [{"key": "tls", "count": workload_failure}] if workload_failure else [],
        },
        "tcpFlow": {
            "stageFailureBySurface": keyed_count("tcp-connect:trojan", stage_failures),
            "stageFailureByErrorType": keyed_count("trojan", stage_failures),
            "stageFailureByDisposition": keyed_count("pending-timeout", stage_failures),
            "failedByPhase": keyed_count("session-start", stage_failures),
            "failedByCleanupAction": keyed_count("socket-abort", stage_failures),
            "failedByReplaySafe": keyed_count("pre-payload", stage_failures),
            "failedByFailureStage": keyed_count("tcp-connect", stage_failures),
            "failedByFailureStageOutbound": keyed_count("tunnel-003", stage_failures),
            "failedByFailureStageKind": keyed_count("trojan", stage_failures),
            "failedByFailureStageErrorType": keyed_count("trojan", stage_failures),
            "failedByFailureStageDisposition": keyed_count("pending-timeout", stage_failures),
        },
        "runtimeReport": {
            "events": gap_stage_events(stage_failures),
        },
        "workloadFlow": {
            "matchedEntries": workload_success,
            "unmatchedEntries": workload_failure,
            "coveredEntries": 8 - terminal,
            "matchedRecoveredFailureEntries": stage_failures,
            "matchedFlowFailedAttempts": stage_failures,
            "matchedFlowStageFailedAttempts": stage_failures,
            "runtimePacketTerminalByReason": keyed_count("closed-before-preflow", terminal),
            "unmatchedRuntimePacketTerminalByReason": keyed_count("closed-before-preflow", terminal),
            "rows": gap_workload_flow_rows(workload["results"], terminal, stage_failures),
        },
        "workloadProbe": workload,
    }


def gap_stage_events(stage_failures: int) -> list[dict[str, object]]:
    events = []
    for index in range(stage_failures):
        events.append(
            {
                "kind": "outbound-stage-finished",
                "sequence": index + 1,
                "fields": {
                    "stage": "tcp-connect",
                    "status": "failed",
                    "errorType": "trojan",
                    "kind": "trojan",
                    "outbound": "tunnel-003",
                    "clientPort": str(49000 + index),
                    "flowId": f"tcp-session-{index + 1}",
                    "elapsedMs": "8000",
                },
            }
        )
    return events


def cascade_attempts(failures: int) -> dict[str, object]:
    return {
        "startedAttempts": failures,
        "finishedAttempts": failures,
        "successAttempts": 0,
        "failedAttempts": failures,
        "retryableFailures": failures,
        "stoppedFailures": 0,
        "recoveredFlows": 0,
        "failedByScope": keyed_count("bound", failures),
        "failedByDisposition": keyed_count("pending-timeout", failures),
        "failedByStage": keyed_count("trojan-tls-handshake", failures),
        "failedByStageSurface": keyed_count("trojan-tls-handshake:trojan", failures),
        "failedByStageDisposition": keyed_count("pending-timeout", failures),
        "failedByStopReason": keyed_count("retry-bound-failure-before-replay", failures),
        "failedBySelected": keyed_count("tunnel-003", failures),
    }


def gap_workload(gap_ms: int, success: int, lag: int) -> dict:
    rows = []
    offsets = [0, 500, 1000, 1500, gap_ms, gap_ms + 500, gap_ms + 1000, gap_ms + 1500]
    for index, offset in enumerate(offsets):
        ok = index < success
        rows.append(
            {
                "id": f"item-{index}-r{1 if index < 4 else 2}",
                "domain": "example.com",
                "scheduledOffsetMs": offset,
                "scheduleLagMs": lag if not ok else 0,
                "ok": ok,
                "errorStage": None if ok else "tls-handshake",
                "errorType": None if ok else "tls",
                "errorClass": None if ok else "SSLEOFError",
                "elapsedMs": 1000,
                "localPort": 12345,
            }
        )
    return {
        "seed": f"trojan-paired-wide-roundgap{gap_ms}ms-v1",
        "totals": {
            "count": 8,
            "success": success,
            "failure": 8 - success,
            "successRate": success / 8,
        },
        "results": rows,
    }


def gap_workload_flow_rows(
    workload_rows: list[dict[str, object]],
    terminal: int,
    stage_failures: int,
) -> list[dict[str, object]]:
    rows = []
    terminal_left = terminal
    recovered_left = stage_failures
    for item in workload_rows:
        ok = item.get("ok") is True
        recovered = ok and recovered_left > 0
        terminal_matched = not ok and terminal_left > 0
        if recovered:
            recovered_left -= 1
        if terminal_matched:
            terminal_left -= 1
        rows.append(gap_workload_flow_row(item, ok, terminal_matched, recovered))
    return rows


def gap_workload_flow_row(
    item: dict[str, object],
    ok: bool,
    terminal_matched: bool,
    recovered: bool,
) -> dict[str, object]:
    return {
        "workloadId": item.get("id"),
        "probe": "https-head",
        "domain": item.get("domain"),
        "workloadOk": ok,
        "localPort": item.get("localPort"),
        "workloadTcpConnectOk": True,
        "workloadTcpAttempted": True,
        "workloadRouteViaDynet": True,
        "workloadTunWitnessed": True,
        "runtimePreflowMatched": not terminal_matched,
        "runtimePacketMatched": True,
        "runtimeIngressSynPackets": 1,
        "runtimeEgressSynAckPackets": 1,
        "runtimeFinPackets": 0,
        "runtimeRstPackets": 0,
        "runtimePacketTerminalMatched": terminal_matched,
        "runtimePacketTerminalReason": "closed-before-preflow" if terminal_matched else None,
        "runtimePacketTerminalHandshakeComplete": terminal_matched,
        "runtimePacketTerminalPromotedToSession": False,
        "runtimePacketTerminalIngressControlPackets": 2 if terminal_matched else 0,
        "runtimePacketTerminalEgressControlPackets": 1 if terminal_matched else 0,
        "runtimePacketTerminalIngressPayloadPackets": 1 if terminal_matched else 0,
        "runtimePacketTerminalIngressPayloadBytes": 517 if terminal_matched else 0,
        "runtimePacketTerminalEgressPayloadPackets": 0,
        "runtimePacketTerminalEgressPayloadBytes": 0,
        "runtimePacketTerminalFinPackets": 1 if terminal_matched else 0,
        "runtimePacketTerminalRstPackets": 0,
        "tunCaptureMatched": True,
        "tunCaptureSynPackets": 1,
        "tunCaptureSynAckPackets": 1,
        "flowMatched": not terminal_matched,
        "flowMatchedCount": 2 if recovered else (1 if not terminal_matched else 0),
        "flowFailedCount": 1 if recovered else 0,
        "flowStageFailedCount": 1 if recovered else 0,
        "flowRecoveredFailure": recovered,
        "flowFailed": False,
        "flowCloseReason": "outbound-eof" if ok else None,
        "failureSurface": failure_surface(ok),
    }


def failure_surface(ok: bool) -> str | None:
    if ok:
        return None
    return "https-head:tls-handshake:tls:route-dynet:tun-witnessed"


def keyed_count(key: str | None, count: int) -> list[dict[str, object]]:
    if not key or count == 0:
        return []
    return [{"key": key, "count": count}]
