from __future__ import annotations

import argparse

from private_runtime_lib import downstream_stop
from private_runtime_lib.briefs import tcp_target_identity_brief
from private_runtime_lib.config import POISON_TAG
from private_runtime_lib.diagnostics.quality import quality_acceptance_checks
from private_runtime_lib.tcp_flow import tcp_flow_brief, workload_flow_brief
from private_runtime_lib.tcp_flow.route_fallback_checks import (
    RELAXED_TCP_CHECKS,
    direct_fallback_checks,
    non_direct_fallback_checks,
)
from private_runtime_lib.tcp_flow.pressure import tcp_slot_pressure_ok


def acceptance_checks(
    report: dict,
    install_report: dict,
    uninstall_report: dict,
    tcp_probe_report: dict,
    udp_probe_report: dict,
    ipv6_probe_report: dict,
    workload_probe_report: dict,
    dns_names: list[str],
    args: argparse.Namespace,
    stability: dict,
) -> list[dict]:
    events = report.get("events", [])
    event_kinds = {event.get("kind") for event in events if isinstance(event, dict)}
    queries = {
        str(event.get("fields", {}).get("query"))
        for event in events
        if isinstance(event, dict) and isinstance(event.get("fields"), dict)
    }
    if getattr(args, "force_private_downstream_failure", False):
        return downstream_stop.checks(
            report,
            install_report,
            uninstall_report,
            dns_names,
            event_kinds,
            queries,
        )
    probe_names = probe_dns_names(args, dns_names)
    checks = [
        check("install-apply", has_lifecycle_pass(install_report, "apply-engine")),
        check("runtime-pass", report.get("status") == "pass"),
        check("tun-observed", int(report.get("tunPackets") or 0) >= 1),
        check("dns-queries", int(report.get("dnsQueries") or 0) >= len(probe_names)),
        check("dns-forwarding", dns_forwarding_ok(report, args, probe_names)),
        check("dns-records", int(report.get("dnsRecords") or 0) >= len(probe_names)),
        check("route-or-rule", route_or_rule_matched(event_kinds)),
        check("dialer-selected", "dialer-cascade-selected" in event_kinds),
        check("all-dns-names-observed", all(name in queries for name in probe_names)),
        check("uninstall-cleanup", has_lifecycle_pass(uninstall_report, "uninstall-engine")),
    ]
    if args.tcp_forward:
        tcp_checks = tcp_acceptance_checks(
            report,
            tcp_probe_report,
            probe_names,
            event_kinds,
            stability,
            workload_probe_report,
        )
        if getattr(args, "tcp_route_direct_fallback", False):
            tcp_checks = [
                item
                for item in tcp_checks
                if item["name"] not in RELAXED_TCP_CHECKS
            ]
            tcp_checks.extend(direct_fallback_checks(report))
        if getattr(args, "tcp_route_non_direct_fallback", False):
            tcp_checks.extend(non_direct_fallback_checks(report))
        checks.extend(tcp_checks)
    if args.udp_forward:
        checks.extend(udp_acceptance_checks(args, report, udp_probe_report, event_kinds))
    if args.ipv6_no_leak:
        checks.extend(ipv6_acceptance_checks(report, ipv6_probe_report, event_kinds))
    if args.workload_manifest:
        checks.extend(
            workload_acceptance_checks(
                args,
                report,
                workload_probe_report,
                dns_names,
                queries,
                tcp_probe_report,
            )
        )
    if args.quality_state and args.tcp_forward:
        checks.extend(
            quality_acceptance_checks(
                report,
                route_non_direct_fallback=getattr(args, "tcp_route_non_direct_fallback", False),
            )
        )
    if getattr(args, "poison_first_bound_candidate", False):
        checks.extend(fallback_acceptance_checks(report))
    return checks


def fallback_acceptance_checks(report: dict) -> list[dict]:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    return [
        check("dns-pre-query-fallback", fallback_flow(events, "dns-query-", "pre-query")),
        check("tcp-pre-payload-fallback", fallback_flow(events, "tcp-session-", "pre-payload")),
        check("tcp-payload-lock", payload_lock_after_fallback(events)),
    ]


def fallback_flow(events: list[dict], flow_prefix: str, replay_safe: str) -> bool:
    started = [
        event
        for event in events
        if event.get("kind") == "dialer-cascade-attempt-started"
        and field(event, "flowId").startswith(flow_prefix)
        and field(event, "replaySafe") == replay_safe
    ]
    finished = [
        event
        for event in events
        if event.get("kind") == "dialer-cascade-attempt-finished"
        and field(event, "flowId").startswith(flow_prefix)
    ]
    poison_failed = any(
        field(event, "boundSelected") == POISON_TAG
        and field(event, "status") == "failed"
        and field(event, "failureScope") == "bound"
        for event in finished
    )
    recovered = any(
        field(event, "boundSelected") != POISON_TAG
        and field(event, "status") == "success"
        and field(event, "failureScope") == "none"
        for event in finished
    )
    poison_started = any(field(event, "boundSelected") == POISON_TAG for event in started)
    return poison_started and poison_failed and recovered


def payload_lock_after_fallback(events: list[dict]) -> bool:
    return any(
        event.get("kind") == "tcp-session-payload-first-write"
        and field(event, "candidateRetryAllowed") == "false"
        for event in events
    )


def field(event: dict, key: str) -> str:
    fields = event.get("fields")
    if not isinstance(fields, dict):
        return ""
    return str(fields.get(key) or "")

def route_or_rule_matched(event_kinds: set) -> bool:
    return {"rule-matched", "plan-bypassed"}.issubset(event_kinds) or "route-matched" in event_kinds

def probe_dns_names(args: argparse.Namespace, dns_names: list[str]) -> list[str]:
    if getattr(args, "tcp_forward", False) and not getattr(args, "tcp_probe", True):
        return []
    return dns_names

def dns_forwarding_ok(report: dict, args: argparse.Namespace, dns_names: list[str]) -> bool:
    if getattr(args, "tcp_route_plan_private", False):
        return int(report.get("dnsRecords") or 0) >= len(dns_names)
    return int(report.get("proxiedDnsQueries") or 0) >= len(dns_names)

def tcp_acceptance_checks(
    report: dict,
    tcp_probe_report: dict,
    dns_names: list[str],
    event_kinds: set,
    stability: dict,
    workload_probe_report: dict | None = None,
) -> list[dict]:
    tcp_results = [item for item in tcp_probe_report.get("results", []) if isinstance(item, dict)]
    tcp_ok_names = {item.get("name") for item in tcp_results if item.get("https", {}).get("ok") is True}
    product_ok_names = tcp_ok_names | successful_workload_https_domains(workload_probe_report or {})
    identity = tcp_target_identity_brief(report)
    flow = tcp_flow_brief(report)
    lifecycle = tcp_lifecycle_counts(report)
    return [
        check("tcp-sessions", int(report.get("tcpSessions") or 0) >= len(dns_names)),
        check("tcp-upstream-bytes", int(report.get("tcpUpstreamBytes") or 0) > 0),
        check("tcp-downstream-bytes", int(report.get("tcpDownstreamBytes") or 0) > 0),
        check(
            "tcp-session-events",
            {
                "tcp-session-started",
                "tcp-session-attributed",
                "tcp-session-established",
                "tcp-session-payload-first-write",
            }.issubset(event_kinds),
        ),
        check("tcp-blackbox-https", all(name in product_ok_names for name in dns_names)),
        check(
            "tcp-no-session-failures",
            int(report.get("tcpSessionFailures") or 0) == 0 and "tcp-session-failed" not in event_kinds,
        ),
        check("tcp-session-closed", int(stability.get("tcpClosedSessions") or 0) >= len(dns_names)),
        check("tcp-no-protocol-short-read", int(stability.get("protocolShortReadErrors") or 0) == 0),
        check("tcp-listen-capacity-reported", int(report.get("tcpListenCapacity") or 0) > 0),
        check(
            "tcp-no-slot-pressure",
            tcp_slot_pressure_ok(report, flow, workload_probe_report),
        ),
        check("tcp-close-events-unique", lifecycle["closeEvents"] == lifecycle["uniqueClosed"]),
        check("tcp-close-events-within-sessions", lifecycle["closeEvents"] <= lifecycle["startedEvents"]),
        check(
            "tcp-connect-target-reported",
            int(identity.get("connectingEvents") or 0) > 0
            and int(identity.get("withConnectTarget") or 0) == int(identity.get("connectingEvents") or 0),
        ),
        check(
            "tcp-target-source-reported",
            int(identity.get("withTargetAddressSource") or 0) == int(identity.get("connectingEvents") or 0),
        ),
        check("tcp-identity-domain-reported", int(identity.get("withIdentityDomain") or 0) >= len(dns_names)),
        check("tcp-domain-connect-target", int(identity.get("domainConnectTargets") or 0) >= len(dns_names)),
        check(
            "tcp-adapter-target-reported",
            int(identity.get("adapterConnectEvents") or 0) > 0
            and int(identity.get("withAdapterTarget") or 0) == int(identity.get("adapterConnectEvents") or 0),
        ),
        check("tcp-adapter-domain-target", int(identity.get("adapterDomainTargets") or 0) >= len(dns_names)),
        check(
            "tcp-target-chain-complete",
            int(identity.get("targetChainFlows") or 0) == int(identity.get("connectingEvents") or 0)
            and int(identity.get("targetChainAdapterFlows") or 0) >= int(flow.get("establishedFlows") or 0)
            and int(identity.get("targetChainMissingAdapter") or 0) == 0
            and int(identity.get("targetChainMissingConnect") or 0) == 0,
        ),
        check(
            "tcp-target-chain-matched",
            int(identity.get("targetChainMatched") or 0) >= len(dns_names)
            and int(identity.get("targetChainMismatched") or 0) == 0,
        ),
        check(
            "tcp-flow-lifecycle-complete",
            int(flow.get("startedFlows") or 0) > 0
            and int(flow.get("lifecycleCompleteFlows") or 0) == int(flow.get("startedFlows") or 0)
            and int(flow.get("failedFlows") or 0) == 0,
        ),
        check(
            "tcp-flow-path-complete",
            int(flow.get("pathCompleteFlows") or 0) == int(flow.get("startedFlows") or 0),
        ),
        check(
            "tcp-flow-close-byte-totals",
            int(flow.get("closedWithByteTotals") or 0) == int(flow.get("closedFlows") or 0)
            and int(flow.get("closedFlows") or 0) >= len(dns_names),
        ),
        check(
            "tcp-flow-payload-bidirectional",
            int(flow.get("payloadStartedFlows") or 0) > 0
            and int(flow.get("payloadCloseConsistent") or 0) == int(flow.get("payloadBidirectionalFlows") or 0)
            and int(flow.get("payloadBidirectionalFlows") or 0) >= len(dns_names),
        ),
    ]


def tcp_lifecycle_counts(report: dict) -> dict[str, int]:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    started = [
        event
        for event in events
        if event.get("kind") == "tcp-session-started"
    ]
    closed = [
        event
        for event in events
        if event.get("kind") == "tcp-session-closed"
    ]
    closed_ids = {
        str(event.get("fields", {}).get("flowId"))
        for event in closed
        if isinstance(event.get("fields"), dict)
    }
    return {
        "startedEvents": len(started),
        "closeEvents": len(closed),
        "uniqueClosed": len(closed_ids),
    }

def udp_acceptance_checks(
    args: argparse.Namespace,
    report: dict,
    udp_probe_report: dict,
    event_kinds: set,
) -> list[dict]:
    checks = [
        check(
            "udp-session-events",
            "udp-session-started" in event_kinds
            and (
                "udp-session-established" in event_kinds
                or "udp-session-denied" in event_kinds
                or "udp-session-failed" in event_kinds
            ),
        ),
        check(
            "udp-attribution-events",
            "udp-session-attributed" in event_kinds
            and ({"rule-matched", "plan-bypassed"}.issubset(event_kinds) or "route-matched" in event_kinds),
        ),
    ]
    if args.udp_direct_probe:
        checks.extend(
            [
                check("udp-direct-blackbox", udp_probe_report.get("ok") is True),
                check("udp-sessions", int(report.get("udpSessions") or 0) >= 1),
                check("udp-upstream-bytes", int(report.get("udpUpstreamBytes") or 0) > 0),
                check("udp-downstream-bytes", int(report.get("udpDownstreamBytes") or 0) > 0),
                check("udp-no-session-failures", int(report.get("udpSessionFailures") or 0) == 0),
            ]
        )
    else:
        checks.append(
            check(
                "udp-fail-closed",
                "udp-session-denied" in event_kinds or int(report.get("udpDroppedPackets") or 0) > 0,
            )
        )
    return checks

def ipv6_acceptance_checks(report: dict, ipv6_probe_report: dict, event_kinds: set) -> list[dict]:
    return [
        check("ipv6-blackbox-no-response", ipv6_probe_report.get("ok") is True),
        check("ipv6-denied-counter", int(report.get("ipv6PacketsDenied") or 0) >= 1),
        check("ipv6-denied-event", "ip-packet-denied" in event_kinds),
    ]

def workload_acceptance_checks(
    args: argparse.Namespace,
    report: dict,
    workload_probe_report: dict,
    dns_names: list[str],
    queries: set[str],
    tcp_probe_report: dict | None = None,
) -> list[dict]:
    workload_results = [item for item in workload_probe_report.get("results", []) if isinstance(item, dict)]
    workload_totals = workload_probe_report.get("totals", {})
    attempted = int(workload_totals.get("count") or 0)
    success = int(workload_totals.get("success") or 0)
    failure = int(workload_totals.get("failure") or 0)
    workload_domains_seen = {
        str(item.get("domain"))
        for item in workload_results
        if isinstance(item.get("domain"), str)
    }
    successful_non_dns = [
        item
        for item in workload_results
        if item.get("probe") != "dns" and item.get("ok") is True
    ]
    workload_flow = workload_flow_brief(report, workload_probe_report) if getattr(args, "tcp_forward", False) else {}
    packet_terminal = int(workload_flow.get("packetTerminalEntries") or 0)
    expected_sessions = successful_tcp_probe_count(tcp_probe_report or {}) + max(len(successful_non_dns) - packet_terminal, 0)
    checks = [
        check("workload-attempted", attempted > 0),
        check("workload-totals-consistent", attempted == success + failure),
        check(
            "workload-success-rate",
            float(workload_totals.get("successRate") or 0)
            >= float(args.workload_min_success_rate),
        ),
        check("workload-dns-observed", all(domain in queries for domain in workload_domains_seen)),
        check("workload-tcp-sessions", int(report.get("tcpSessions") or 0) >= expected_sessions),
    ]
    if getattr(args, "workload_require_all_success", False):
        checks.append(check("workload-all-success", failure == 0))
    if getattr(args, "tcp_forward", False):
        checks.extend(workload_flow_acceptance_checks(report, workload_probe_report))
    concurrency = workload_probe_report.get("concurrency", {})
    if isinstance(concurrency, dict) and concurrency.get("enabled") is True:
        checks.append(check("workload-concurrent-sessions", int(report.get("tcpActiveSlotsMax") or 0) > 1))
    return checks


def successful_tcp_probe_count(tcp_probe_report: dict) -> int:
    return sum(
        1
        for item in tcp_probe_report.get("results", [])
        if isinstance(item, dict) and item.get("https", {}).get("ok") is True
    )


def successful_workload_https_domains(workload_probe_report: dict) -> set[str]:
    return {
        str(item.get("domain"))
        for item in workload_probe_report.get("results", [])
        if isinstance(item, dict)
        and item.get("ok") is True
        and item.get("probe") in {"https-head", "https-get"}
        and isinstance(item.get("domain"), str)
    }


def workload_flow_acceptance_checks(report: dict, workload_probe_report: dict) -> list[dict]:
    flow = workload_flow_brief(report, workload_probe_report)
    event_kinds = {
        event.get("kind")
        for event in report.get("events", [])
        if isinstance(event, dict)
    }
    entries = int(flow.get("entries") or 0)
    if entries == 0:
        return []
    matched = int(flow.get("matchedEntries") or 0)
    flow_required = int(flow.get("tcpAttemptedEntries") or 0)
    required_covered = int(flow.get("tcpAttemptedCoveredEntries") or 0)
    terminal = int(flow.get("matchedClosed") or 0) + int(flow.get("matchedFlowFailed") or 0)
    checks = [
        check(
            "workload-flow-local-ports",
            int(flow.get("tcpAttemptedEntriesWithLocalPort") or 0) == flow_required,
        ),
        check("workload-flow-path-complete", int(flow.get("matchedPathComplete") or 0) == matched),
        check("workload-flow-lifecycle-complete", int(flow.get("matchedLifecycleComplete") or 0) == matched),
        check("workload-flow-terminal", terminal == matched),
    ]
    if "tcp-forwarder-packet" in event_kinds:
        checks.append(check("workload-flow-covered", required_covered == flow_required))
    else:
        checks.append(
            check("workload-flow-matched", matched == entries and int(flow.get("unmatchedEntries") or 0) == 0)
        )
    capture = workload_probe_report.get("tunCapture", {}) if isinstance(workload_probe_report, dict) else {}
    if isinstance(capture, dict) and capture.get("enabled") is True:
        checks.extend(
            [
                check("workload-tun-capture-started", capture.get("started") is True),
                check(
                    "workload-tun-capture-privacy",
                    capture.get("rawLinesStored") is False and capture.get("rawPcapStored") is False,
                ),
                check(
                    "workload-flow-tun-capture-matched",
                    int(flow.get("tcpAttemptedTunCaptureMatchedEntries") or 0) == flow_required,
                ),
            ]
        )
    if "tcp-forwarder-packet" in event_kinds:
        checks.extend(
            [
                check(
                    "workload-flow-runtime-packet-matched",
                    int(flow.get("tcpAttemptedRuntimePacketMatchedEntries") or 0) == flow_required,
                ),
                check(
                    "workload-flow-runtime-syn-matched",
                    int(flow.get("tcpAttemptedRuntimeIngressSynMatchedEntries") or 0) == flow_required,
                ),
            ]
        )
    return checks


def check(name: str, passed: bool) -> dict:
    return {"name": name, "passed": bool(passed)}

def product_forwarding_evidence(args: argparse.Namespace) -> str:
    parts = []
    if args.tcp_forward:
        parts.append("TCP session lifecycle and byte counters are enabled")
    if args.udp_forward:
        if args.udp_direct_probe:
            parts.append("UDP direct black-box probe and UDP session counters are enabled")
        else:
            parts.append("UDP forwarding gate is enabled; unsupported paths must fail closed")
    if args.ipv6_no_leak:
        parts.append("IPv6 no-leak probe and ip-packet-denied events are enabled")
    if args.workload_manifest:
        parts.append("workload manifest replay is enabled through the same TUN/Private runtime")
    if not parts:
        return "runtime reports TUN packet observation and DNS hijack only; forwarding experiments were not enabled"
    return "; ".join(parts)

def has_lifecycle_pass(report: dict, name: str) -> bool:
    for item in report.get("checks", []):
        if item.get("name") == name and item.get("status") == "pass":
            return True
    return False
