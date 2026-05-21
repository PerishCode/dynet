from __future__ import annotations

import argparse


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
    checks = [
        check("install-apply", has_lifecycle_pass(install_report, "apply-engine")),
        check("runtime-pass", report.get("status") == "pass"),
        check("tun-observed", int(report.get("tunPackets") or 0) >= 1),
        check("dns-queries", int(report.get("dnsQueries") or 0) >= len(dns_names)),
        check("dns-proxied", int(report.get("proxiedDnsQueries") or 0) >= len(dns_names)),
        check("dns-records", int(report.get("dnsRecords") or 0) >= len(dns_names)),
        check("rule-bypass", {"rule-matched", "plan-bypassed"}.issubset(event_kinds)),
        check("dialer-selected", "dialer-cascade-selected" in event_kinds),
        check("all-dns-names-observed", all(name in queries for name in dns_names)),
        check("uninstall-cleanup", has_lifecycle_pass(uninstall_report, "uninstall-engine")),
    ]
    if args.tcp_forward:
        checks.extend(tcp_acceptance_checks(report, tcp_probe_report, dns_names, event_kinds, stability))
    if args.udp_forward:
        checks.extend(udp_acceptance_checks(args, report, udp_probe_report, event_kinds))
    if args.ipv6_no_leak:
        checks.extend(ipv6_acceptance_checks(report, ipv6_probe_report, event_kinds))
    if args.workload_manifest:
        checks.extend(workload_acceptance_checks(args, report, workload_probe_report, dns_names, queries))
    return checks

def tcp_acceptance_checks(
    report: dict,
    tcp_probe_report: dict,
    dns_names: list[str],
    event_kinds: set,
    stability: dict,
) -> list[dict]:
    tcp_results = [item for item in tcp_probe_report.get("results", []) if isinstance(item, dict)]
    tcp_ok_names = {item.get("name") for item in tcp_results if item.get("https", {}).get("ok") is True}
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
        check("tcp-blackbox-https", all(name in tcp_ok_names for name in dns_names)),
        check(
            "tcp-no-session-failures",
            int(report.get("tcpSessionFailures") or 0) == 0 and "tcp-session-failed" not in event_kinds,
        ),
        check("tcp-session-closed", int(stability.get("tcpClosedSessions") or 0) >= len(dns_names)),
        check("tcp-no-protocol-short-read", int(stability.get("protocolShortReadErrors") or 0) == 0),
    ]

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
) -> list[dict]:
    workload_results = [item for item in workload_probe_report.get("results", []) if isinstance(item, dict)]
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
    return [
        check("workload-attempted", int(workload_probe_report.get("totals", {}).get("count") or 0) > 0),
        check(
            "workload-success-rate",
            float(workload_probe_report.get("totals", {}).get("successRate") or 0)
            >= float(args.workload_min_success_rate),
        ),
        check("workload-dns-observed", all(domain in queries for domain in workload_domains_seen)),
        check("workload-tcp-sessions", int(report.get("tcpSessions") or 0) >= len(dns_names) + len(successful_non_dns)),
    ]

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
