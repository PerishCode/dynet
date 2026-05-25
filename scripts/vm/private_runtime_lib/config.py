from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import CommandError, ROOT, join, q
from private_probe import target_family
from private_runtime_lib.common import split_host_port
from private_runtime_lib.diagnostics.config import (
    POISON_BOUND_PLAN_TAG,
    POISON_DIALER_TAG,
    POISON_TAG,
    ROUTE_FALLBACK_TAG,
    add_direct_fallback,
    add_non_direct_fallback,
    add_poison_bound_candidate,
    force_bound_candidate,
    poison_private_downstream,
    set_poison_bound_only,
)
from private_runtime_lib.probe_scripts import (
    dns_probe_python,
    ipv6_leak_probe_python,
    tcp_probe_python,
    udp_probe_python,
)
from private_runtime_lib.workload_script import workload_probe_python


def load_workload_manifest(args: argparse.Namespace) -> dict | None:
    if not args.workload_manifest:
        return None
    path = Path(args.workload_manifest).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    manifest = json.loads(path.read_text())
    entries = workload_entries(manifest)
    if not entries:
        raise CommandError("--workload-manifest has no entries")
    probes = {str(entry.get("probe")) for entry in entries}
    unsupported = probes - {"dns", "tcp-connect", "tls-handshake", "https-head", "https-get"}
    if unsupported:
        raise CommandError(
            "--workload-manifest has unsupported probes: " + ", ".join(sorted(unsupported))
        )
    if any(probe != "dns" for probe in probes) and not args.tcp_forward:
        raise CommandError("--workload-manifest with TCP/TLS/HTTPS probes requires --tcp-forward")
    return manifest

def workload_entries(manifest: dict | None) -> list[dict]:
    if not isinstance(manifest, dict):
        return []
    return [
        item
        for item in manifest.get("entries", [])
        if isinstance(item, dict) and isinstance(item.get("domain"), str)
    ]

def workload_domains(manifest: dict | None) -> list[str]:
    domains = []
    seen = set()
    for entry in workload_entries(manifest):
        domain = str(entry["domain"]).lower().strip(".")
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains

def add_required_domain_suffixes(args: argparse.Namespace, names: list[str], manifest: dict | None) -> None:
    suffixes = {target_family(f"https://{name}/") for name in names}
    suffixes.update(target_family(f"https://{domain}/") for domain in workload_domains(manifest))
    args.domain_suffix = sorted(set(args.domain_suffix or []) | suffixes)

def augment_runtime_config(config_text: str, args: argparse.Namespace) -> str:
    if (
        not args.udp_direct_probe
        and not getattr(args, "poison_first_bound_candidate", False)
        and not getattr(args, "poison_bound_only", False)
        and not getattr(args, "force_bound_candidate", None)
        and not getattr(args, "force_private_downstream_failure", False)
        and not getattr(args, "tcp_route_direct_fallback", False)
        and not getattr(args, "tcp_route_non_direct_fallback", False)
    ):
        return config_text
    if getattr(args, "tcp_route_direct_fallback", False) and getattr(
        args,
        "tcp_route_non_direct_fallback",
        False,
    ):
        raise CommandError(
            "--tcp-route-direct-fallback cannot be combined with --tcp-route-non-direct-fallback"
        )
    if getattr(args, "tcp_route_non_direct_fallback", False) and (
        getattr(args, "poison_first_bound_candidate", False)
        or getattr(args, "poison_bound_only", False)
    ):
        raise CommandError(
            "--tcp-route-non-direct-fallback cannot be combined with tunnel bound poison overrides"
        )
    if getattr(args, "poison_first_bound_candidate", False) and getattr(args, "force_bound_candidate", None):
        raise CommandError("--force-bound-candidate cannot be combined with --poison-first-bound-candidate")
    if getattr(args, "poison_bound_only", False) and (
        getattr(args, "poison_first_bound_candidate", False) or getattr(args, "force_bound_candidate", None)
    ):
        raise CommandError("--poison-bound-only cannot be combined with bound candidate overrides")
    config = json.loads(config_text)
    if getattr(args, "poison_first_bound_candidate", False):
        add_poison_bound_candidate(config)
    if getattr(args, "poison_bound_only", False):
        set_poison_bound_only(config)
    if forced := getattr(args, "force_bound_candidate", None):
        force_bound_candidate(config, str(forced))
    if getattr(args, "force_private_downstream_failure", False):
        poison_private_downstream(config)
    if getattr(args, "tcp_route_direct_fallback", False):
        add_direct_fallback(config, args)
    if getattr(args, "tcp_route_non_direct_fallback", False):
        add_non_direct_fallback(config, args)
    if args.udp_direct_probe:
        add_direct_udp_probe(config, args)
    return json.dumps(config, sort_keys=True)


def add_direct_udp_probe(config: dict, args: argparse.Namespace) -> None:
    host, _ = split_host_port(args.udp_target)
    outbounds = config.setdefault("outbounds", [])
    if not any(item.get("tag") == "direct-udp-probe" for item in outbounds if isinstance(item, dict)):
        outbounds.append(
            {
                "tag": "direct-udp-probe",
                "type": "direct",
                "metadata": {"purpose": "vm-runtime-udp-forwarding-probe"},
            }
        )
    routes = config.setdefault("routes", [])
    routes.insert(
        0,
        {
            "inbound": "tun-in",
            "transport": "udp",
            "ipCidr": host + "/32",
            "outbound": "direct-udp-probe",
        },
    )

def runtime_command(
    label: str,
    remote_config: str,
    remote_quality: str | None,
    remote_workload: str | None,
    dns_names: list[str],
    args: argparse.Namespace,
    workload_manifest: dict | None = None,
) -> str:
    out = f"/tmp/dynet-{label}-private-runtime.json"
    err = f"/tmp/dynet-{label}-private-runtime.err"
    install = f"/tmp/dynet-{label}-private-install.json"
    uninstall = f"/tmp/dynet-{label}-private-uninstall.json"
    tcp_probe = f"/tmp/dynet-{label}-private-tcp-probe.json"
    udp_probe = f"/tmp/dynet-{label}-private-udp-probe.json"
    ipv6_probe = f"/tmp/dynet-{label}-private-ipv6-probe.json"
    workload_probe = f"/tmp/dynet-{label}-private-workload-probe.json"
    upstream_host, upstream_port = args.upstream_dns.rsplit(":", 1)
    run = [
        "sudo",
        args.dynet_bin,
        "run",
        "--config",
        remote_config,
        "--format",
        "json",
        "--timeout",
        str(effective_runtime_timeout(args, workload_manifest)),
        "--log-level",
        "debug",
    ]
    if getattr(args, "runtime_udp_dns", False):
        run.extend(["--upstream-dns", args.upstream_dns])
    if args.tcp_forward:
        run.append("--experimental-tcp-forward")
        if args.tcp_listen_slots_per_port:
            run.extend([
                "--experimental-tcp-listen-slots-per-port",
                str(args.tcp_listen_slots_per_port),
            ])
        run.extend([
            "--outbound-tcp-connect-timeout-ms",
            str(args.outbound_tcp_connect_timeout_ms),
            "--outbound-tcp-read-write-timeout-ms",
            str(args.outbound_tcp_read_write_timeout_ms),
        ])
        tcp_terminals = expected_tcp_terminal_sessions(
            dns_names,
            workload_manifest,
            tcp_probe_enabled(args),
        )
        if tcp_terminals:
            run.extend(["--max-tcp-terminal-sessions", str(tcp_terminals)])
    if args.udp_forward:
        run.append("--experimental-udp-forward")
    elif not remote_workload and not args.tcp_forward:
        run.extend(
            [
                "--max-dns-queries",
                str(len(dns_names)),
                "--max-tun-packets",
                "1",
            ]
        )
    if args.udp_forward and args.udp_direct_probe and not args.ipv6_no_leak:
        run.extend(["--max-udp-downstream-bytes", "1"])
    elif args.udp_forward and not args.ipv6_no_leak:
        run.extend(["--max-udp-sessions", "1"])
    if remote_quality:
        run.extend(["--quality-state", remote_quality])
    probe = ""
    if args.udp_direct_probe:
        probe += udp_probe_python(args.udp_target, args.dns_timeout, udp_probe)
    if args.ipv6_no_leak:
        probe += ipv6_leak_probe_python(args.ipv6_target, args.dns_timeout, ipv6_probe)
    if tcp_probe_enabled(args):
        probe += tcp_probe_python(dns_names, upstream_host, upstream_port, args.dns_timeout, tcp_probe)
    elif not args.tcp_forward:
        probe += dns_probe_python(dns_names, upstream_host, upstream_port, args.dns_timeout)
    if remote_workload:
        probe += workload_probe_python(
            remote_workload,
            upstream_host,
            upstream_port,
            args.dns_timeout,
            workload_probe,
            args.workload_respect_schedule,
            args.workload_concurrency_limit,
        )
    tun_packet_probe = (
        ""
        if args.tcp_forward
        else (
            f"sudo ip route replace {q(args.tun_target)}/32 dev dynet0; "
            f"ping -c 1 -W 1 {q(args.tun_target)} >/dev/null 2>&1 || true; "
        )
    )
    return (
        "set -e; "
        f"out={q(out)}; err={q(err)}; install={q(install)}; uninstall={q(uninstall)}; "
        f"tcp_probe={q(tcp_probe)}; udp_probe={q(udp_probe)}; ipv6_probe={q(ipv6_probe)}; workload_probe={q(workload_probe)}; "
        "rm -f \"$out\" \"$err\" \"$install\" \"$uninstall\" \"$tcp_probe\" \"$udp_probe\" \"$ipv6_probe\" \"$workload_probe\"; "
        "pid=''; "
        "cleanup() { "
        "if [ -n \"$pid\" ]; then sudo kill \"$pid\" >/dev/null 2>&1 || true; wait \"$pid\" >/dev/null 2>&1 || true; fi; "
        f"sudo ip route del {q(args.tun_target)}/32 dev dynet0 >/dev/null 2>&1 || true; "
        f"sudo {q(args.dynet_bin)} uninstall --format json >\"$uninstall\" 2>/dev/null || true; "
        "}; "
        "trap cleanup EXIT; "
        f"sudo {q(args.dynet_bin)} install --config {q(remote_config)} --format json >\"$install\"; "
        f"{join(run)} >\"$out\" 2>\"$err\" & pid=$!; "
        "sleep 1; "
        f"{tun_packet_probe}"
        f"{probe}"
        "wait \"$pid\"; pid=''; "
        "cleanup; trap - EXIT"
    )


def effective_runtime_timeout(args: argparse.Namespace, manifest: dict | None) -> int:
    timeout = int(args.timeout or 0)
    entries = workload_entries(manifest)
    if not entries:
        return timeout
    workload = manifest.get("workload", {}) if isinstance(manifest, dict) else {}
    duration = int(workload.get("durationSeconds") or 0) if isinstance(workload, dict) else 0
    probe_timeout = int(args.dns_timeout)
    stage_budget = workload_stage_timeout_budget(
        entries,
        workload,
        probe_timeout,
        getattr(args, "workload_concurrency_limit", None),
    )
    return max(timeout, duration + stage_budget + 10)


def workload_stage_timeout_budget(
    entries: list[dict],
    workload: dict,
    probe_timeout: int,
    concurrency_limit: int | None = None,
) -> int:
    stage_counts = [workload_probe_timeout_stages(str(item.get("probe") or "https-head")) for item in entries]
    if not stage_counts:
        return 0
    if workload_is_concurrent(workload):
        batches = workload_concurrency_batches(len(entries), concurrency_limit)
        return batches * max(stage_counts) * probe_timeout
    return sum(stage_counts) * probe_timeout


def workload_is_concurrent(workload: dict) -> bool:
    mode = str(workload.get("mode") or "")
    return bool(workload.get("concurrent")) or mode == "concurrent" or "parallel" in mode


def workload_concurrency_batches(entry_count: int, limit: int | None) -> int:
    if entry_count <= 0:
        return 0
    if not limit or limit <= 0:
        return 1
    effective_limit = max(1, min(int(limit), entry_count))
    return (entry_count + effective_limit - 1) // effective_limit


def workload_probe_timeout_stages(probe: str) -> int:
    if probe == "dns":
        return 1
    if probe == "tcp-connect":
        return 2
    if probe == "tls-handshake":
        return 3
    if probe in {"https-head", "https-get"}:
        return 4
    return 4


def tcp_probe_enabled(args: argparse.Namespace) -> bool:
    return bool(args.tcp_forward and getattr(args, "tcp_probe", True))


def expected_tcp_terminal_sessions(
    dns_names: list[str],
    manifest: dict | None,
    include_tcp_probe: bool = True,
) -> int:
    entries = workload_entries(manifest)
    workload_tcp = sum(1 for item in entries if str(item.get("probe") or "https-head") != "dns")
    probe_tcp = len(dns_names) if include_tcp_probe else 0
    return probe_tcp + workload_tcp
