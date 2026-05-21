from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import CommandError, ROOT, join, q
from private_probe import target_family
from private_runtime_lib.common import split_host_port
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
    if not args.udp_direct_probe:
        return config_text
    config = json.loads(config_text)
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
    return json.dumps(config, sort_keys=True)

def runtime_command(
    label: str,
    remote_config: str,
    remote_quality: str | None,
    remote_workload: str | None,
    dns_names: list[str],
    args: argparse.Namespace,
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
        "--upstream-dns",
        args.upstream_dns,
        "--timeout",
        str(args.timeout),
        "--log-level",
        "debug",
    ]
    if args.tcp_forward:
        run.append("--experimental-tcp-forward")
    if args.udp_forward:
        run.append("--experimental-udp-forward")
    elif not remote_workload:
        run.extend(
            [
                "--max-dns-queries",
                str(len(dns_names)),
                "--max-tun-packets",
                "1",
            ]
        )
    if args.udp_forward and not args.ipv6_no_leak:
        run.extend(["--max-udp-sessions", "1"])
    if remote_quality:
        run.extend(["--quality-state", remote_quality])
    probe = ""
    if args.udp_direct_probe:
        probe += udp_probe_python(args.udp_target, args.dns_timeout, udp_probe)
    if args.ipv6_no_leak:
        probe += ipv6_leak_probe_python(args.ipv6_target, args.dns_timeout, ipv6_probe)
    probe += (
        tcp_probe_python(dns_names, upstream_host, upstream_port, args.dns_timeout, tcp_probe)
        if args.tcp_forward
        else dns_probe_python(dns_names, upstream_host, upstream_port, args.dns_timeout)
    )
    if remote_workload:
        probe += workload_probe_python(
            remote_workload,
            upstream_host,
            upstream_port,
            args.dns_timeout,
            workload_probe,
            args.workload_respect_schedule,
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
