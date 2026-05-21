#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import random
import socket
import ssl
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA = "dynet-real-access-manifest/v1alpha1"
RUN_SCHEMA = "dynet-real-access-blackbox-run/v1alpha1"
COMPARE_SCHEMA = "dynet-real-access-blackbox-comparison/v1alpha1"
OBSERVER_VERSION = "real-access-blackbox/0.2"
ERROR_TAXONOMY_VERSION = "v1alpha1"
TARGET_POLICY_VERSION = "v1alpha1"
DEFAULT_PROFILE = ".task/resources/clash-verge-access-profile.json"
DEFAULT_RUN_ROOT = ".task/resources/real-access-runs"
DEFAULT_SEED = "dynet-real-access-v1"
DEFAULT_ENVIRONMENT = "system-current"
DEFAULT_PROBES = ("dns", "tcp-connect", "tls-handshake", "https-head", "https-get")
DEFAULT_BEHAVIORS = ("single", "repeat", "burst", "interval")
DEFAULT_CONTROL_DOMAINS = (
    "www.cloudflare.com",
    "example.com",
    "github.com",
    "www.google.com",
)
USER_AGENT = "dynet-real-access-blackbox/0.1"
HTTP_REQUEST_TARGET = "/"
HTTP_GET_READ_LIMIT = 8192
ATTRIBUTION_TRACE_FIELDS = (
    "route.rule",
    "route.outbound",
    "plan.strategy",
    "plan.candidates",
    "plan.selectedOutbound",
    "cascade.attempts",
    "admission.verdict",
    "egress.verdict",
    "outbound.qualityState",
)


class ProbeSemanticError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def parse_csv(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {item.strip() for item in value.split(",") if item.strip()}


def parse_csv_ordered(value: str | None, default: tuple[str, ...]) -> list[str]:
    if not value:
        return list(default)
    selected = [item.strip() for item in value.split(",") if item.strip()]
    return selected or list(default)


def load_pools(profile: dict[str, Any], buckets: set[str] | None) -> list[dict[str, Any]]:
    pools = profile.get("experimentProfile", {}).get("samplePools", [])
    selected = []
    for pool in pools:
        if buckets and pool.get("name") not in buckets:
            continue
        domains = [
            domain
            for domain in pool.get("domains", [])
            if isinstance(domain, str) and domain and not domain.startswith("ip:")
        ]
        modes = [
            mode
            for mode in pool.get("probeModes", [])
            if isinstance(mode, str) and mode in DEFAULT_PROBES
        ]
        if "https-head" in modes and "https-get" not in modes:
            modes.append("https-get")
        if domains and modes:
            selected.append({**pool, "domains": domains, "probeModes": modes})
    return selected


def control_pool(args: argparse.Namespace) -> dict[str, Any] | None:
    domains = list(args.control_domain or [])
    if not args.no_default_controls:
        domains.extend(DEFAULT_CONTROL_DOMAINS)
    domains = unique_domains(domains)
    if not domains:
        return None
    return {
        "name": "control-global",
        "weight": args.control_weight,
        "purpose": "stable zero-identity control endpoints",
        "domains": domains,
        "probeModes": list(DEFAULT_PROBES),
    }


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    profile_path = Path(args.profile)
    profile = load_json(profile_path)
    pools = load_pools(profile, parse_csv(args.buckets))
    control = control_pool(args)
    if control is not None:
        pools.append(control)
    if not pools:
        raise SystemExit("profile has no selectable sample pools")
    requested_modes = parse_csv(args.probe_modes)
    if requested_modes:
        unsupported = requested_modes - set(DEFAULT_PROBES)
        if unsupported:
            raise SystemExit(f"unsupported probe modes: {', '.join(sorted(unsupported))}")
    behaviors = [
        behavior
        for behavior in parse_csv_ordered(args.behaviors, DEFAULT_BEHAVIORS)
        if behavior in DEFAULT_BEHAVIORS
    ]
    if not behaviors:
        raise SystemExit("no supported workload behaviors selected")
    rng = random.Random(args.seed)
    weights = [max(int(pool.get("weight", 1)), 1) for pool in pools]
    entries = []
    history: list[str] = []
    burst_domains: dict[str, str] = {}
    for index in range(args.count):
        pool = rng.choices(pools, weights=weights, k=1)[0]
        modes = [
            mode
            for mode in pool["probeModes"]
            if requested_modes is None or mode in requested_modes
        ]
        if not modes:
            modes = list(DEFAULT_PROBES)
        behavior = rng.choice(behaviors)
        burst_id = None
        if behavior == "repeat" and history:
            domain = rng.choice(history)
        elif behavior == "burst":
            burst_id = f"burst-{rng.randrange(max(args.burst_groups, 1)) + 1:02d}"
            domain = burst_domains.setdefault(burst_id, rng.choice(pool["domains"]))
        else:
            domain = rng.choice(pool["domains"])
        probe = rng.choice(modes)
        entries.append(
            {
                "id": f"{index + 1:04d}",
                "bucket": pool["name"],
                "domain": domain,
                "behavior": behavior,
                "groupId": burst_id or f"{behavior}-{site_for_domain(domain)}",
                "probe": probe,
                "port": default_port(probe),
                "timeoutMs": int(args.timeout_seconds * 1000),
            }
        )
        history.append(domain)
    apply_schedule(entries, args, rng)
    return {
        "schema": MANIFEST_SCHEMA,
        "generatedAt": utc_now(),
        "environment": args.environment,
        "seed": args.seed,
        "profile": {
            "path": str(profile_path),
            "schema": profile.get("schema"),
            "summary": profile.get("summary", {}),
        },
        "privacy": privacy_model(),
        "workload": {
            "version": "v1",
            "durationSeconds": args.duration_seconds,
            "count": args.count,
            "behaviors": behaviors,
            "schedule": "seeded-offsets" if args.duration_seconds > 0 else "spacing-only",
            "burstGroups": args.burst_groups,
            "burstWindowMs": args.burst_window_ms,
            "jitterMs": args.jitter_ms,
            "zeroIdentity": True,
        },
        "sampling": {
            "count": args.count,
            "buckets": sorted({pool["name"] for pool in pools}),
            "probeModes": sorted(requested_modes or DEFAULT_PROBES),
            "controlDomains": control["domains"] if control else [],
        },
        "entries": entries,
    }


def unique_domains(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        domain = value.lower().strip(".")
        if domain and domain not in seen:
            seen.add(domain)
            output.append(domain)
    return output


def site_for_domain(domain: str) -> str:
    labels = [label for label in domain.lower().strip(".").split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else "unknown"


def apply_schedule(
    entries: list[dict[str, Any]],
    args: argparse.Namespace,
    rng: random.Random,
) -> None:
    duration_ms = max(int(args.duration_seconds * 1000), 0)
    if not entries:
        return
    if duration_ms == 0:
        for index, entry in enumerate(entries):
            entry["scheduledOffsetMs"] = index * args.spacing_ms
        return
    burst_bases = {
        entry["groupId"]: rng.randrange(0, duration_ms + 1)
        for entry in entries
        if entry.get("behavior") == "burst"
    }
    for index, entry in enumerate(entries):
        behavior = entry.get("behavior")
        if behavior == "burst":
            base = burst_bases[str(entry["groupId"])]
            offset = base + rng.randrange(0, max(args.burst_window_ms, 1))
        elif behavior == "interval":
            offset = int(index * duration_ms / max(len(entries) - 1, 1))
        else:
            offset = rng.randrange(0, duration_ms + 1)
        if args.jitter_ms:
            offset += rng.randrange(-args.jitter_ms, args.jitter_ms + 1)
        entry["scheduledOffsetMs"] = max(0, min(duration_ms, offset))
    entries.sort(key=lambda item: (int(item["scheduledOffsetMs"]), item["id"]))
    for index, entry in enumerate(entries, start=1):
        entry["id"] = f"{index:04d}"


def default_port(probe: str) -> int | None:
    if probe == "dns":
        return None
    return 443


def privacy_model() -> dict[str, Any]:
    return {
        "blackBox": True,
        "dynetStateRead": False,
        "dynetApiCalled": False,
        "cookiesSent": False,
        "authorizationSent": False,
        "browserProfileUsed": False,
        "requestBodiesSent": False,
        "responseBodiesStored": False,
        "responseHeadersStored": False,
        "resolvedIpAddressesStored": False,
        "urlPathsFromSourceLogsStored": False,
        "scheduleContainsOnlyOffsets": True,
    }


def run_manifest(manifest: dict[str, Any], args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    started = utc_now()
    started_monotonic = time.perf_counter()
    results = []
    jsonl = output_dir / "results.jsonl"
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    with jsonl.open("w") as sink:
        for entry in manifest["entries"]:
            lag = sleep_until_entry(entry, args, started_monotonic)
            result = run_probe(entry, args.timeout_seconds, lag)
            results.append(result)
            sink.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
            sink.flush()
            if not args.respect_schedule and args.spacing_ms > 0:
                time.sleep(args.spacing_ms / 1000)
    summary = summarize_run(manifest, results, started, utc_now())
    write_json(output_dir / "summary.json", summary)
    write_report(output_dir / "report.md", summary)
    return summary


def sleep_until_entry(
    entry: dict[str, Any],
    args: argparse.Namespace,
    started_monotonic: float,
) -> int | None:
    if not args.respect_schedule:
        return None
    offset = int(entry.get("scheduledOffsetMs") or 0)
    due = started_monotonic + offset / 1000
    now = time.perf_counter()
    if due > now:
        time.sleep(due - now)
        return 0
    return int((now - due) * 1000)


def run_probe(entry: dict[str, Any], timeout_seconds: float, schedule_lag_ms: int | None) -> dict[str, Any]:
    started = utc_now()
    begin = time.perf_counter()
    stages: list[dict[str, Any]] = []
    policy = target_policy(entry)
    try:
        details = probe(entry, timeout_seconds, stages)
        ok = True
        error = None
        error_stage = None
        error_class = None
    except Exception as exc:  # noqa: BLE001 - black-box classification boundary
        details = {}
        ok = False
        failed_stage = first_failed_stage(stages)
        error = failed_stage.get("errorType") if failed_stage else classify_error(exc)
        error_stage = failed_stage.get("name") if failed_stage else "probe"
        error_class = type(exc).__name__
    elapsed = int((time.perf_counter() - begin) * 1000)
    result = {
        "id": entry["id"],
        "startedAt": started,
        "observer": observer_model(timeout_seconds),
        "bucket": entry["bucket"],
        "domain": entry["domain"],
        "behavior": entry.get("behavior", "single"),
        "groupId": entry.get("groupId"),
        "probe": entry["probe"],
        "port": entry.get("port"),
        "scheduledOffsetMs": entry.get("scheduledOffsetMs"),
        "scheduleLagMs": schedule_lag_ms,
        "ok": ok,
        "elapsedMs": elapsed,
        "stages": stages,
        "targetPolicy": policy,
        "errorType": error,
        "errorStage": error_stage,
        "errorClass": error_class,
        "attribution": result_attribution(entry, ok, elapsed, error, error_stage, policy),
    }
    result.update(details)
    return result


def probe(
    entry: dict[str, Any],
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    probe_name = entry["probe"]
    if probe_name == "dns":
        return probe_dns(entry["domain"], timeout_seconds, stages)
    if probe_name == "tcp-connect":
        return probe_tcp(entry["domain"], int(entry["port"]), timeout_seconds, stages)
    if probe_name == "tls-handshake":
        return probe_tls(entry["domain"], int(entry["port"]), timeout_seconds, stages)
    if probe_name == "https-head":
        return probe_https_head(entry["domain"], int(entry["port"]), timeout_seconds, stages)
    if probe_name == "https-get":
        return probe_https_get(entry["domain"], int(entry["port"]), timeout_seconds, stages)
    raise ValueError(f"unsupported probe mode: {probe_name}")


def probe_dns(domain: str, timeout_seconds: float, stages: list[dict[str, Any]]) -> dict[str, Any]:
    records = resolve_addresses(domain, 443, timeout_seconds, stages)
    return dns_details(records)


def probe_tcp(
    domain: str,
    port: int,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    sock, connect_details = connect_resolved(records, timeout_seconds, stages)
    sock.close()
    return {**dns_details(records), **connect_details}


def probe_tls(
    domain: str,
    port: int,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    sock, connect_details = connect_resolved(records, timeout_seconds, stages)
    tls = wrap_tls(sock, domain, timeout_seconds, stages)
    tls_version = tls.version()
    tls.close()
    return {**dns_details(records), **connect_details, "tlsVersion": tls_version}


def probe_https_head(
    domain: str,
    port: int,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    sock, connect_details = connect_resolved(records, timeout_seconds, stages)
    tls = wrap_tls(sock, domain, timeout_seconds, stages)
    tls_version = tls.version()
    try:
        http_details = perform_https_head(tls, domain, timeout_seconds, stages)
    finally:
        tls.close()
    return {**dns_details(records), **connect_details, "tlsVersion": tls_version, **http_details}


def probe_https_get(
    domain: str,
    port: int,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    sock, connect_details = connect_resolved(records, timeout_seconds, stages)
    tls = wrap_tls(sock, domain, timeout_seconds, stages)
    tls_version = tls.version()
    try:
        http_details = perform_https_get(tls, domain, timeout_seconds, stages)
    finally:
        tls.close()
    return {**dns_details(records), **connect_details, "tlsVersion": tls_version, **http_details}


def resolve_addresses(
    domain: str,
    port: int,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> list[Any]:
    begin = time.perf_counter()
    stage = {"name": "dns", "ok": False}
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_seconds)
    try:
        records = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
        if not records:
            raise socket.gaierror("empty DNS answer")
        stage["ok"] = True
        stage.update(dns_details(records))
        return records
    except Exception as exc:
        stage["errorType"] = classify_stage_error("dns", exc)
        stage["errorClass"] = type(exc).__name__
        raise
    finally:
        socket.setdefaulttimeout(original_timeout)
        stage["elapsedMs"] = elapsed_ms(begin)
        stages.append(stage)


def dns_details(records: list[Any]) -> dict[str, Any]:
    families = Counter(family_name(record[0]) for record in records)
    return {
        "dnsAnswers": len(records),
        "dnsFamilies": dict(sorted(families.items())),
    }


def family_name(family: socket.AddressFamily) -> str:
    if family == socket.AF_INET:
        return "ipv4"
    if family == socket.AF_INET6:
        return "ipv6"
    return "other"


def connect_resolved(
    records: list[Any],
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> tuple[socket.socket, dict[str, Any]]:
    begin = time.perf_counter()
    stage = {"name": "tcp-connect", "ok": False}
    attempts: list[dict[str, Any]] = []
    last_error: Exception | None = None
    try:
        for family, socktype, proto, _canonname, sockaddr in records:
            sock = socket.socket(family, socktype, proto)
            attempt = {
                "family": family_name(family),
                "ok": False,
            }
            try:
                sock.settimeout(timeout_seconds)
                sock.connect(sockaddr)
                attempt["ok"] = True
                attempts.append(attempt)
                details = connect_details(attempts, family_name(family))
                stage["ok"] = True
                stage.update(details)
                return sock, details
            except Exception as exc:  # noqa: BLE001 - classify and continue address candidates
                attempt["errorType"] = classify_stage_error("tcp-connect", exc)
                attempt["errorClass"] = type(exc).__name__
                attempts.append(attempt)
                last_error = exc
                sock.close()
        if last_error is not None:
            raise last_error
        raise ProbeSemanticError("no address candidates")
    except Exception as exc:
        stage["errorType"] = classify_stage_error("tcp-connect", exc)
        stage["errorClass"] = type(exc).__name__
        stage.update(connect_details(attempts, None))
        raise
    finally:
        stage["elapsedMs"] = elapsed_ms(begin)
        stages.append(stage)


def connect_details(attempts: list[dict[str, Any]], connected_family: str | None) -> dict[str, Any]:
    families = Counter(str(attempt["family"]) for attempt in attempts)
    failures = Counter(
        str(attempt.get("errorType"))
        for attempt in attempts
        if not attempt.get("ok") and attempt.get("errorType")
    )
    return {
        "connectAttempts": len(attempts),
        "connectFamilies": dict(sorted(families.items())),
        "connectFailures": dict(sorted(failures.items())),
        "connectedFamily": connected_family,
    }


def wrap_tls(
    sock: socket.socket,
    domain: str,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> ssl.SSLSocket:
    begin = time.perf_counter()
    stage = {"name": "tls-handshake", "ok": False}
    try:
        context = ssl.create_default_context()
        sock.settimeout(timeout_seconds)
        tls = context.wrap_socket(sock, server_hostname=domain)
        stage["ok"] = True
        stage["tlsVersion"] = tls.version()
        return tls
    except Exception as exc:
        stage["errorType"] = classify_stage_error("tls-handshake", exc)
        stage["errorClass"] = type(exc).__name__
        sock.close()
        raise
    finally:
        stage["elapsedMs"] = elapsed_ms(begin)
        stages.append(stage)


def perform_https_head(
    tls: ssl.SSLSocket,
    domain: str,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    begin = time.perf_counter()
    stage = {"name": "http-head", "ok": False}
    try:
        tls.settimeout(timeout_seconds)
        request = (
            f"HEAD {HTTP_REQUEST_TARGET} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n"
        ).encode("ascii")
        tls.sendall(request)
        status_code = read_status_code(tls)
        stage["ok"] = True
        stage["statusClass"] = f"{status_code // 100}xx"
        return {
            "statusCode": status_code,
            "statusClass": f"{status_code // 100}xx",
        }
    except Exception as exc:
        stage["errorType"] = classify_stage_error("http-head", exc)
        stage["errorClass"] = type(exc).__name__
        raise
    finally:
        stage["elapsedMs"] = elapsed_ms(begin)
        stages.append(stage)


def perform_https_get(
    tls: ssl.SSLSocket,
    domain: str,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
) -> dict[str, Any]:
    begin = time.perf_counter()
    stage = {"name": "http-get", "ok": False}
    try:
        tls.settimeout(timeout_seconds)
        request = (
            f"GET {HTTP_REQUEST_TARGET} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: text/html,*/*;q=0.8\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n"
        ).encode("ascii")
        tls.sendall(request)
        status_code, bytes_read = read_http_response(tls, HTTP_GET_READ_LIMIT)
        stage["ok"] = True
        stage["statusClass"] = f"{status_code // 100}xx"
        stage["bytesRead"] = bytes_read
        return {
            "statusCode": status_code,
            "statusClass": f"{status_code // 100}xx",
            "responseBytesRead": bytes_read,
            "responseBodyStored": False,
        }
    except Exception as exc:
        stage["errorType"] = classify_stage_error("http-get", exc)
        stage["errorClass"] = type(exc).__name__
        raise
    finally:
        stage["elapsedMs"] = elapsed_ms(begin)
        stages.append(stage)


def read_status_code(tls: ssl.SSLSocket) -> int:
    data = b""
    while b"\r\n" not in data and len(data) < 4096:
        chunk = tls.recv(4096)
        if not chunk:
            break
        data += chunk
    line = data.split(b"\r\n", 1)[0]
    parts = line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeSemanticError("invalid HTTP status line")
    return int(parts[1])


def read_http_response(tls: ssl.SSLSocket, read_limit: int) -> tuple[int, int]:
    data = b""
    while len(data) < read_limit:
        chunk = tls.recv(min(4096, read_limit - len(data)))
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data and len(data) >= read_limit:
            break
    line = data.split(b"\r\n", 1)[0]
    parts = line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeSemanticError("invalid HTTP status line")
    return int(parts[1]), len(data)


def elapsed_ms(begin: float) -> int:
    return int((time.perf_counter() - begin) * 1000)


def first_failed_stage(stages: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((stage for stage in reversed(stages) if not stage.get("ok")), None)


def observer_model(timeout_seconds: float) -> dict[str, Any]:
    return {
        "name": OBSERVER_VERSION,
        "errorTaxonomy": ERROR_TAXONOMY_VERSION,
        "targetPolicy": TARGET_POLICY_VERSION,
        "timeoutPerStageMs": int(timeout_seconds * 1000),
        "identitySurface": "zero-identity",
        "httpRequestTarget": HTTP_REQUEST_TARGET,
    }


def target_policy(entry: dict[str, Any]) -> dict[str, Any]:
    domain = str(entry["domain"]).lower()
    bucket = str(entry["bucket"])
    probe_name = str(entry["probe"])
    tags = []
    reasons = []
    confidence_weight = 1.0
    fault_signal = "normal"
    if bucket == "platform-background":
        tags.append("platform-background")
        confidence_weight = 0.5
        fault_signal = "weak"
        reasons.append("background platform endpoints are not user-intent traffic")
    if domain.endswith(".push.apple.com") or ".courier.push.apple.com" in domain:
        tags.extend(["platform-push", "apple-push"])
        confidence_weight = 0.0
        fault_signal = "informational"
        reasons.append("Apple push/courier endpoints may reject generic black-box TLS/HTTP probes")
    elif bucket == "platform-background" and probe_name in {"tls-handshake", "https-head", "https-get"}:
        tags.append("platform-service-probe")
        confidence_weight = min(confidence_weight, 0.25)
        fault_signal = "weak"
        reasons.append("generic TLS/HTTP probes against platform services are weak fault signals")
    return {
        "version": TARGET_POLICY_VERSION,
        "faultSignal": fault_signal,
        "confidenceWeight": confidence_weight,
        "lowConfidence": confidence_weight < 0.5,
        "tags": sorted(set(tags)),
        "reasons": reasons,
    }


def result_attribution(
    entry: dict[str, Any],
    ok: bool,
    elapsed_ms_value: int,
    error: str | None,
    error_stage: str | None,
    policy: dict[str, Any],
) -> dict[str, Any]:
    needs_trace = list(ATTRIBUTION_TRACE_FIELDS)
    if ok:
        outcome = "healthy"
    elif policy["faultSignal"] == "informational":
        outcome = "target-or-probe-semantics"
    elif policy["faultSignal"] == "weak":
        outcome = "weak-blackbox-failure"
    else:
        outcome = "path-or-target-failure"
    return {
        "blackboxOnly": True,
        "canAttributePlanVsNode": False,
        "outcome": outcome,
        "faultSignal": policy["faultSignal"],
        "requiresDynetTraceFields": needs_trace,
        "probeKey": f"{entry['bucket']}:{entry['probe']}",
        "elapsedMs": elapsed_ms_value,
        "errorType": error,
        "errorStage": error_stage,
    }


def classify_stage_error(stage: str, exc: Exception) -> str:
    base = classify_error(exc)
    if stage == "dns":
        if base == "timeout":
            return "dns.timeout"
        return f"dns.{base}"
    if stage == "tcp-connect":
        if base == "timeout":
            return "connect.timeout"
        if base in {"refused", "reset", "network-unreachable"}:
            return f"connect.{base}"
        return f"connect.{base}"
    if stage == "tls-handshake":
        if base == "timeout":
            return "tls.timeout"
        if base == "certificate":
            return "tls.certificate"
        if base in {"reset", "network-unreachable"}:
            return f"tls.{base}"
        return f"tls.{base}"
    if stage in {"http-head", "http-get"}:
        if base == "timeout":
            return "http.timeout"
        if base in {"reset", "refused", "network-unreachable"}:
            return f"http.{base}"
        return f"http.{base}"
    return base


def classify_error(exc: Exception) -> str:
    text = f"{type(exc).__name__}: {exc}".lower()
    if isinstance(exc, socket.gaierror) or "name or service not known" in text:
        return "dns"
    if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
        return "timeout"
    if isinstance(exc, ssl.SSLEOFError) or "eof" in text:
        return "eof"
    if "alert" in text:
        return "alert"
    if isinstance(exc, ssl.SSLCertVerificationError) or "certificate" in text:
        return "certificate"
    if isinstance(exc, ssl.SSLError) or "ssl" in text:
        return "tls"
    if "refused" in text:
        return "refused"
    if "reset" in text:
        return "reset"
    if "network is unreachable" in text:
        return "network-unreachable"
    return "other"


def summarize_run(
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    started: str,
    ended: str,
) -> dict[str, Any]:
    observer = results[0]["observer"] if results else observer_model(0)
    return {
        "schema": RUN_SCHEMA,
        "startedAt": started,
        "endedAt": ended,
        "environment": manifest["environment"],
        "seed": manifest["seed"],
        "manifestSchema": manifest["schema"],
        "observer": observer,
        "workload": manifest.get("workload", {}),
        "privacy": privacy_model(),
        "totals": aggregate(results),
        "byBucket": aggregate_groups(results, "bucket"),
        "byBehavior": aggregate_groups(results, "behavior"),
        "byProbe": aggregate_groups(results, "probe"),
        "byStage": aggregate_stage_groups(results),
        "byFaultSignal": aggregate_fault_signal_groups(results),
        "byDomain": aggregate_groups(results, "domain"),
        "schedule": schedule_summary(results),
        "errors": top(Counter(row["errorType"] for row in results if row["errorType"])),
        "failureClusters": failure_clusters(results),
        "latencyHotspots": latency_hotspots(results),
        "slowSamples": slow_samples(results),
        "attribution": run_attribution(results),
    }


def aggregate_groups(results: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        grouped[str(row[field])].append(row)
    return [
        {"key": key, **aggregate(rows)}
        for key, rows in sorted(grouped.items(), key=lambda item: item[0])
    ]


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    successes = sum(1 for row in rows if row["ok"])
    failures = total - successes
    latencies = [row["elapsedMs"] for row in rows]
    output = {
        "count": total,
        "success": successes,
        "failure": failures,
        "successRate": round(successes / total, 4) if total else 0,
        "latencyMs": {
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "max": max(latencies) if latencies else None,
        },
    }
    errors = top(Counter(str(row["errorType"]) for row in rows if row.get("errorType")))
    if errors:
        output["errors"] = errors
    return output


def aggregate_stage_groups(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        for stage in row.get("stages", []):
            grouped[str(stage["name"])].append(stage)
    return [{"key": key, **aggregate(rows)} for key, rows in sorted(grouped.items())]


def aggregate_fault_signal_groups(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        key = row.get("targetPolicy", {}).get("faultSignal", "unknown")
        grouped[str(key)].append(row)
    return [{"key": key, **aggregate(rows)} for key, rows in sorted(grouped.items())]


def schedule_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    lags = [
        int(row["scheduleLagMs"])
        for row in results
        if isinstance(row.get("scheduleLagMs"), int)
    ]
    offsets = [
        int(row["scheduledOffsetMs"])
        for row in results
        if isinstance(row.get("scheduledOffsetMs"), int)
    ]
    return {
        "scheduled": bool(offsets),
        "lagMs": {
            "p50": percentile(lags, 50),
            "p95": percentile(lags, 95),
            "max": max(lags) if lags else None,
        },
        "offsetMs": {
            "first": min(offsets) if offsets else None,
            "last": max(offsets) if offsets else None,
        },
    }


def failure_clusters(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        if row.get("ok"):
            continue
        policy = row.get("targetPolicy", {})
        key = (
            str(row.get("bucket")),
            str(row.get("behavior")),
            str(row.get("domain")),
            str(row.get("probe")),
            str(row.get("errorStage")),
            str(row.get("errorType")),
            str(policy.get("faultSignal", "unknown")),
        )
        grouped[key].append(row)
    output = []
    for (
        bucket,
        behavior,
        domain,
        probe,
        error_stage,
        error_type,
        fault_signal,
    ), rows in sorted(grouped.items()):
        tags = sorted(
            {
                tag
                for row in rows
                for tag in row.get("targetPolicy", {}).get("tags", [])
                if isinstance(tag, str)
            }
        )
        output.append(
            {
                "bucket": bucket,
                "behavior": behavior,
                "domain": domain,
                "probe": probe,
                "errorStage": error_stage,
                "errorType": error_type,
                "faultSignal": fault_signal,
                "count": len(rows),
                "targetTags": tags,
                "canAttributePlanVsNode": False,
            }
        )
    return output


def latency_hotspots(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    rows.extend(hotspots_for_groups("bucket", aggregate_groups(results, "bucket")))
    rows.extend(hotspots_for_groups("behavior", aggregate_groups(results, "behavior")))
    rows.extend(hotspots_for_groups("probe", aggregate_groups(results, "probe")))
    rows.extend(hotspots_for_groups("stage", aggregate_stage_groups(results)))
    return rows


def slow_samples(results: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    ordered = sorted(results, key=lambda row: int(row.get("elapsedMs", 0)), reverse=True)
    output = []
    for row in ordered[:limit]:
        output.append(
            {
                "id": row["id"],
                "bucket": row["bucket"],
                "behavior": row.get("behavior"),
                "groupId": row.get("groupId"),
                "domain": row["domain"],
                "probe": row["probe"],
                "scheduledOffsetMs": row.get("scheduledOffsetMs"),
                "scheduleLagMs": row.get("scheduleLagMs"),
                "ok": row["ok"],
                "elapsedMs": row["elapsedMs"],
                "faultSignal": row.get("targetPolicy", {}).get("faultSignal", "unknown"),
                "stageLatencyMs": {
                    stage["name"]: stage.get("elapsedMs")
                    for stage in row.get("stages", [])
                    if isinstance(stage, dict)
                },
                "errorStage": row.get("errorStage"),
                "errorType": row.get("errorType"),
                "canAttributePlanVsNode": False,
            }
        )
    return output


def hotspots_for_groups(kind: str, groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for item in groups:
        p95 = item.get("latencyMs", {}).get("p95")
        if p95 is None:
            continue
        threshold = latency_threshold(kind, str(item["key"]))
        if p95 >= threshold:
            output.append(
                {
                    "kind": kind,
                    "key": item["key"],
                    "p95Ms": p95,
                    "thresholdMs": threshold,
                    "count": item["count"],
                    "successRate": item["successRate"],
                }
            )
    return output


def latency_threshold(kind: str, key: str) -> int:
    if kind == "stage" and key == "dns":
        return 200
    if kind == "stage" and key == "tcp-connect":
        return 500
    if kind == "stage" and key == "tls-handshake":
        return 1000
    if kind == "stage" and key in {"http-head", "http-get"}:
        return 1500
    if kind == "probe" and key in {"dns", "tcp-connect"}:
        return 500
    return 1500


def run_attribution(results: list[dict[str, Any]]) -> dict[str, Any]:
    failures = [row for row in results if not row.get("ok")]
    normal_failures = [
        row for row in failures if row.get("targetPolicy", {}).get("faultSignal") == "normal"
    ]
    weak_failures = [
        row for row in failures if row.get("targetPolicy", {}).get("faultSignal") == "weak"
    ]
    informational_failures = [
        row for row in failures if row.get("targetPolicy", {}).get("faultSignal") == "informational"
    ]
    if normal_failures:
        signal = "actionable-blackbox-failures"
    elif weak_failures:
        signal = "weak-blackbox-failures"
    elif informational_failures:
        signal = "informational-failures-only"
    else:
        signal = "no-failures"
    return {
        "blackboxOnlyCanAttributePlanVsNode": False,
        "failureSignal": signal,
        "failureCounts": {
            "normal": len(normal_failures),
            "weak": len(weak_failures),
            "informational": len(informational_failures),
        },
        "requiresDynetTraceFields": list(ATTRIBUTION_TRACE_FIELDS),
        "canBlamePlan": False,
        "canBlameNode": False,
        "reason": "black-box outcomes do not expose selected outbound, candidate set, cascade attempts, or gate verdicts",
    }


def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]


def top(counter: Counter[str], limit: int = 20) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]


def write_report(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Real Access Blackbox Report",
        "",
        f"- Environment: `{summary['environment']}`",
        f"- Seed: `{summary['seed']}`",
        f"- Started: `{summary['startedAt']}`",
        f"- Ended: `{summary['endedAt']}`",
        f"- Success rate: `{summary['totals']['successRate']}`",
        f"- Count: `{summary['totals']['count']}`",
        f"- Observer: `{summary['observer']['name']}`",
        f"- Attribution: `{summary['attribution']['failureSignal']}`",
        f"- Workload duration: `{summary['workload'].get('durationSeconds', 0)}` seconds",
        f"- Schedule lag p95: `{summary['schedule']['lagMs']['p95']}` ms",
        "",
        "## Privacy",
        "",
        "- No dynet state/API/events were read.",
        "- No cookies, Authorization headers, browser profiles, or request bodies were used.",
        "- Response bodies, response headers, and resolved IP addresses were not stored.",
        "",
        "## By Bucket",
        "",
    ]
    for item in summary["byBucket"]:
        lines.append(
            f"- `{item['key']}`: success={item['success']}/{item['count']} "
            f"rate={item['successRate']} p95={item['latencyMs']['p95']}ms"
        )
    lines.extend(["", "## By Behavior", ""])
    for item in summary["byBehavior"]:
        lines.append(
            f"- `{item['key']}`: success={item['success']}/{item['count']} "
            f"rate={item['successRate']} p95={item['latencyMs']['p95']}ms"
        )
    lines.extend(["", "## By Probe", ""])
    for item in summary["byProbe"]:
        lines.append(
            f"- `{item['key']}`: success={item['success']}/{item['count']} "
            f"rate={item['successRate']} p95={item['latencyMs']['p95']}ms"
        )
    lines.extend(["", "## By Stage", ""])
    for item in summary["byStage"]:
        lines.append(
            f"- `{item['key']}`: success={item['success']}/{item['count']} "
            f"rate={item['successRate']} p95={item['latencyMs']['p95']}ms"
        )
    lines.extend(["", "## Fault Signals", ""])
    for item in summary["byFaultSignal"]:
        lines.append(
            f"- `{item['key']}`: success={item['success']}/{item['count']} "
            f"rate={item['successRate']} p95={item['latencyMs']['p95']}ms"
        )
    if summary["errors"]:
        lines.extend(["", "## Errors", ""])
        for item in summary["errors"]:
            lines.append(f"- `{item['key']}`: {item['count']}")
    if summary["failureClusters"]:
        lines.extend(["", "## Failure Clusters", ""])
        for item in summary["failureClusters"]:
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` "
                f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
                f"signal=`{item['faultSignal']}` count={item['count']}"
            )
    if summary["latencyHotspots"]:
        lines.extend(["", "## Latency Hotspots", ""])
        for item in summary["latencyHotspots"]:
            lines.append(
                f"- {item['kind']} `{item['key']}` p95={item['p95Ms']}ms "
                f"threshold={item['thresholdMs']}ms count={item['count']}"
            )
    if summary["slowSamples"]:
        lines.extend(["", "## Slow Samples", ""])
        for item in summary["slowSamples"][:10]:
            stages = ", ".join(
                f"{name}={value}ms" for name, value in item["stageLatencyMs"].items()
            )
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` lag={item['scheduleLagMs']}ms "
                f"elapsed={item['elapsedMs']}ms signal=`{item['faultSignal']}` stages: {stages}"
            )
    lines.extend(
        [
            "",
            "## Attribution Boundary",
            "",
            "- Black-box output cannot attribute plan-vs-node by itself.",
            "- Needed dynet trace fields: "
            + ", ".join(f"`{field}`" for field in summary["attribution"]["requiresDynetTraceFields"]),
        ]
    )
    path.write_text("\n".join(lines) + "\n")


def load_summary_spec(spec: str) -> dict[str, Any]:
    if "=" in spec:
        label, path_text = spec.split("=", 1)
    else:
        path_text = spec
        label = ""
    path = Path(path_text)
    summary = load_json(path)
    return {
        "label": label or summary.get("environment") or path.parent.name,
        "path": str(path),
        "summary": summary,
    }


def build_comparison(specs: list[str]) -> dict[str, Any]:
    runs = [load_summary_spec(spec) for spec in specs]
    if not runs:
        raise SystemExit("compare requires at least one run summary")
    baseline = runs[0]["summary"]["totals"]
    stable_failures = stable_failure_clusters(runs)
    changed_failures = changed_failure_clusters(runs)
    return {
        "schema": COMPARE_SCHEMA,
        "generatedAt": utc_now(),
        "privacy": privacy_model(),
        "baseline": runs[0]["label"],
        "runs": [compare_run(run, baseline) for run in runs],
        "byBucket": compare_group(runs, "byBucket"),
        "byBehavior": compare_group(runs, "byBehavior"),
        "byProbe": compare_group(runs, "byProbe"),
        "byStage": compare_group(runs, "byStage"),
        "byFaultSignal": compare_group(runs, "byFaultSignal"),
        "stableFailures": stable_failures,
        "changedFailures": changed_failures,
        "attribution": comparison_attribution(runs, stable_failures, changed_failures),
    }


def compare_run(run: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    summary = run["summary"]
    totals = summary["totals"]
    return {
        "label": run["label"],
        "path": run["path"],
        "environment": summary.get("environment"),
        "seed": summary.get("seed"),
        "count": totals["count"],
        "successRate": totals["successRate"],
        "successRateDelta": round(totals["successRate"] - baseline["successRate"], 4),
        "p50Ms": totals["latencyMs"]["p50"],
        "p95Ms": totals["latencyMs"]["p95"],
        "p95DeltaMs": delta(totals["latencyMs"]["p95"], baseline["latencyMs"]["p95"]),
        "errors": summary.get("errors", []),
    }


def compare_group(runs: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    group_keys = sorted(
        {
            item["key"]
            for run in runs
            for item in run["summary"].get(key, [])
        }
    )
    output = []
    for group_key in group_keys:
        row = {"key": group_key, "runs": []}
        baseline = group_item(runs[0]["summary"], key, group_key)
        for run in runs:
            item = group_item(run["summary"], key, group_key)
            if item is None:
                row["runs"].append({"label": run["label"], "count": 0})
                continue
            row["runs"].append(
                {
                    "label": run["label"],
                    "count": item["count"],
                    "successRate": item["successRate"],
                    "successRateDelta": group_delta(item, baseline, "successRate"),
                    "p95Ms": item["latencyMs"]["p95"],
                    "p95DeltaMs": group_latency_delta(item, baseline),
                }
            )
        output.append(row)
    return output


def stable_failure_clusters(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not runs:
        return []
    cluster_maps = [cluster_map(run) for run in runs]
    common_keys = set(cluster_maps[0])
    for mapping in cluster_maps[1:]:
        common_keys &= set(mapping)
    return [
        merge_cluster(key, cluster_maps, runs)
        for key in sorted(common_keys)
    ]


def changed_failure_clusters(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cluster_maps = [cluster_map(run) for run in runs]
    all_keys = sorted({key for mapping in cluster_maps for key in mapping})
    changed = []
    for key in all_keys:
        labels = [runs[index]["label"] for index, mapping in enumerate(cluster_maps) if key in mapping]
        if len(labels) == len(runs):
            continue
        item = merge_cluster(key, cluster_maps, runs)
        item["presentIn"] = labels
        changed.append(item)
    return changed


def cluster_map(run: dict[str, Any]) -> dict[tuple[str, str, str, str, str, str, str], dict[str, Any]]:
    return {cluster_key(item): item for item in run["summary"].get("failureClusters", [])}


def cluster_key(item: dict[str, Any]) -> tuple[str, str, str, str, str, str, str]:
    return (
        str(item.get("bucket")),
        str(item.get("behavior")),
        str(item.get("domain")),
        str(item.get("probe")),
        str(item.get("errorStage")),
        str(item.get("errorType")),
        str(item.get("faultSignal")),
    )


def merge_cluster(
    key: tuple[str, str, str, str, str, str, str],
    cluster_maps: list[dict[tuple[str, str, str, str, str, str, str], dict[str, Any]]],
    runs: list[dict[str, Any]],
) -> dict[str, Any]:
    bucket, behavior, domain, probe, error_stage, error_type, fault_signal = key
    counts = []
    tags = set()
    for index, mapping in enumerate(cluster_maps):
        item = mapping.get(key)
        count = int(item.get("count", 0)) if item else 0
        counts.append({"label": runs[index]["label"], "count": count})
        if item:
            tags.update(str(tag) for tag in item.get("targetTags", []))
    return {
        "bucket": bucket,
        "behavior": behavior,
        "domain": domain,
        "probe": probe,
        "errorStage": error_stage,
        "errorType": error_type,
        "faultSignal": fault_signal,
        "targetTags": sorted(tags),
        "runs": counts,
        "canAttributePlanVsNode": False,
    }


def comparison_attribution(
    runs: list[dict[str, Any]],
    stable_failures: list[dict[str, Any]],
    changed_failures: list[dict[str, Any]],
) -> dict[str, Any]:
    signals = Counter(
        run["summary"].get("attribution", {}).get("failureSignal", "unknown")
        for run in runs
    )
    stable_normal = [
        item for item in stable_failures if item.get("faultSignal") == "normal"
    ]
    stable_informational = [
        item for item in stable_failures if item.get("faultSignal") == "informational"
    ]
    if stable_normal:
        conclusion = "stable-actionable-failures-need-dynet-trace"
    elif changed_failures:
        conclusion = "unstable-blackbox-failures-need-repeat-or-dynet-trace"
    elif stable_informational:
        conclusion = "stable-informational-failures-only"
    else:
        conclusion = "no-stable-failures"
    return {
        "blackboxOnlyCanAttributePlanVsNode": False,
        "conclusion": conclusion,
        "runFailureSignals": top(signals),
        "requiresDynetTraceFields": list(ATTRIBUTION_TRACE_FIELDS),
        "reason": "comparison still lacks selected outbound, candidate quality, and cascade attempt evidence",
    }


def group_item(summary: dict[str, Any], group_name: str, key: str) -> dict[str, Any] | None:
    return next((item for item in summary.get(group_name, []) if item["key"] == key), None)


def group_delta(item: dict[str, Any], baseline: dict[str, Any] | None, field: str) -> float | None:
    if baseline is None:
        return None
    return round(item[field] - baseline[field], 4)


def group_latency_delta(item: dict[str, Any], baseline: dict[str, Any] | None) -> int | None:
    if baseline is None:
        return None
    return delta(item["latencyMs"]["p95"], baseline["latencyMs"]["p95"])


def delta(value: int | None, baseline: int | None) -> int | None:
    if value is None or baseline is None:
        return None
    return value - baseline


def write_comparison_report(path: Path, comparison: dict[str, Any]) -> None:
    lines = [
        "# Real Access Blackbox Comparison",
        "",
        f"- Baseline: `{comparison['baseline']}`",
        "",
        "## Runs",
        "",
    ]
    for run in comparison["runs"]:
        lines.append(
            f"- `{run['label']}` env=`{run['environment']}` count={run['count']} "
            f"success={run['successRate']} delta={run['successRateDelta']} "
            f"p95={run['p95Ms']}ms delta={run['p95DeltaMs']}ms"
        )
    lines.extend(["", "## Buckets", ""])
    for bucket in comparison["byBucket"]:
        pieces = []
        for run in bucket["runs"]:
            if run["count"] == 0:
                pieces.append(f"{run['label']}:none")
            else:
                pieces.append(
                    f"{run['label']}:n={run['count']} sr={run['successRate']} "
                    f"p95={run['p95Ms']}ms"
                )
        lines.append(f"- `{bucket['key']}`: " + "; ".join(pieces))
    lines.extend(["", "## Behaviors", ""])
    for behavior in comparison["byBehavior"]:
        pieces = []
        for run in behavior["runs"]:
            if run["count"] == 0:
                pieces.append(f"{run['label']}:none")
            else:
                pieces.append(
                    f"{run['label']}:n={run['count']} sr={run['successRate']} "
                    f"p95={run['p95Ms']}ms"
                )
        lines.append(f"- `{behavior['key']}`: " + "; ".join(pieces))
    lines.extend(["", "## Probes", ""])
    for probe in comparison["byProbe"]:
        pieces = []
        for run in probe["runs"]:
            if run["count"] == 0:
                pieces.append(f"{run['label']}:none")
            else:
                pieces.append(
                    f"{run['label']}:n={run['count']} sr={run['successRate']} "
                    f"p95={run['p95Ms']}ms"
                )
        lines.append(f"- `{probe['key']}`: " + "; ".join(pieces))
    lines.extend(["", "## Stages", ""])
    for stage in comparison["byStage"]:
        pieces = []
        for run in stage["runs"]:
            if run["count"] == 0:
                pieces.append(f"{run['label']}:none")
            else:
                pieces.append(
                    f"{run['label']}:n={run['count']} sr={run['successRate']} "
                    f"p95={run['p95Ms']}ms"
                )
        lines.append(f"- `{stage['key']}`: " + "; ".join(pieces))
    lines.extend(["", "## Fault Signals", ""])
    for signal in comparison["byFaultSignal"]:
        pieces = []
        for run in signal["runs"]:
            if run["count"] == 0:
                pieces.append(f"{run['label']}:none")
            else:
                pieces.append(
                    f"{run['label']}:n={run['count']} sr={run['successRate']} "
                    f"p95={run['p95Ms']}ms"
                )
        lines.append(f"- `{signal['key']}`: " + "; ".join(pieces))
    if comparison["stableFailures"]:
        lines.extend(["", "## Stable Failures", ""])
        for item in comparison["stableFailures"]:
            counts = ", ".join(f"{run['label']}={run['count']}" for run in item["runs"])
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` "
                f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
                f"signal=`{item['faultSignal']}` counts={counts}"
            )
    if comparison["changedFailures"]:
        lines.extend(["", "## Changed Failures", ""])
        for item in comparison["changedFailures"]:
            present = ", ".join(item.get("presentIn", []))
            lines.append(
                f"- `{item['domain']}` bucket=`{item['bucket']}` behavior=`{item['behavior']}` "
                f"probe=`{item['probe']}` "
                f"stage=`{item['errorStage']}` error=`{item['errorType']}` "
                f"presentIn={present}"
            )
    lines.extend(
        [
            "",
            "## Attribution",
            "",
            f"- Conclusion: `{comparison['attribution']['conclusion']}`",
            "- Black-box comparison still cannot attribute plan-vs-node without dynet trace fields.",
        ]
    )
    path.write_text("\n".join(lines) + "\n")


def run_output_dir(root: Path, environment: str, seed: str, label: str | None) -> Path:
    safe_env = safe_name(environment)
    safe_seed = safe_name(seed)[:24]
    suffix = safe_name(label) if label else dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / f"{suffix}-{safe_env}-{safe_seed}"


def safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "-" for char in value)
    return cleaned.strip(".-_") or "run"


def command_plan(args: argparse.Namespace) -> int:
    manifest = build_manifest(args)
    output = Path(args.output)
    write_json(output, manifest)
    print(json.dumps({"manifest": str(output), "count": len(manifest["entries"])}))
    return 0


def command_run(args: argparse.Namespace) -> int:
    output_dir = run_output_dir(
        Path(args.output_root),
        args.environment,
        args.seed,
        args.label,
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    if args.manifest:
        manifest = load_json(Path(args.manifest))
    else:
        manifest = build_manifest(args)
    manifest["environment"] = args.environment
    write_json(output_dir / "manifest.json", manifest)
    summary = run_manifest(manifest, args, output_dir)
    print(
        json.dumps(
            {
                "outputDir": str(output_dir),
                "count": summary["totals"]["count"],
                "successRate": summary["totals"]["successRate"],
            },
            sort_keys=True,
        )
    )
    return 0


def command_compare(args: argparse.Namespace) -> int:
    comparison = build_comparison(args.run)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    write_json(output_json, comparison)
    write_comparison_report(output_md, comparison)
    print(
        json.dumps(
            {
                "outputJson": str(output_json),
                "outputMd": str(output_md),
                "runs": len(comparison["runs"]),
            },
            sort_keys=True,
        )
    )
    return 0


def add_sampling_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--environment", default=DEFAULT_ENVIRONMENT)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--count", type=int, default=24)
    parser.add_argument("--buckets")
    parser.add_argument("--probe-modes")
    parser.add_argument("--behaviors")
    parser.add_argument("--duration-seconds", type=float, default=0)
    parser.add_argument("--spacing-ms", type=int, default=250)
    parser.add_argument("--jitter-ms", type=int, default=250)
    parser.add_argument("--burst-groups", type=int, default=4)
    parser.add_argument("--burst-window-ms", type=int, default=1000)
    parser.add_argument("--control-domain", action="append")
    parser.add_argument("--control-weight", type=int, default=8)
    parser.add_argument("--no-default-controls", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=5)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run zero-identity black-box real-access baseline probes."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="write a replay manifest")
    add_sampling_args(plan_parser)
    plan_parser.add_argument("--output", required=True)
    plan_parser.set_defaults(handler=command_plan)

    run_parser = subparsers.add_parser("run", help="run a replay manifest or sampled plan")
    add_sampling_args(run_parser)
    run_parser.add_argument("--manifest")
    run_parser.add_argument("--output-root", default=DEFAULT_RUN_ROOT)
    run_parser.add_argument("--label")
    run_parser.add_argument(
        "--no-respect-schedule",
        action="store_false",
        dest="respect_schedule",
        help="ignore manifest scheduled offsets and use --spacing-ms between entries",
    )
    run_parser.set_defaults(respect_schedule=True)
    run_parser.set_defaults(handler=command_run)

    compare_parser = subparsers.add_parser("compare", help="compare run summaries")
    compare_parser.add_argument(
        "--run",
        action="append",
        required=True,
        help="summary path or label=summary path; pass once per run",
    )
    compare_parser.add_argument("--output-json", required=True)
    compare_parser.add_argument("--output-md", required=True)
    compare_parser.set_defaults(handler=command_compare)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
