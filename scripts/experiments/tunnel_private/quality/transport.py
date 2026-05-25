from __future__ import annotations

import argparse
import http.client
import json
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from real_access.controller import auth_headers, http_request, read_http_body
from tunnel_private_config import ConfigInputs, load_yaml, metadata, safe_proxy, write_json
from tunnel_private.quality.mihomo_proxy import (
    classify_curl_result,
    mihomo_delay_row,
    mihomo_proxy_row,
)
from tunnel_private.quality.tls_probe import (
    classify_go_tls_error,
    classify_go_tls_payload,
    classify_transport_error,
    classify_utls_error,
    classify_utls_payload,
    go_tls_payload,
    trojan_tls_handshake,
    utls_fingerprint_rows,
    utls_fingerprints,
    utls_payload,
    utls_winner,
)


TRANSPORT_SCHEMA = "dynet-tunnel-private-transport-check/v1alpha1"
DEFAULT_CLASH_UNIX_SOCKET = "/tmp/verge/verge-mihomo.sock"


def command_transport_check(
    args: argparse.Namespace,
    *,
    inputs: ConfigInputs,
) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        check_candidate(args, proxy, f"tunnel-{index:03d}")
        for index, proxy in enumerate(inputs.candidates, start=1)
    ]
    summary = transport_summary(args, inputs, rows)
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    print(json.dumps(print_summary(output_dir, summary), sort_keys=True))
    return 0 if rows else 1


def check_candidate(
    args: argparse.Namespace,
    proxy: dict[str, Any],
    tag: str,
) -> dict[str, Any]:
    if args.check == "clash-delay":
        return check_clash_delay(args, proxy, tag)
    if args.check == "go-tls":
        return check_go_tls(args, proxy, tag)
    if args.check == "utls":
        return check_utls(args, proxy, tag)
    if args.check == "mihomo-delay":
        return mihomo_delay_row(args, proxy, tag)
    if args.check == "mihomo-proxy":
        return mihomo_proxy_row(args, proxy, tag)
    if args.check != "trojan-tls":
        return row(tag, proxy, "unsupported-check", 0)
    if str(proxy.get("type", "")).lower() != "trojan":
        return row(tag, proxy, "unsupported-type", 0)
    started = time.monotonic()
    try:
        version = trojan_tls_handshake(proxy, float(args.timeout_seconds))
        result = row(tag, proxy, "tls-handshake-pass", elapsed_ms(started))
        result["tlsVersion"] = version
        return result
    except Exception as error:
        return row(tag, proxy, classify_transport_error(error), elapsed_ms(started))


def check_clash_delay(
    args: argparse.Namespace,
    proxy: dict[str, Any],
    tag: str,
) -> dict[str, Any]:
    if str(proxy.get("type", "")).lower() != "trojan":
        return row(tag, proxy, "unsupported-type", 0)
    if not proxy.get("name"):
        return row(tag, proxy, "missing-proxy-name", 0)
    started = time.monotonic()
    try:
        payload = clash_delay_payload(args, str(proxy["name"]))
        result = row(tag, proxy, classify_clash_delay_payload(payload), elapsed_ms(started))
        if isinstance(payload.get("delay"), int):
            result["delayMs"] = int(payload["delay"])
        return result
    except Exception as error:
        return row(tag, proxy, classify_controller_error(error), elapsed_ms(started))


def check_go_tls(
    args: argparse.Namespace,
    proxy: dict[str, Any],
    tag: str,
) -> dict[str, Any]:
    if str(proxy.get("type", "")).lower() != "trojan":
        return row(tag, proxy, "unsupported-type", 0)
    started = time.monotonic()
    try:
        payload = go_tls_payload(proxy, float(args.timeout_seconds))
        result = row(tag, proxy, classify_go_tls_payload(payload), elapsed_ms(started))
        if payload.get("version"):
            result["tlsVersion"] = str(payload["version"])
        return result
    except Exception as error:
        return row(tag, proxy, classify_go_tls_error(error), elapsed_ms(started))


def check_utls(
    args: argparse.Namespace,
    proxy: dict[str, Any],
    tag: str,
) -> dict[str, Any]:
    if str(proxy.get("type", "")).lower() != "trojan":
        return row(tag, proxy, "unsupported-type", 0)
    started = time.monotonic()
    try:
        payload = utls_payload(proxy, float(args.timeout_seconds), utls_fingerprints(args))
        result = row(tag, proxy, classify_utls_payload(payload), elapsed_ms(started))
        result["fingerprints"] = utls_fingerprint_rows(payload)
        if winner := utls_winner(payload):
            result["matchedFingerprint"] = winner["fingerprint"]
            result["tlsVersion"] = winner.get("version")
        return result
    except Exception as error:
        return row(tag, proxy, classify_utls_error(error), elapsed_ms(started))


def clash_delay_payload(args: argparse.Namespace, proxy_name: str) -> dict[str, Any]:
    endpoint = clash_delay_endpoint(proxy_name, args.clash_delay_url, args.timeout_seconds)
    timeout = controller_timeout(args)
    unix_socket = clash_unix_socket(args)
    if unix_socket:
        return unix_json(unix_socket, endpoint, args.clash_controller_secret, timeout)
    if args.clash_controller_url:
        return http_json(args.clash_controller_url, endpoint, args.clash_controller_secret, timeout)
    raise ValueError("no-clash-controller")


def controller_timeout(args: argparse.Namespace) -> float:
    return max(float(args.timeout_seconds) + 1.0, 2.0)


def unix_json(path: str, endpoint: str, secret: str | None, timeout: float) -> dict[str, Any]:
    request = http_request(endpoint, secret)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(path)
        sock.sendall(request)
        body = read_http_body(sock)
    return json.loads(body)


def http_json(base_url: str, endpoint: str, secret: str | None, timeout: float) -> dict[str, Any]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", ""}:
        raise ValueError("only http Clash controller URLs are supported")
    conn = http.client.HTTPConnection(parsed.hostname or "127.0.0.1", parsed.port or 9090, timeout=timeout)
    conn.request("GET", endpoint, headers=auth_headers(secret))
    response = conn.getresponse()
    body = response.read().decode("utf-8")
    conn.close()
    return json.loads(body)


def clash_delay_endpoint(proxy_name: str, delay_url: str, timeout: float) -> str:
    query = urlencode({"timeout": int(float(timeout) * 1000), "url": delay_url})
    return f"/proxies/{quote(proxy_name, safe='')}/delay?{query}"


def clash_unix_socket(args: argparse.Namespace) -> str | None:
    configured = getattr(args, "clash_controller_unix_socket", None)
    if configured:
        return str(configured)
    if Path(DEFAULT_CLASH_UNIX_SOCKET).exists():
        return DEFAULT_CLASH_UNIX_SOCKET
    return None


def classify_clash_delay_payload(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("delay"), int):
        return "clash-delay-pass"
    text = str(payload.get("message") or payload.get("error") or "").lower()
    if "timeout" in text or "deadline" in text:
        return "clash-delay-timeout"
    if "eof" in text:
        return "clash-delay-eof"
    if "refused" in text:
        return "clash-delay-refused"
    if "reset" in text:
        return "clash-delay-reset"
    if text:
        return "clash-delay-error"
    return "clash-delay-missing"


def classify_controller_error(error: BaseException) -> str:
    text = str(error).lower()
    if "no-clash-controller" in text:
        return "no-clash-controller"
    if "timed out" in text or "timeout" in text:
        return "controller-timeout"
    if "connection refused" in text or "refused" in text:
        return "controller-refused"
    if "no such file" in text:
        return "controller-missing"
    return f"controller-{type(error).__name__}"


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def row(tag: str, proxy: dict[str, Any], outcome: str, elapsed: int) -> dict[str, Any]:
    return {
        "tag": tag,
        "candidate": safe_proxy(proxy, tag),
        "outcome": outcome,
        "elapsedMs": elapsed,
    }


def transport_summary(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = {
        "schema": TRANSPORT_SCHEMA,
        "check": args.check,
        "status": "complete" if rows else "empty",
        "candidateCount": len(rows),
        "outcomeCounts": outcome_counts(rows),
        "metadata": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            inputs.private,
            inputs.resolution,
        ),
        "environment": runtime_environment(args),
        "controller": controller_summary(args),
        "privacy": {
            "rawSecretsStored": False,
            "serverStored": False,
            "sniStored": False,
            "passwordStored": False,
            "rawNodeNamesStored": False,
            "controllerSecretStored": False,
            "delayUrlStored": False,
            "probeUrlStored": False,
        },
        "rows": rows,
    }
    baselines = load_baselines(getattr(args, "baseline_transport_summary", []) or [])
    if baselines:
        summary["baselineComparison"] = baseline_comparison(rows, baselines)
    return summary


def load_baselines(paths: list[str]) -> list[dict[str, Any]]:
    return [json.loads(Path(path).read_text()) for path in paths]


def baseline_comparison(
    rows: list[dict[str, Any]],
    baselines: list[dict[str, Any]],
) -> dict[str, Any]:
    baseline_rows = {
        str(row.get("tag")): row
        for summary in baselines
        for row in summary.get("rows", [])
        if isinstance(row, dict)
    }
    paired = [paired_row(row, baseline_rows.get(str(row.get("tag")))) for row in rows]
    return {
        "baselineChecks": sorted({str(item.get("check")) for item in baselines}),
        "baselineOutcomeCounts": merge_outcome_counts(baselines),
        "conclusionCounts": outcome_counts(paired),
        "rows": paired,
    }


def paired_row(row: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    current = str(row.get("outcome"))
    previous = str((baseline or {}).get("outcome") or "missing")
    return {
        "tag": row.get("tag"),
        "baselineOutcome": previous,
        "currentOutcome": current,
        "outcome": paired_conclusion(previous, current),
    }


def paired_conclusion(baseline: str, current: str) -> str:
    baseline_pass = baseline.endswith("-pass")
    current_pass = current.endswith("-pass")
    if not baseline_pass and current_pass:
        return "current-pass-baseline-fail"
    if baseline_pass and not current_pass:
        return "current-fail-baseline-pass"
    if current_pass:
        return "both-pass"
    return "both-fail"


def merge_outcome_counts(summaries: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for summary in summaries:
        for outcome, count in (summary.get("outcomeCounts") or {}).items():
            counts[str(outcome)] = counts.get(str(outcome), 0) + int(count)
    return dict(sorted(counts.items()))


def controller_summary(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "check", "") in {"mihomo-delay", "mihomo-proxy"}:
        return {
            "enabled": True,
            "mode": temporary_mihomo_mode(str(getattr(args, "check", ""))),
            "probeUrlHost": urlparse(str(getattr(args, "mihomo_probe_url", ""))).hostname,
        }
    if getattr(args, "check", "") != "clash-delay":
        return {"enabled": False}
    return {
        "enabled": True,
        "unixSocketConfigured": bool(clash_unix_socket(args)),
        "urlConfigured": bool(getattr(args, "clash_controller_url", None)),
        "secretPresent": bool(getattr(args, "clash_controller_secret", None)),
        "delayUrlHost": urlparse(str(getattr(args, "clash_delay_url", ""))).hostname,
    }


def temporary_mihomo_mode(check: str) -> str:
    if check == "mihomo-delay":
        return "temporary-mihomo-controller-delay"
    return "temporary-mihomo-mixed-port"


def runtime_environment(args: argparse.Namespace) -> dict[str, Any]:
    path = Path(getattr(args, "merged_config", ""))
    if not path.is_file():
        return {"mergedConfigPresent": False}
    try:
        config = load_yaml(path)
    except SystemExit:
        return {"mergedConfigPresent": True, "readable": False}
    tun = config.get("tun") if isinstance(config.get("tun"), dict) else {}
    dns = config.get("dns") if isinstance(config.get("dns"), dict) else {}
    sniffer = config.get("sniffer") if isinstance(config.get("sniffer"), dict) else {}
    return {
        "mergedConfigPresent": True,
        "readable": True,
        "tunEnabled": bool(tun.get("enable")),
        "tunAutoRoute": bool(tun.get("auto-route")),
        "tunStack": str(tun.get("stack") or ""),
        "dnsEnabled": bool(dns.get("enable")),
        "dnsEnhancedMode": str(dns.get("enhanced-mode") or ""),
        "dnsIpv6": bool(dns.get("ipv6")),
        "proxyServerNameserverCount": len(dns.get("proxy-server-nameserver", []) or []),
        "snifferEnabled": bool(sniffer.get("enable")),
        "mixedPortPresent": config.get("mixed-port") is not None,
        "externalControllerUnixPresent": bool(config.get("external-controller-unix")),
    }


def outcome_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    outcomes = sorted({str(item.get("outcome")) for item in rows})
    return {outcome: sum(1 for item in rows if item.get("outcome") == outcome) for outcome in outcomes}


def print_summary(output_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "outputDir": str(output_dir),
        "check": summary["check"],
        "candidateCount": summary["candidateCount"],
        "outcomeCounts": summary["outcomeCounts"],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    controller = summary.get("controller", {})
    lines = [
        "# Tunnel/Private Transport Check",
        "",
        f"- check: `{summary['check']}`",
        f"- status: `{summary['status']}`",
        f"- candidates: `{summary['candidateCount']}`",
        f"- delay host: `{controller.get('delayUrlHost')}`",
        f"- probe host: `{controller.get('probeUrlHost')}`",
        "",
        "## Outcomes",
        "",
    ]
    for outcome, count in summary["outcomeCounts"].items():
        lines.append(f"- `{outcome}`: `{count}`")
    comparison = summary.get("baselineComparison")
    if comparison:
        lines.extend(["", "## Baseline Comparison", ""])
        for outcome, count in comparison["conclusionCounts"].items():
            lines.append(f"- `{outcome}`: `{count}`")
    path.write_text("\n".join(lines) + "\n")
