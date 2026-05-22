from __future__ import annotations

import socket
import ssl
import time
from collections import Counter
from typing import Any

from real_access.common import (
    HTTP_GET_READ_LIMIT,
    HTTP_REQUEST_TARGET,
    USER_AGENT,
    ProbeSemanticError,
)


def probe(
    entry: dict[str, Any],
    timeout_seconds: float,
    stages: list[dict[str, Any]],
    on_resolved: Any | None = None,
) -> dict[str, Any]:
    probe_name = entry["probe"]
    if probe_name == "dns":
        return probe_dns(entry["domain"], timeout_seconds, stages, on_resolved)
    if probe_name == "tcp-connect":
        return probe_tcp(
            entry["domain"],
            int(entry["port"]),
            timeout_seconds,
            stages,
            on_resolved,
        )
    if probe_name == "tls-handshake":
        return probe_tls(
            entry["domain"],
            int(entry["port"]),
            timeout_seconds,
            stages,
            on_resolved,
        )
    if probe_name == "https-head":
        return probe_https_head(
            entry["domain"],
            int(entry["port"]),
            timeout_seconds,
            stages,
            on_resolved,
        )
    if probe_name == "https-get":
        return probe_https_get(
            entry["domain"],
            int(entry["port"]),
            timeout_seconds,
            stages,
            on_resolved,
        )
    raise ValueError(f"unsupported probe mode: {probe_name}")

def probe_dns(
    domain: str,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
    on_resolved: Any | None = None,
) -> dict[str, Any]:
    records = resolve_addresses(domain, 443, timeout_seconds, stages)
    notify_resolved(on_resolved, records)
    return dns_details(records)

def probe_tcp(
    domain: str,
    port: int,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
    on_resolved: Any | None = None,
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    notify_resolved(on_resolved, records)
    sock, connect_details = connect_resolved(records, timeout_seconds, stages)
    sock.close()
    return {**dns_details(records), **connect_details}

def probe_tls(
    domain: str,
    port: int,
    timeout_seconds: float,
    stages: list[dict[str, Any]],
    on_resolved: Any | None = None,
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    notify_resolved(on_resolved, records)
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
    on_resolved: Any | None = None,
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    notify_resolved(on_resolved, records)
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
    on_resolved: Any | None = None,
) -> dict[str, Any]:
    records = resolve_addresses(domain, port, timeout_seconds, stages)
    notify_resolved(on_resolved, records)
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

def notify_resolved(on_resolved: Any | None, records: list[Any]) -> None:
    if on_resolved is not None:
        on_resolved(records)

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
            attempt = {"family": family_name(family), "ok": False}
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
