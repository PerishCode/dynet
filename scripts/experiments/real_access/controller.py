from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ControllerSettings:
    unix_socket: str | None
    url: str | None
    secret: str | None
    hash_salt: str
    poll_ms: int
    tail_ms: int


class ClashSampler:
    def __init__(self, settings: ControllerSettings):
        self.settings = settings

    def capture(self, entry: dict[str, Any]) -> ControllerCapture:
        return ControllerCapture(self.settings, str(entry["domain"]).lower())


class ControllerCapture:
    def __init__(self, settings: ControllerSettings, domain: str):
        self.settings = settings
        self.domain = domain
        self.stop_event = threading.Event()
        self.samples: list[dict[str, Any]] = []
        self.target_ips: set[str] = set()
        self.lock = threading.Lock()
        self.polls = 0
        self.fetch_errors = 0
        self.connections_seen = 0
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def add_target_records(self, records: list[Any]) -> None:
        with self.lock:
            self.target_ips.update(target_ips_from_records(records))

    def close(self) -> dict[str, Any]:
        if self.settings.tail_ms > 0:
            time.sleep(self.settings.tail_ms / 1000)
        self.stop_event.set()
        self.thread.join(timeout=2)
        return summarize_samples(
            self.samples,
            polls=self.polls,
            fetch_errors=self.fetch_errors,
            connections_seen=self.connections_seen,
            target_ip_count=self.target_ip_count(),
        )

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.capture_snapshot(fetch_connections(self.settings))
            except Exception:
                self.fetch_errors += 1
            self.stop_event.wait(max(self.settings.poll_ms, 10) / 1000)

    def capture_snapshot(self, snapshot: dict[str, Any]) -> None:
        self.polls += 1
        connections = [
            item
            for item in snapshot.get("connections", [])
            if isinstance(item, dict)
        ]
        self.connections_seen += len(connections)
        target_ips = self.target_ip_snapshot()
        for item in connections:
            match_source = connection_match_source(item, self.domain, target_ips)
            if match_source:
                self.samples.append(
                    sanitize_connection(
                        item,
                        self.domain,
                        self.settings.hash_salt,
                        match_source,
                    )
                )

    def target_ip_snapshot(self) -> set[str]:
        with self.lock:
            return set(self.target_ips)

    def target_ip_count(self) -> int:
        with self.lock:
            return len(self.target_ips)


def sampler_from_args(args: argparse.Namespace) -> ClashSampler | None:
    if not args.clash_controller_unix_socket and not args.clash_controller_url:
        return None
    settings = ControllerSettings(
        unix_socket=args.clash_controller_unix_socket,
        url=args.clash_controller_url,
        secret=args.clash_controller_secret,
        hash_salt=args.clash_controller_hash_salt,
        poll_ms=args.clash_controller_poll_ms,
        tail_ms=args.clash_controller_tail_ms,
    )
    return ClashSampler(settings)


def fetch_connections(settings: ControllerSettings) -> dict[str, Any]:
    if settings.unix_socket:
        return unix_get_json(settings.unix_socket, "/connections", settings.secret)
    if settings.url:
        return http_get_json(settings.url, "/connections", settings.secret)
    return {"connections": []}


def unix_get_json(path: str, endpoint: str, secret: str | None) -> dict[str, Any]:
    request = http_request(endpoint, secret)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(path)
        sock.sendall(request)
        body = read_http_body(sock)
    return json.loads(body)


def http_get_json(base_url: str, endpoint: str, secret: str | None) -> dict[str, Any]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", ""}:
        raise ValueError("only http Clash controller URLs are supported")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 9090
    conn = http.client.HTTPConnection(host, port, timeout=2)
    headers = auth_headers(secret)
    conn.request("GET", endpoint, headers=headers)
    response = conn.getresponse()
    body = response.read().decode("utf-8")
    conn.close()
    return json.loads(body)


def http_request(endpoint: str, secret: str | None) -> bytes:
    headers = [
        f"GET {endpoint} HTTP/1.1",
        "Host: 127.0.0.1",
        "Connection: close",
    ]
    if secret:
        headers.append(f"Authorization: Bearer {secret}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")


def auth_headers(secret: str | None) -> dict[str, str]:
    if not secret:
        return {}
    return {"Authorization": f"Bearer {secret}"}


def read_http_body(sock: socket.socket) -> str:
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            break
        chunks.append(data)
    raw = b"".join(chunks)
    headers, _, body = raw.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in headers.lower():
        body = decode_chunked(body)
    return body.decode("utf-8")


def decode_chunked(body: bytes) -> bytes:
    output = bytearray()
    rest = body
    while rest:
        size_raw, _, after_size = rest.partition(b"\r\n")
        if not after_size:
            break
        size = int(size_raw.split(b";", 1)[0], 16)
        if size == 0:
            break
        output.extend(after_size[:size])
        rest = after_size[size + 2 :]
    return bytes(output)


def connection_matches(
    item: dict[str, Any],
    domain: str,
    target_ips: set[str] | None = None,
) -> bool:
    return bool(connection_match_source(item, domain, target_ips or set()))


def connection_match_source(
    item: dict[str, Any],
    domain: str,
    target_ips: set[str],
) -> str | None:
    metadata = item.get("metadata", {})
    if not isinstance(metadata, dict):
        return None
    if domain in metadata_hosts(metadata):
        return "domain"
    destination_ip = string_or_none(metadata.get("destinationIP"))
    if destination_ip and destination_ip in target_ips:
        return "destination-ip"
    return None


def metadata_hosts(metadata: dict[str, Any]) -> set[str]:
    return {
        host
        for field in ("host", "sniffHost", "remoteDestination")
        if (host := normalize_host(metadata.get(field)))
    }


def normalize_host(value: Any) -> str | None:
    if value is None:
        return None
    host = str(value).lower().strip().strip(".")
    if not host:
        return None
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if ":" in host:
        name, port = host.rsplit(":", 1)
        if port.isdigit():
            return name.strip(".")
    return host


def sanitize_connection(
    item: dict[str, Any],
    domain: str,
    salt: str,
    match_source: str,
) -> dict[str, Any]:
    chains = [str(value) for value in item.get("chains", []) if isinstance(value, str)]
    rule_payload = item.get("rulePayload")
    return {
        "domain": domain,
        "network": string_or_none(item.get("metadata", {}).get("network")),
        "type": string_or_none(item.get("metadata", {}).get("type")),
        "matchSource": match_source,
        "rule": string_or_none(item.get("rule")),
        "rulePayloadHash": hash_value(rule_payload, salt) if rule_payload else None,
        "chainHashes": [hash_value(value, salt) for value in chains],
        "chainLength": len(chains),
    }


def target_ips_from_records(records: list[Any]) -> set[str]:
    output = set()
    for record in records:
        try:
            sockaddr = record[4]
            output.add(str(sockaddr[0]))
        except (IndexError, TypeError):
            continue
    return output


def string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def hash_value(value: Any, salt: str) -> str:
    raw = f"{salt}\0{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def summarize_samples(
    samples: list[dict[str, Any]],
    *,
    polls: int = 0,
    fetch_errors: int = 0,
    connections_seen: int = 0,
    target_ip_count: int = 0,
) -> dict[str, Any]:
    chain_keys = sorted(
        {
            ">".join(sample.get("chainHashes", []))
            for sample in samples
            if sample.get("chainHashes")
        }
    )
    rules = sorted({sample.get("rule") for sample in samples if sample.get("rule")})
    match_sources = sorted(
        {
            sample.get("matchSource")
            for sample in samples
            if sample.get("matchSource")
        }
    )
    observed = bool(samples)
    return {
        "enabled": True,
        "samples": len(samples),
        "observed": observed,
        "chainKeys": chain_keys,
        "rules": rules,
        "matchSources": match_sources,
        "polls": polls,
        "fetchErrors": fetch_errors,
        "connectionsSeen": connections_seen,
        "targetIpCount": target_ip_count,
        "missReason": miss_reason(observed, polls, fetch_errors, connections_seen),
    }


def miss_reason(
    observed: bool,
    polls: int,
    fetch_errors: int,
    connections_seen: int,
) -> str | None:
    if observed:
        return None
    if fetch_errors and not polls:
        return "fetch-error"
    if polls and connections_seen == 0:
        return "no-controller-connections"
    if polls:
        return "no-domain-match"
    return "not-polled"


def add_controller_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--clash-controller-unix-socket")
    parser.add_argument("--clash-controller-url")
    parser.add_argument("--clash-controller-secret")
    parser.add_argument("--clash-controller-hash-salt", default="dynet-clash-proof-v1")
    parser.add_argument("--clash-controller-poll-ms", type=int, default=100)
    parser.add_argument("--clash-controller-tail-ms", type=int, default=250)
