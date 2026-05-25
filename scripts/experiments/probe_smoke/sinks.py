from __future__ import annotations

import socket
import ssl
import tempfile
import threading
from pathlib import Path
from typing import Any


TROJAN_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUGlaHB5423Akk3B0x7gvefE+CB0MwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDUyMjEwNTAxMVoXDTM2MDUxOTEw
NTAxMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE7E1dqH9AlRDfY4emYCsK7xJRSwHCtWFREbGp22QYO5lhDNcfEJPBaRmx
olSdtLKmLstPfvMfRQ4W9Efc/29kQqNTMFEwHQYDVR0OBBYEFO+1LlejZqp+d+Ux
YQ/a1nSvJ6pRMB8GA1UdIwQYMBaAFO+1LlejZqp+d+UxYQ/a1nSvJ6pRMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgWfIwk5lFuNOeYk9+bbwoGZqi
FUpJLMlzeo4FQKFSsBICIQDYEN6N8K5CWGKMH+psMi4DQaROJWIsDyQhk9PSa2AC
rA==
-----END CERTIFICATE-----
"""
TROJAN_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM23ia3VlOCNK20UYp8VTF3OUzHyzI5ajWjOBXeiyzMOoAoGCCqGSM49
AwEHoUQDQgAE7E1dqH9AlRDfY4emYCsK7xJRSwHCtWFREbGp22QYO5lhDNcfEJPB
aRmxolSdtLKmLstPfvMfRQ4W9Efc/29kQg==
-----END EC PRIVATE KEY-----
"""


class TcpSink:
    def __init__(self, expected: int) -> None:
        self.expected = expected
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(expected)
        self.listener.settimeout(5)
        self.address = self.listener.getsockname()
        self.byte_counts: list[int] = []
        self.errors: list[str] = []
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "TcpSink":
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            self.listener.close()
        finally:
            self.thread.join(timeout=6)

    @property
    def port(self) -> int:
        return int(self.address[1])

    def _run(self) -> None:
        for _ in range(self.expected):
            try:
                conn, _ = self.listener.accept()
            except OSError as error:
                self.errors.append(str(error))
                return
            with conn:
                conn.settimeout(2)
                self.byte_counts.append(read_count(conn, 64, self.errors))

    def summary(self) -> dict[str, Any]:
        return {
            "address": "127.0.0.1",
            "port": self.port,
            "expectedConnections": self.expected,
            "connections": len(self.byte_counts),
            "byteCounts": self.byte_counts,
            "totalBytes": sum(self.byte_counts),
            "errors": self.errors,
            "rawPayloadStored": False,
        }


class TlsSink(TcpSink):
    def __init__(self, expected: int) -> None:
        super().__init__(expected)
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> "TlsSink":
        self.temp_dir = tempfile.TemporaryDirectory(prefix="dynet-trojan-smoke-")
        super().__enter__()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            super().__exit__(exc_type, exc, tb)
        finally:
            if self.temp_dir is not None:
                self.temp_dir.cleanup()

    def _run(self) -> None:
        context = self.context()
        for _ in range(self.expected):
            try:
                conn, _ = self.listener.accept()
            except OSError as error:
                self.errors.append(str(error))
                return
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(2)
                    self.byte_counts.append(read_count(tls, 64, self.errors))
            except OSError as error:
                self.errors.append(str(error))

    def context(self) -> ssl.SSLContext:
        assert self.temp_dir is not None
        base = Path(self.temp_dir.name)
        cert = base / "cert.pem"
        key = base / "key.pem"
        cert.write_text(TROJAN_CERT_PEM)
        key.write_text(TROJAN_KEY_PEM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        return context


def read_count(conn: socket.socket | ssl.SSLSocket, minimum: int, errors: list[str]) -> int:
    chunks = []
    while True:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        except OSError as error:
            errors.append(str(error))
            break
        if not chunk:
            break
        chunks.append(chunk)
        if sum(len(item) for item in chunks) >= minimum:
            break
    return sum(len(item) for item in chunks)


def combined_server_summary(raw: dict[str, Any], tls: dict[str, Any]) -> dict[str, Any]:
    return {
        "address": "127.0.0.1",
        "rawTcp": raw,
        "tlsTcp": tls,
        "expectedConnections": raw["expectedConnections"] + tls["expectedConnections"],
        "connections": raw["connections"] + tls["connections"],
        "byteCounts": raw["byteCounts"] + tls["byteCounts"],
        "totalBytes": raw["totalBytes"] + tls["totalBytes"],
        "errors": raw["errors"] + tls["errors"],
        "rawPayloadStored": False,
    }
