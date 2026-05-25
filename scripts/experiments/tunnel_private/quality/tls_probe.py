from __future__ import annotations

import json
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any


UTLS_VERSION = "v1.8.4"
DEFAULT_UTLS_FINGERPRINTS = [
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "randomized",
    "randomized-noalpn",
]
GO_TLS_PROBE = r'''
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

type input struct {
	Host      string
	Port      int
	SNI       string
	TimeoutMs int
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		write(false, "", fmt.Sprintf("decode: %v", err))
		return
	}
	dialer := &net.Dialer{Timeout: time.Duration(in.TimeoutMs) * time.Millisecond}
	config := &tls.Config{ServerName: in.SNI, InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(in.Host, strconv.Itoa(in.Port)), config)
	if err != nil {
		write(false, "", err.Error())
		return
	}
	defer conn.Close()
	write(true, tls.VersionName(conn.ConnectionState().Version), "")
}

func write(ok bool, version string, message string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"ok": ok,
		"version": version,
		"message": message,
	})
}
'''
UTLS_PROBE = r'''
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
)

type input struct {
	Host         string
	Port         int
	SNI          string
	TimeoutMs    int
	Fingerprints []string
}

type result struct {
	Fingerprint string `json:"fingerprint"`
	OK          bool   `json:"ok"`
	Version     string `json:"version,omitempty"`
	Message     string `json:"message,omitempty"`
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		write([]result{{OK: false, Message: fmt.Sprintf("decode: %v", err)}})
		return
	}
	results := make([]result, 0, len(in.Fingerprints))
	for _, fingerprint := range in.Fingerprints {
		results = append(results, probe(in, fingerprint))
	}
	write(results)
}

func probe(in input, fingerprint string) result {
	id, ok := helloID(fingerprint)
	if !ok {
		return result{Fingerprint: fingerprint, OK: false, Message: "unsupported fingerprint"}
	}
	dialer := &net.Dialer{Timeout: time.Duration(in.TimeoutMs) * time.Millisecond}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(in.Host, strconv.Itoa(in.Port)))
	if err != nil {
		return result{Fingerprint: fingerprint, OK: false, Message: err.Error()}
	}
	defer conn.Close()
	config := &utls.Config{ServerName: in.SNI, InsecureSkipVerify: true}
	tlsConn := utls.UClient(conn, config, id)
	if err := tlsConn.Handshake(); err != nil {
		return result{Fingerprint: fingerprint, OK: false, Message: err.Error()}
	}
	return result{
		Fingerprint: fingerprint,
		OK: true,
		Version: utls.VersionName(tlsConn.ConnectionState().Version),
	}
}

func helloID(fingerprint string) (utls.ClientHelloID, bool) {
	switch strings.ToLower(fingerprint) {
	case "chrome":
		return utls.HelloChrome_Auto, true
	case "firefox":
		return utls.HelloFirefox_Auto, true
	case "safari":
		return utls.HelloSafari_Auto, true
	case "ios":
		return utls.HelloIOS_Auto, true
	case "android":
		return utls.HelloAndroid_11_OkHttp, true
	case "randomized":
		return utls.HelloRandomized, true
	case "randomized-alpn":
		return utls.HelloRandomizedALPN, true
	case "randomized-noalpn":
		return utls.HelloRandomizedNoALPN, true
	default:
		return utls.ClientHelloID{}, false
	}
}

func write(results []result) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"results": results})
}
'''


def trojan_tls_handshake(proxy: dict[str, Any], timeout: float) -> str:
    host = proxy_host(proxy)
    sni = proxy_sni(proxy)
    port = int(proxy["port"])
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as socket_file:
        socket_file.settimeout(timeout)
        with context.wrap_socket(socket_file, server_hostname=sni) as tls_file:
            return str(tls_file.version())


def go_tls_payload(proxy: dict[str, Any], timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dynet-go-tls-") as temp_dir:
        probe = Path(temp_dir) / "main.go"
        probe.write_text(GO_TLS_PROBE)
        completed = subprocess.run(
            ["go", "run", str(probe)],
            input=json.dumps(go_tls_input(proxy, timeout)),
            text=True,
            capture_output=True,
            timeout=timeout + 10.0,
            check=False,
        )
    if completed.returncode != 0:
        return {"ok": False, "message": "go-run-failed"}
    return json.loads(completed.stdout)


def utls_payload(
    proxy: dict[str, Any],
    timeout: float,
    fingerprints: list[str],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dynet-utls-") as temp_dir:
        root = Path(temp_dir)
        (root / "go.mod").write_text(utls_go_mod())
        (root / "main.go").write_text(UTLS_PROBE)
        if not go_mod_download(root):
            return {"results": [{"ok": False, "message": "utls-mod-download-failed"}]}
        completed = subprocess.run(
            ["go", "run", "."],
            input=json.dumps(utls_input(proxy, timeout, fingerprints)),
            text=True,
            capture_output=True,
            timeout=timeout * max(len(fingerprints), 1) + 30.0,
            cwd=root,
            check=False,
        )
    if completed.returncode != 0:
        return {"results": [{"ok": False, "message": "utls-run-failed"}]}
    return json.loads(completed.stdout)


def go_mod_download(root: Path) -> bool:
    completed = subprocess.run(
        ["go", "mod", "tidy"],
        text=True,
        capture_output=True,
        cwd=root,
        check=False,
    )
    return completed.returncode == 0


def utls_go_mod() -> str:
    return (
        "module dynet-utls-probe\n\n"
        "go 1.25\n\n"
        f"require github.com/metacubex/utls {UTLS_VERSION}\n"
    )


def go_tls_input(proxy: dict[str, Any], timeout: float) -> dict[str, Any]:
    return {
        "Host": proxy_host(proxy),
        "Port": int(proxy["port"]),
        "SNI": proxy_sni(proxy),
        "TimeoutMs": int(timeout * 1000),
    }


def utls_input(
    proxy: dict[str, Any],
    timeout: float,
    fingerprints: list[str],
) -> dict[str, Any]:
    return {
        **go_tls_input(proxy, timeout),
        "Fingerprints": fingerprints,
    }


def utls_fingerprints(args: Any) -> list[str]:
    values = getattr(args, "utls_fingerprint", None) or DEFAULT_UTLS_FINGERPRINTS
    return [str(item) for item in values]


def classify_go_tls_payload(payload: dict[str, Any]) -> str:
    if payload.get("ok"):
        return "go-tls-pass"
    return classify_go_tls_message(str(payload.get("message") or ""))


def classify_utls_payload(payload: dict[str, Any]) -> str:
    rows = payload.get("results", [])
    if any(row.get("ok") for row in rows if isinstance(row, dict)):
        return "utls-pass"
    if any(has_message(row, "timeout", "deadline") for row in rows if isinstance(row, dict)):
        return "utls-timeout"
    if any(has_message(row, "eof") for row in rows if isinstance(row, dict)):
        return "utls-eof"
    if rows:
        return "utls-error"
    return "utls-missing"


def classify_go_tls_error(error: BaseException) -> str:
    return classify_go_tls_message(str(error))


def classify_utls_error(error: BaseException) -> str:
    return classify_go_tls_message(str(error)).replace("go-tls", "utls")


def classify_go_tls_message(message: str) -> str:
    text = message.lower()
    if "timeout" in text or "deadline" in text:
        return "go-tls-timeout"
    if "eof" in text:
        return "go-tls-eof"
    if "refused" in text:
        return "go-tls-refused"
    if "reset" in text:
        return "go-tls-reset"
    if "go-run-failed" in text:
        return "go-tls-run-failed"
    return "go-tls-error"


def classify_transport_error(error: BaseException) -> str:
    if isinstance(error, ssl.SSLEOFError):
        return "tls-handshake-eof"
    if isinstance(error, ssl.SSLError):
        return "tls-error"
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, OSError):
        text = str(error).lower()
        if "timed out" in text or "timeout" in text:
            return "timeout"
        if "refused" in text:
            return "refused"
        if "reset" in text:
            return "reset"
        if "temporarily unavailable" in text:
            return "temporarily-unavailable"
        return type(error).__name__
    return type(error).__name__


def utls_fingerprint_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in payload.get("results", []):
        if not isinstance(row, dict):
            continue
        rows.append({
            "fingerprint": row.get("fingerprint"),
            "outcome": utls_row_outcome(row),
            "tlsVersion": row.get("version"),
        })
    return rows


def utls_row_outcome(row: dict[str, Any]) -> str:
    if row.get("ok"):
        return "pass"
    return classify_go_tls_message(str(row.get("message") or "")).replace("go-tls-", "")


def utls_winner(payload: dict[str, Any]) -> dict[str, Any] | None:
    for row in payload.get("results", []):
        if isinstance(row, dict) and row.get("ok"):
            return row
    return None


def has_message(row: dict[str, Any], *needles: str) -> bool:
    text = str(row.get("message") or "").lower()
    return any(needle in text for needle in needles)


def proxy_host(proxy: dict[str, Any]) -> str:
    return str(proxy.get("server-ip") or proxy.get("serverIp") or proxy["server"])


def proxy_sni(proxy: dict[str, Any]) -> str:
    return str(proxy.get("sni") or proxy.get("servername") or proxy["server"])
