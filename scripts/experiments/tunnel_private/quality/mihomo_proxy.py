from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from real_access.controller import http_request, read_http_body
from tunnel_private_config import safe_proxy, yaml


MIHOMO_PROXY_TYPES = {"trojan", "vmess"}


def mihomo_proxy_row(args: Any, proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    if yaml is None:
        return row(tag, proxy, "mihomo-yaml-missing", 0)
    if not mihomo_supported(proxy):
        return row(tag, proxy, "unsupported-type", 0)
    started = time.monotonic()
    try:
        probe = mihomo_proxy_probe(args, proxy)
        result = row(tag, proxy, probe["outcome"], elapsed_ms(started))
        if probe.get("httpStatus") is not None:
            result["httpStatus"] = probe["httpStatus"]
        result["stageEvidence"] = probe.get("stageEvidence", {})
        result["configFeatures"] = mihomo_proxy_features(proxy, args)
        return result
    except Exception as error:
        return row(tag, proxy, classify_mihomo_error(error), elapsed_ms(started))


def mihomo_delay_row(args: Any, proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    if yaml is None:
        return row(tag, proxy, "mihomo-yaml-missing", 0)
    if not mihomo_supported(proxy):
        return row(tag, proxy, "unsupported-type", 0)
    started = time.monotonic()
    try:
        probe = mihomo_delay_probe(args, proxy)
        result = row(tag, proxy, probe["outcome"], elapsed_ms(started))
        if probe.get("delayMs") is not None:
            result["delayMs"] = probe["delayMs"]
        result["stageEvidence"] = probe.get("stageEvidence", {})
        result["configFeatures"] = mihomo_proxy_features(proxy, args)
        return result
    except Exception as error:
        return row(tag, proxy, classify_mihomo_error(error), elapsed_ms(started))


def mihomo_proxy_probe(args: Any, proxy: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dynet-mihomo-proxy-") as temp_dir:
        return run_mihomo_proxy_probe(Path(temp_dir), args, proxy)


def mihomo_delay_probe(args: Any, proxy: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dynet-mihomo-delay-") as temp_dir:
        return run_mihomo_delay_probe(Path(temp_dir), args, proxy)


def run_mihomo_delay_probe(root: Path, args: Any, proxy: dict[str, Any]) -> dict[str, Any]:
    socket_path = root / "mihomo.sock"
    config_path = root / "config.yaml"
    config_path.write_text(yaml.safe_dump(mihomo_config(
        proxy,
        free_local_port(),
        interface_name=mihomo_interface_name(args),
    ), sort_keys=False))
    process = start_mihomo(args, root, config_path, controller_socket=socket_path)
    try:
        probe = run_delay_when_ready(socket_path, args)
    finally:
        output = stop_process(process)
    probe["stageEvidence"] = stage_evidence(probe, output)
    return probe


def run_delay_when_ready(socket_path: Path, args: Any) -> dict[str, Any]:
    if not wait_unix_socket(socket_path, 5.0):
        return {"outcome": "mihomo-delay-controller-not-ready"}
    return run_delay_request(
        socket_path,
        str(args.mihomo_probe_url),
        float(args.timeout_seconds),
    )


def run_mihomo_proxy_probe(root: Path, args: Any, proxy: dict[str, Any]) -> dict[str, Any]:
    port = free_local_port()
    config_path = root / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            mihomo_config(
                proxy,
                port,
                interface_name=mihomo_interface_name(args),
            ),
            sort_keys=False,
        )
    )
    process = start_mihomo(args, root, config_path)
    try:
        if not wait_port(port, 5.0):
            probe = {"outcome": "mihomo-not-ready"}
        else:
            probe = run_proxy_curl(port, str(args.mihomo_probe_url), float(args.timeout_seconds))
    finally:
        output = stop_process(process)
    probe["stageEvidence"] = stage_evidence(probe, output)
    return probe


def start_mihomo(
    args: Any,
    root: Path,
    config_path: Path,
    controller_socket: Path | None = None,
) -> subprocess.Popen:
    controller_args = ["-ext-ctl", "", "-ext-ctl-unix", ""]
    if controller_socket is not None:
        controller_args = ["-ext-ctl", "", "-ext-ctl-unix", str(controller_socket)]
    return subprocess.Popen(
        [
            str(args.mihomo_bin),
            "-d",
            str(root),
            "-f",
            str(config_path),
            *controller_args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def mihomo_config(
    proxy: dict[str, Any],
    port: int,
    interface_name: str | None = None,
) -> dict[str, Any]:
    config = {
        "mixed-port": port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": "",
        "proxies": [mihomo_proxy(proxy)],
        "proxy-groups": [{"name": "out", "type": "select", "proxies": ["node"]}],
        "rules": ["MATCH,out"],
    }
    if interface_name:
        config["interface-name"] = interface_name
    return config


def mihomo_proxy(proxy: dict[str, Any]) -> dict[str, Any]:
    common = {
        "type",
        "server",
        "port",
        "udp",
        "network",
    }
    by_type = {
        "trojan": {
            "password",
            "sni",
            "servername",
            "skip-cert-verify",
            "client-fingerprint",
            "fingerprint",
            "alpn",
        },
        "vmess": {
            "uuid",
            "alterId",
            "cipher",
            "tls",
            "servername",
            "sni",
            "skip-cert-verify",
            "client-fingerprint",
            "fingerprint",
            "alpn",
            "ws-opts",
            "h2-opts",
            "http-opts",
            "grpc-opts",
            "packet-encoding",
        },
    }
    kind = proxy_type(proxy)
    allowed = common | by_type.get(kind, set())
    result = {key: value for key, value in proxy.items() if key in allowed}
    if kind == "vmess":
        add_alias(result, proxy, "alterId", "alter-id")
        add_alias(result, proxy, "client-fingerprint", "clientFingerprint")
    apply_resolved_server_ip(proxy, result)
    result["name"] = "node"
    return result


def mihomo_supported(proxy: dict[str, Any]) -> bool:
    return proxy_type(proxy) in MIHOMO_PROXY_TYPES


def proxy_type(proxy: dict[str, Any]) -> str:
    return str(proxy.get("type", "")).lower()


def add_alias(
    target: dict[str, Any],
    source: dict[str, Any],
    output_key: str,
    input_key: str,
) -> None:
    if output_key not in target and input_key in source:
        target[output_key] = source[input_key]


def apply_resolved_server_ip(source: dict[str, Any], target: dict[str, Any]) -> None:
    server_ip = source.get("server-ip") or source.get("serverIp")
    if not server_ip:
        return
    original_server = str(source.get("server") or "")
    target["server"] = str(server_ip)
    if original_server and not (target.get("sni") or target.get("servername")):
        if proxy_type(source) == "vmess":
            target["servername"] = original_server
        else:
            target["sni"] = original_server


def mihomo_interface_name(args: Any) -> str | None:
    value = str(getattr(args, "mihomo_interface_name", "") or "").strip()
    return value or None


def mihomo_proxy_features(proxy: dict[str, Any], args: Any | None = None) -> dict[str, Any]:
    interface_name = mihomo_interface_name(args) if args is not None else None
    return {
        "resolvedServerIpUsed": bool(proxy.get("server-ip") or proxy.get("serverIp")),
        "sniPresent": bool(proxy.get("sni") or proxy.get("servername")),
        "skipCertVerify": bool(proxy.get("skip-cert-verify") or proxy.get("skipCertVerify")),
        "interfaceNameConfigured": interface_name is not None,
        "interfaceNameLength": len(interface_name or ""),
    }


def free_local_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int, timeout: float) -> bool:
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_unix_socket(path: Path, timeout: float) -> bool:
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                sock.connect(str(path))
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_delay_request(socket_path: Path, url: str, timeout: float) -> dict[str, Any]:
    endpoint = delay_endpoint(url, timeout)
    request = http_request(endpoint, None)
    import socket

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout + 1.0)
        sock.connect(str(socket_path))
        sock.sendall(request)
        payload = yaml.safe_load(read_http_body(sock))
    return classify_delay_payload(payload if isinstance(payload, dict) else {})


def delay_endpoint(url: str, timeout: float) -> str:
    query = urlencode({"timeout": int(timeout * 1000), "url": url})
    return f"/proxies/{quote('node', safe='')}/delay?{query}"


def classify_delay_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload.get("delay"), int):
        return {"outcome": "mihomo-delay-pass", "delayMs": int(payload["delay"])}
    text = str(payload.get("message") or payload.get("error") or "").lower()
    result = {"markerCounts": marker_counts(text)}
    if "timeout" in text or "deadline" in text:
        return {**result, "outcome": "mihomo-delay-timeout"}
    if "eof" in text:
        return {**result, "outcome": "mihomo-delay-eof"}
    if "refused" in text:
        return {**result, "outcome": "mihomo-delay-refused"}
    if "reset" in text:
        return {**result, "outcome": "mihomo-delay-reset"}
    if text:
        return {**result, "outcome": "mihomo-delay-error"}
    return {**result, "outcome": "mihomo-delay-missing"}


def run_proxy_curl(port: int, url: str, timeout: float) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "curl",
            "-x",
            f"http://127.0.0.1:{port}",
            "-I",
            "-m",
            str(timeout),
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{errormsg}",
            url,
        ],
        text=True,
        capture_output=True,
        timeout=timeout + 3.0,
        check=False,
    )
    return classify_curl_result(completed.returncode, completed.stdout, completed.stderr)


def classify_curl_result(code: int, output: str, error: str = "") -> dict[str, Any]:
    status = curl_http_status(output)
    result = {
        "httpStatus": status,
        "curlExitCode": code,
        "curlMarkerCounts": marker_counts(error),
        "curlStageMarkerCounts": stage_marker_counts(error),
    }
    if code == 0 and status and status < 500:
        return {**result, "outcome": "mihomo-proxy-pass"}
    if code == 28:
        return {**result, "outcome": "mihomo-proxy-timeout"}
    if code == 35:
        return {**result, "outcome": "mihomo-proxy-tls-error"}
    if code in {5, 6}:
        return {**result, "outcome": "mihomo-proxy-dns-error"}
    if code == 7:
        return {**result, "outcome": "mihomo-proxy-connect-error"}
    return {**result, "outcome": "mihomo-proxy-error"}


def curl_http_status(output: str) -> int | None:
    token = output.strip().split(" ", 1)[0]
    if not token.isdigit():
        return None
    return int(token)


def stop_process(process: subprocess.Popen) -> str:
    if process.poll() is not None:
        return collect_process_output(process)
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=2.0)
    return f"{stdout or ''}\n{stderr or ''}"


def collect_process_output(process: subprocess.Popen) -> str:
    stdout, stderr = process.communicate(timeout=0.1)
    return f"{stdout or ''}\n{stderr or ''}"


def stage_evidence(probe: dict[str, Any], process_output: str) -> dict[str, Any]:
    markers = merge_counts(
        probe.get("curlMarkerCounts", {}),
        marker_counts(f"{probe.get('outcome', '')}\n{process_output}"),
    )
    stage_markers = merge_counts(
        probe.get("curlStageMarkerCounts", {}),
        stage_marker_counts(process_output),
    )
    return {
        "curlExitCode": probe.get("curlExitCode"),
        "httpStatus": probe.get("httpStatus"),
        "markerCounts": markers,
        "stageMarkerCounts": stage_markers,
        "failureCategory": failure_category(probe, stage_markers),
        "rawLogsStored": False,
        "rawCurlErrorStored": False,
    }


def merge_counts(*items: dict[str, int]) -> dict[str, int]:
    result: dict[str, int] = {}
    for item in items:
        for key, count in item.items():
            result[key] = result.get(key, 0) + int(count)
    return dict(sorted(result.items()))


def marker_counts(text: str) -> dict[str, int]:
    lowered = text.lower()
    markers = {
        "tls": ["tls", "ssl"],
        "eof": ["eof"],
        "timeout": ["timeout", "deadline"],
        "connect": ["connect"],
        "dial": ["dial"],
        "reset": ["reset"],
        "refused": ["refused"],
        "proxy": ["proxy"],
    }
    counts = {
        name: sum(lowered.count(needle) for needle in needles)
        for name, needles in markers.items()
    }
    return {name: count for name, count in counts.items() if count}


def stage_marker_counts(text: str) -> dict[str, int]:
    lowered = text.lower()
    markers = {
        "curl-ssl-connect-error": ["ssl_connect", "ssl connect", "tls connect"],
        "curl-proxy-connect": ["proxy connect", "connect tunnel"],
        "mihomo-dial-timeout": ["i/o timeout", "connect timeout", "context deadline"],
        "mihomo-dial-error": ["dial ", "dial tcp", "dial failed"],
        "mihomo-unexpected-eof": ["unexpected eof", "eof"],
        "mihomo-tls-handshake": ["tls handshake", "handshake failure"],
        "mihomo-dns-error": ["dns", "lookup"],
    }
    counts = {
        name: sum(lowered.count(needle) for needle in needles)
        for name, needles in markers.items()
    }
    return {name: count for name, count in counts.items() if count}


def failure_category(probe: dict[str, Any], stage_markers: dict[str, int]) -> str:
    if probe.get("outcome") == "mihomo-proxy-pass":
        return "product-pass"
    if stage_markers.get("mihomo-dial-timeout"):
        return "proxy-dial-timeout"
    if stage_markers.get("mihomo-tls-handshake") and stage_markers.get("mihomo-unexpected-eof"):
        return "proxy-tls-handshake-eof"
    if stage_markers.get("mihomo-tls-handshake"):
        return "proxy-tls-handshake-error"
    if stage_markers.get("curl-ssl-connect-error"):
        return "curl-target-tls-error"
    return str(probe.get("outcome") or "unknown")


def classify_mihomo_error(error: BaseException) -> str:
    text = str(error).lower()
    if "timed out" in text or "timeout" in text:
        return "mihomo-proxy-timeout"
    if "no such file" in text:
        return "mihomo-binary-missing"
    return f"mihomo-{type(error).__name__}"


def row(tag: str, proxy: dict[str, Any], outcome: str, elapsed: int) -> dict[str, Any]:
    return {
        "tag": tag,
        "candidate": safe_proxy(proxy, tag),
        "outcome": outcome,
        "elapsedMs": elapsed,
    }


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
