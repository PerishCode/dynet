from __future__ import annotations

import argparse
import ipaddress
import json
import selectors
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from tunnel_private_config import (
    ConfigInputs,
    build_config,
    build_private_config,
    metadata,
    write_json,
)
from tunnel_private.reporting import write_observer_markdown


OBSERVE_SCHEMA = "dynet-tunnel-private-target-observer/v1alpha1"
REMOTE_SCHEMA = "dynet-remote-echo-target/v1alpha1"
OBSERVER_TARGET = "https://<observer-target>/"
REMOTE_ECHO_SERVER = r"""
from __future__ import annotations

import json
import socket
import sys
import time

port = int(sys.argv[1])
expected = int(sys.argv[2])
timeout = float(sys.argv[3])
reply = sys.argv[4].encode("utf-8")
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", port))
server.listen(max(1, expected))
actual_port = server.getsockname()[1]
print(json.dumps({"ready": True, "port": actual_port}, sort_keys=True), flush=True)
deadline = time.monotonic() + timeout
connections = []
try:
    while len(connections) < expected and time.monotonic() < deadline:
        server.settimeout(max(0.1, min(1.0, deadline - time.monotonic())))
        try:
            conn, _peer = server.accept()
        except socket.timeout:
            continue
        row = {"index": len(connections) + 1}
        try:
            conn.settimeout(3.0)
            try:
                data = conn.recv(4096)
                row["readTimedOut"] = False
            except socket.timeout:
                data = b""
                row["readTimedOut"] = True
            row["receivedBytes"] = len(data)
            row["tlsClientHelloLike"] = data.startswith(b"\x16\x03")
            sent = 0
            if reply:
                try:
                    sent = conn.send(reply)
                except OSError:
                    sent = 0
            row["sentBytes"] = sent
        finally:
            conn.close()
        connections.append(row)
finally:
    server.close()

print(
    json.dumps(
        {
            "schema": "dynet-remote-echo-target/v1alpha1",
            "status": "completed",
            "listenPort": actual_port,
            "expectedConnections": expected,
            "connections": connections,
            "privacy": {
                "rawPayloadStored": False,
                "peerAddressStored": False,
            },
        },
        sort_keys=True,
    ),
    flush=True,
)
"""


ProbeFn = Callable[[argparse.Namespace, Path], dict[str, Any]]
CleanFn = Callable[[dict[str, Any]], dict[str, Any]]
SummaryFn = Callable[[argparse.Namespace, ConfigInputs, dict[str, Any], Path], dict[str, Any]]


def command_observe_target(
    args: argparse.Namespace,
    *,
    inputs: ConfigInputs,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    plan_summary: SummaryFn,
    private_summary: SummaryFn,
) -> int:
    target_host = args.target_host or target_host_from_ssh(args.ssh_host)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    with tempfile.TemporaryDirectory(prefix="dynet-target-observer-") as temp_dir:
        temp_root = Path(temp_dir)
        for case in observer_cases():
            cases.append(
                run_observer_case(
                    args,
                    inputs,
                    case,
                    target_host,
                    temp_root,
                    output_dir,
                    run_probe,
                    clean_report,
                    private_summary if case.get("privateDirect") else plan_summary,
                )
            )
    summary = observer_summary(args, inputs, target_host, cases)
    write_json(output_dir / "summary.json", summary)
    write_observer_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    return 0


def observer_cases() -> list[dict[str, Any]]:
    return [
        {
            "label": "private-direct-echo",
            "probeMode": "private-direct",
            "privateDirect": True,
            "expectedConnections": "single",
        },
        {
            "label": "candidate-direct-echo",
            "probeMode": "candidate",
            "privatePath": False,
            "expectedConnections": "single",
        },
        {
            "label": "tunnel-private-echo",
            "probeMode": "private",
            "privatePath": True,
            "expectedConnections": "candidates",
        },
    ]


def run_observer_case(
    base_args: argparse.Namespace,
    inputs: ConfigInputs,
    case: dict[str, Any],
    target_host: str,
    temp_root: Path,
    output_dir: Path,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    summary_fn: SummaryFn,
) -> dict[str, Any]:
    expected = case_expected_connections(case, inputs)
    server = start_remote_echo(base_args, expected)
    ready = read_ready(server, base_args.ready_timeout)
    args = observer_case_args(base_args, case, target_host, int(ready["port"]))
    case_dir = output_dir / str(case["label"])
    case_dir.mkdir(parents=True, exist_ok=True)
    config_path = temp_root / f"{case['label']}.json"
    write_json(config_path, observer_case_config(args, inputs, case), secret=True)
    report = run_probe(args, config_path)
    report_path = case_dir / "report.json"
    write_json(report_path, redact_observer_report(clean_report(report)))
    probe_summary = summary_fn(args, inputs, report, report_path)
    probe_summary["targetUrl"] = OBSERVER_TARGET
    remote = finish_remote_echo(server, base_args.server_timeout + 5.0)
    row = observer_case_summary(case, probe_summary, remote, expected)
    write_json(case_dir / "summary.json", row)
    return row


def observer_case_args(
    base_args: argparse.Namespace,
    case: dict[str, Any],
    target_host: str,
    target_port: int,
) -> argparse.Namespace:
    args = argparse.Namespace(**vars(base_args))
    args.protocol = "tls-handshake"
    args.probe_mode = case["probeMode"]
    args.target_url = f"https://{target_host}:{target_port}/"
    args.domain = append_unique(list(args.domain or []), target_host)
    return args


def observer_case_config(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    case: dict[str, Any],
) -> dict[str, Any]:
    if case.get("privateDirect"):
        return build_private_config(inputs.private)
    return build_config(
        args,
        inputs.candidates,
        inputs.private,
        private_path=bool(case["privatePath"]),
    )


def observer_case_summary(
    case: dict[str, Any],
    probe_summary: dict[str, Any],
    remote: dict[str, Any],
    expected: int,
) -> dict[str, Any]:
    signals = observer_signals(remote)
    return {
        "label": case["label"],
        "probeMode": probe_summary["probeMode"],
        "protocol": "tls-handshake",
        "expectedConnections": expected,
        "probe": probe_summary["report"],
        "observer": remote,
        "signals": signals,
    }


def observer_summary(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    target_host: str,
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": OBSERVE_SCHEMA,
        "target": {
            "hostLength": len(target_host),
            "portPolicy": "dynamic" if args.target_port == 0 else "fixed",
        },
        "metadata": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            inputs.private,
            inputs.resolution,
        ),
        "totals": {
            "cases": len(cases),
            "observerConnections": sum(item["signals"]["connections"] for item in cases),
            "observerReceivedConnections": sum(
                item["signals"]["receivedConnections"] for item in cases
            ),
            "observerSentConnections": sum(
                item["signals"]["sentConnections"] for item in cases
            ),
            "tlsClientHelloLikeConnections": sum(
                item["signals"]["tlsClientHelloLikeConnections"] for item in cases
            ),
        },
        "cases": cases,
        "privacy": {
            "rawPayloadStored": False,
            "peerAddressStored": False,
            "targetHostStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def observer_signals(remote: dict[str, Any]) -> dict[str, int]:
    connections = remote.get("connections", [])
    if not isinstance(connections, list):
        connections = []
    return {
        "connections": len(connections),
        "receivedConnections": sum(
            1 for item in connections if int(item.get("receivedBytes") or 0) > 0
        ),
        "sentConnections": sum(1 for item in connections if int(item.get("sentBytes") or 0) > 0),
        "tlsClientHelloLikeConnections": sum(
            1 for item in connections if item.get("tlsClientHelloLike") is True
        ),
    }


def case_expected_connections(case: dict[str, Any], inputs: ConfigInputs) -> int:
    if case["expectedConnections"] == "candidates":
        return len(inputs.candidates)
    return 1


def start_remote_echo(args: argparse.Namespace, expected: int) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [
            "ssh",
            args.ssh_host,
            "python3",
            "-u",
            "-",
            str(args.target_port),
            str(expected),
            str(args.server_timeout),
            args.reply_text,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdin is None:
        raise RuntimeError("failed to open ssh stdin")
    process.stdin.write(REMOTE_ECHO_SERVER)
    process.stdin.close()
    return process


def read_ready(process: subprocess.Popen[str], timeout: float) -> dict[str, Any]:
    try:
        line = read_line(process, timeout)
    except RuntimeError as error:
        stop_remote_echo(process)
        raise RuntimeError(
            f"{error}; remoteExit={process.returncode}; "
            f"stderrPresent={remote_stderr_present(process)}"
        ) from error
    ready = json.loads(line)
    if ready.get("ready") is not True or ready.get("port") is None:
        raise RuntimeError(f"remote observer did not become ready: {line.strip()}")
    return ready


def read_line(process: subprocess.Popen[str], timeout: float) -> str:
    if process.stdout is None:
        raise RuntimeError("remote observer stdout is closed")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise RuntimeError("timed out waiting for remote observer")
        line = process.stdout.readline()
    finally:
        selector.close()
    if not line:
        raise RuntimeError("remote observer exited before writing readiness")
    return line


def finish_remote_echo(process: subprocess.Popen[str], timeout: float) -> dict[str, Any]:
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        return {
            "schema": REMOTE_SCHEMA,
            "status": "timeout",
            "connections": [],
            "privacy": {"rawPayloadStored": False, "peerAddressStored": False},
        }
    stdout = process.stdout.read() if process.stdout is not None else ""
    stderr = process.stderr.read() if process.stderr is not None else ""
    summary = last_remote_summary(stdout)
    if summary is not None:
        summary["exitCode"] = process.returncode
        summary["stderrPresent"] = bool(stderr.strip())
        return summary
    return {
        "schema": REMOTE_SCHEMA,
        "status": "missing-summary",
        "exitCode": process.returncode,
        "stderrPresent": bool(stderr.strip()),
        "connections": [],
        "privacy": {"rawPayloadStored": False, "peerAddressStored": False},
    }


def stop_remote_echo(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)


def remote_stderr_present(process: subprocess.Popen[str]) -> bool:
    if process.stderr is None:
        return False
    try:
        return bool(process.stderr.read().strip())
    except ValueError:
        return False


def last_remote_summary(stdout: str) -> dict[str, Any] | None:
    found = None
    for line in stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("schema") == REMOTE_SCHEMA:
            found = item
    return found


def target_host_from_ssh(host: str) -> str:
    completed = subprocess.run(
        ["ssh", "-G", host],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"failed to inspect ssh host `{host}`")
    hostname = None
    for line in completed.stdout.splitlines():
        if line.startswith("hostname "):
            hostname = line.split(None, 1)[1].strip()
            break
    if not hostname:
        raise RuntimeError(f"ssh host `{host}` has no hostname")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    if address.version == 4:
        return f"{hostname}.sslip.io"
    raise RuntimeError("IPv6 ssh hostnames need explicit --target-host")


def redact_observer_report(report: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(report)
    target = cleaned.get("target")
    if isinstance(target, dict):
        cleaned["target"] = {
            "host": "<observer-target>",
            "port": target.get("port"),
            "path": target.get("path"),
        }
    events = cleaned.get("events")
    if isinstance(events, list):
        cleaned["events"] = [redact_observer_event(event) for event in events]
    return cleaned


def redact_observer_event(event: Any) -> Any:
    if not isinstance(event, dict):
        return event
    cleaned = dict(event)
    fields = cleaned.get("fields")
    if isinstance(fields, dict):
        fields = dict(fields)
        if "host" in fields:
            fields["host"] = "<observer-target>"
        if "port" in fields:
            fields["port"] = "<observer-port>"
        cleaned["fields"] = fields
    return cleaned


def append_unique(values: list[str], value: str) -> list[str]:
    if value not in values:
        values.append(value)
    return values
