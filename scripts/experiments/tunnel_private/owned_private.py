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
from tunnel_private.owned_private_remote import REMOTE_OWNED_PRIVATE_SERVER
from tunnel_private.reporting import write_owned_private_markdown
from tunnel_private.target_observer import redact_observer_report


OWNED_SCHEMA = "dynet-tunnel-private-owned-private/v1alpha1"
REMOTE_SCHEMA = "dynet-owned-private-remote/v1alpha1"
OWNED_TARGET = "https://<owned-target>/"

ProbeFn = Callable[[argparse.Namespace, Path], dict[str, Any]]
CleanFn = Callable[[dict[str, Any]], dict[str, Any]]
SummaryFn = Callable[[argparse.Namespace, ConfigInputs, dict[str, Any], Path], dict[str, Any]]


def command_observe_owned_private(
    args: argparse.Namespace,
    *,
    inputs: ConfigInputs,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    plan_summary: SummaryFn,
    private_summary: SummaryFn,
) -> int:
    private_host = args.private_host or public_host_from_ssh(args.ssh_host)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cases = []
    with tempfile.TemporaryDirectory(prefix="dynet-owned-private-") as temp_dir:
        temp_root = Path(temp_dir)
        for case in owned_cases():
            cases.append(
                run_owned_case(
                    args,
                    inputs,
                    case,
                    private_host,
                    temp_root,
                    output_dir,
                    run_probe,
                    clean_report,
                    private_summary if case.get("privateDirect") else plan_summary,
                )
            )
    summary = owned_summary(args, inputs, private_host, cases)
    write_json(output_dir / "summary.json", summary)
    write_owned_private_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    return 0


def owned_cases() -> list[dict[str, Any]]:
    return [
        {
            "label": "owned-private-direct",
            "probeMode": "private-direct",
            "privateDirect": True,
            "privateExpected": "single",
            "targetExpected": "single",
        },
        {
            "label": "candidate-direct-owned-target",
            "probeMode": "candidate",
            "privatePath": False,
            "privateExpected": "none",
            "targetExpected": "single",
        },
        {
            "label": "tunnel-owned-private",
            "probeMode": "private",
            "privatePath": True,
            "privateExpected": "candidates",
            "targetExpected": "candidates",
        },
    ]


def run_owned_case(
    base_args: argparse.Namespace,
    inputs: ConfigInputs,
    case: dict[str, Any],
    private_host: str,
    temp_root: Path,
    output_dir: Path,
    run_probe: ProbeFn,
    clean_report: CleanFn,
    summary_fn: SummaryFn,
) -> dict[str, Any]:
    private_expected = expected_count(case["privateExpected"], inputs)
    target_expected = expected_count(case["targetExpected"], inputs)
    server = start_owned_remote(base_args, private_expected, target_expected)
    ready = read_ready(server, base_args.ready_timeout)
    owned_private = owned_private_proxy(private_host, int(ready["privatePort"]), base_args)
    args = owned_case_args(base_args, case, private_host, int(ready["targetPort"]))
    case_dir = output_dir / str(case["label"])
    case_dir.mkdir(parents=True, exist_ok=True)
    config_path = temp_root / f"{case['label']}.json"
    write_json(config_path, owned_case_config(args, inputs, case, owned_private), secret=True)
    report = run_probe(args, config_path)
    report_path = case_dir / "report.json"
    write_json(report_path, redact_observer_report(clean_report(report)))
    probe_summary = summary_fn(args, inputs, report, report_path)
    probe_summary["targetUrl"] = OWNED_TARGET
    remote = finish_owned_remote(server, base_args.server_timeout + 5.0)
    row = owned_case_summary(case, probe_summary, remote, private_expected, target_expected)
    write_json(case_dir / "summary.json", row)
    return row


def owned_case_args(
    base_args: argparse.Namespace,
    case: dict[str, Any],
    private_host: str,
    target_port: int,
) -> argparse.Namespace:
    args = argparse.Namespace(**vars(base_args))
    args.protocol = "tls-handshake"
    args.probe_mode = case["probeMode"]
    args.target_url = f"https://{private_host}:{target_port}/"
    args.domain = append_unique(list(args.domain or []), private_host)
    return args


def owned_private_proxy(host: str, port: int, args: argparse.Namespace) -> dict[str, Any]:
    return {
        "name": "owned-private",
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": "aes-128-gcm",
        "password": args.owned_private_password,
    }


def owned_case_config(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    case: dict[str, Any],
    owned_private: dict[str, Any],
) -> dict[str, Any]:
    if case.get("privateDirect"):
        return build_private_config(owned_private)
    return build_config(
        args,
        inputs.candidates,
        owned_private,
        private_path=bool(case["privatePath"]),
    )


def owned_case_summary(
    case: dict[str, Any],
    probe_summary: dict[str, Any],
    remote: dict[str, Any],
    private_expected: int,
    target_expected: int,
) -> dict[str, Any]:
    signals = owned_signals(remote)
    return {
        "label": case["label"],
        "probeMode": probe_summary["probeMode"],
        "protocol": "tls-handshake",
        "expectedPrivateConnections": private_expected,
        "expectedTargetConnections": target_expected,
        "probe": probe_summary["report"],
        "observer": remote,
        "signals": signals,
    }


def owned_summary(
    args: argparse.Namespace,
    inputs: ConfigInputs,
    private_host: str,
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": OWNED_SCHEMA,
        "ownedPrivate": {
            "hostLength": len(private_host),
            "cipher": "aes-128-gcm",
            "passwordLength": len(args.owned_private_password),
        },
        "metadata": metadata(
            inputs.group,
            inputs.all_candidates,
            inputs.supported_candidates,
            inputs.selected_candidates,
            inputs.candidates,
            owned_private_proxy(private_host, 0, args),
            inputs.resolution,
        ),
        "totals": {
            "cases": len(cases),
            "privateConnections": sum(item["signals"]["privateConnections"] for item in cases),
            "privateDecodedConnections": sum(
                item["signals"]["privateDecodedConnections"] for item in cases
            ),
            "targetConnections": sum(item["signals"]["targetConnections"] for item in cases),
            "targetTlsClientHelloLikeConnections": sum(
                item["signals"]["targetTlsClientHelloLikeConnections"] for item in cases
            ),
        },
        "cases": cases,
        "privacy": {
            "rawPayloadStored": False,
            "peerAddressStored": False,
            "targetHostStored": False,
            "privateHostStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def owned_signals(remote: dict[str, Any]) -> dict[str, int]:
    private_connections = list_rows(remote.get("privateConnections"))
    target_connections = list_rows(remote.get("targetConnections"))
    return {
        "connections": len(target_connections),
        "receivedConnections": sum(
            1 for item in target_connections if int(item.get("receivedBytes") or 0) > 0
        ),
        "sentConnections": sum(
            1 for item in target_connections if int(item.get("sentBytes") or 0) > 0
        ),
        "privateConnections": len(private_connections),
        "privateDecodedConnections": sum(1 for item in private_connections if item.get("decoded")),
        "privateForwardedTargets": sum(
            1 for item in private_connections if item.get("targetConnected")
        ),
        "privateResponseConnections": sum(
            1 for item in private_connections if int(item.get("responseSentBytes") or 0) > 0
        ),
        "targetConnections": len(target_connections),
        "targetReceivedConnections": sum(
            1 for item in target_connections if int(item.get("receivedBytes") or 0) > 0
        ),
        "targetSentConnections": sum(
            1 for item in target_connections if int(item.get("sentBytes") or 0) > 0
        ),
        "targetTlsClientHelloLikeConnections": sum(
            1 for item in target_connections if item.get("tlsClientHelloLike") is True
        ),
    }


def list_rows(value: Any) -> list[dict[str, Any]]:
    return value if isinstance(value, list) else []


def expected_count(value: str, inputs: ConfigInputs) -> int:
    if value == "candidates":
        return len(inputs.candidates)
    if value == "single":
        return 1
    return 0


def start_owned_remote(
    args: argparse.Namespace,
    private_expected: int,
    target_expected: int,
) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [
            "ssh",
            args.ssh_host,
            "python3",
            "-u",
            "-",
            str(private_expected),
            str(target_expected),
            str(args.server_timeout),
            args.owned_private_password,
            args.reply_text,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdin is None:
        raise RuntimeError("failed to open ssh stdin")
    process.stdin.write(REMOTE_OWNED_PRIVATE_SERVER)
    process.stdin.close()
    return process


def read_ready(process: subprocess.Popen[str], timeout: float) -> dict[str, Any]:
    try:
        line = read_line(process, timeout)
    except RuntimeError as error:
        stop_remote(process)
        raise RuntimeError(
            f"{error}; remoteExit={process.returncode}; "
            f"stderrPresent={remote_stderr_present(process)}"
        ) from error
    ready = json.loads(line)
    if ready.get("ready") is not True or ready.get("targetPort") is None:
        raise RuntimeError(f"owned-private remote did not become ready: {line.strip()}")
    return ready


def read_line(process: subprocess.Popen[str], timeout: float) -> str:
    if process.stdout is None:
        raise RuntimeError("owned-private remote stdout is closed")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise RuntimeError("timed out waiting for owned-private remote")
        line = process.stdout.readline()
    finally:
        selector.close()
    if not line:
        raise RuntimeError("owned-private remote exited before readiness")
    return line


def finish_owned_remote(process: subprocess.Popen[str], timeout: float) -> dict[str, Any]:
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_remote(process)
        return {
            "schema": REMOTE_SCHEMA,
            "status": "timeout",
            "privateConnections": [],
            "targetConnections": [],
            "privacy": remote_privacy(),
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
        "privateConnections": [],
        "targetConnections": [],
        "privacy": remote_privacy(),
    }


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


def stop_remote(process: subprocess.Popen[str]) -> None:
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


def remote_privacy() -> dict[str, bool]:
    return {
        "rawPayloadStored": False,
        "peerAddressStored": False,
        "targetHostStored": False,
    }


def public_host_from_ssh(host: str) -> str:
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
    raise RuntimeError("IPv6 ssh hostnames need explicit --private-host")


def append_unique(values: list[str], value: str) -> list[str]:
    if value not in values:
        values.append(value)
    return values
