from __future__ import annotations

import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from common import CommandError, ROOT
from private_probe import write_json


DEFAULT_DNS_NAMES = ["www.cloudflare.com", "chatgpt.com"]
WORKLOAD_PROBE_SCHEMA = "dynet-vm-private-runtime-workload/v1alpha1"
IP_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.:-])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.:-])|"
    r"(?<![A-Za-z0-9_.:-])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]{1,}(?![A-Za-z0-9_.:-])"
)
SERVER_BACKTICK_PATTERN = re.compile(r"(server `)[^`]+(`)")
OUTBOUND_SERVER_PATTERN = re.compile(r"(outbound server )[A-Za-z0-9_.-]+(:\d+)")
SECRET_FIELD_NAMES = {"server", "password", "uuid", "serverIp", "cipher"}
STABILITY_PATTERNS = {
    "receiveWindowChallengeAcks": "segment not in receive window",
    "protocolShortReadErrors": "failed to fill whole buffer",
    "pendingFrameTimeouts": " is not ready",
    "dnsEarlyTimeouts": "Shadowsocks response salt is not ready",
}
SELECTION_EVENT_KINDS = {
    "rule-matched",
    "plan-bypassed",
    "outbound-candidate-set",
    "dialer-cascade-selected",
    "dns-proxy-forward",
    "outbound-attempt-finished",
    "tcp-session-started",
    "tcp-session-attributed",
    "tcp-session-outbound-connecting",
    "tcp-session-established",
    "tcp-session-payload-first-write",
    "tcp-session-payload-received",
    "tcp-session-closed",
    "tcp-session-failed",
    "ip-packet-denied",
    "udp-session-started",
    "udp-session-attributed",
    "udp-session-denied",
    "udp-session-outbound-connecting",
    "udp-session-established",
    "udp-session-payload-sent",
    "udp-session-payload-received",
    "udp-session-closed",
    "udp-session-failed",
}


def task_output_dir(raw: str | None, label: str) -> Path:
    base = (ROOT / ".task" / "resources").resolve(strict=False)
    if raw:
        path = Path(raw).expanduser()
        candidate = path if path.is_absolute() else ROOT / path
    else:
        candidate = base / "vm-private-runtime" / label
    resolved = candidate.resolve(strict=False)
    if resolved != base and base not in resolved.parents:
        raise CommandError(f"output must stay under .task/resources: {candidate}")
    return resolved

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

class StageRecorder:
    def __init__(self, path: Path, label: str) -> None:
        self.path = path
        self.report = {
            "schema": "dynet-vm-private-runtime-stages/v1alpha1",
            "label": label,
            "stages": [],
        }

    def run(self, name: str, action):
        index = len(self.report["stages"])
        stage = {
            "name": name,
            "status": "running",
            "startedAt": utc_now(),
        }
        self.report["stages"].append(stage)
        self._write()
        started = time.monotonic()
        try:
            result = action()
        except Exception as error:
            stage.update(
                {
                    "status": "failed",
                    "finishedAt": utc_now(),
                    "elapsedMs": int((time.monotonic() - started) * 1000),
                    "errorType": type(error).__name__,
                    "error": stage_error(error),
                }
            )
            if isinstance(error, subprocess.CalledProcessError):
                stage["returnCode"] = error.returncode
                stage["stdout"] = sanitize_text(error.stdout or "")
                stage["stderr"] = sanitize_text(error.stderr or "")
            self.report["stages"][index] = stage
            self._write()
            raise
        stage.update(
            {
                "status": "pass",
                "finishedAt": utc_now(),
                "elapsedMs": int((time.monotonic() - started) * 1000),
            }
        )
        self.report["stages"][index] = stage
        self._write()
        return result

    def _write(self) -> None:
        write_json(self.path, sanitize_report(self.report))

def stage_error(error: Exception) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        stderr = (error.stderr or "").strip()
        stdout = (error.stdout or "").strip()
        details = stderr or stdout or str(error)
        return sanitize_text(details)
    return sanitize_text(str(error))

def latest_failed_stage(stage_report: dict) -> str | None:
    for stage in reversed(stage_report.get("stages", [])):
        if stage.get("status") == "failed":
            return str(stage.get("name"))
    return None

def split_host_port(value: str) -> tuple[str, int]:
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)

def sanitize_report(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in SECRET_FIELD_NAMES:
                result[key] = "<redacted>"
            elif key == "address":
                result[key] = "<redacted-ip>"
            else:
                result[key] = sanitize_report(item)
        return result
    if isinstance(value, list):
        return [sanitize_report(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value

def sanitize_text(value: str) -> str:
    value = SERVER_BACKTICK_PATTERN.sub(r"\1<redacted-server>\2", value)
    value = OUTBOUND_SERVER_PATTERN.sub(r"\1<redacted-server>\2", value)
    return IP_PATTERN.sub("<redacted-ip>", value)
