from __future__ import annotations

import datetime as dt
import json
from collections import Counter
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

def observer_model(timeout_seconds: float) -> dict[str, Any]:
    return {
        "name": OBSERVER_VERSION,
        "errorTaxonomy": ERROR_TAXONOMY_VERSION,
        "targetPolicy": TARGET_POLICY_VERSION,
        "timeoutPerStageMs": int(timeout_seconds * 1000),
        "identitySurface": "zero-identity",
        "httpRequestTarget": HTTP_REQUEST_TARGET,
    }

def percentile(values: list[int], target: int) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * (target / 100))
    return ordered[index]

def top(counter: Counter[str], limit: int = 20) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]

def run_output_dir(root: Path, environment: str, seed: str, label: str | None) -> Path:
    safe_env = safe_name(environment)
    safe_seed = safe_name(seed)[:24]
    suffix = safe_name(label) if label else dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / f"{suffix}-{safe_env}-{safe_seed}"

def safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "-" for char in value)
    return cleaned.strip(".-_") or "run"
