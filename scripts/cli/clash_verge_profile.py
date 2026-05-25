#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scripts.lib.bootstrap import add_experiments_path

add_experiments_path()

from clash_profile_taxonomy import CATEGORY_PATTERNS, MULTI_SUFFIXES


ACCESS_RE = re.compile(
    r'^\[(?P<wall>[^\]]+)\] time="(?P<ts>[^"]+)" level=(?P<level>\w+) '
    r'msg="\[(?P<proto>[A-Z]+)\] (?P<src>\S+) --> (?P<target>\S+) '
    r'match (?P<match>.+?) using (?P<using>.+)"$'
)
WARNING_RE = re.compile(
    r'^\[(?P<wall>[^\]]+)\] time="(?P<ts>[^"]+)" level=warning '
    r'msg="\[(?P<proto>[A-Z]+)\] dial (?P<policy>.*?) '
    r'\(match (?P<match>.*?)\) (?P<src>\S+) --> (?P<target>\S+) '
    r'error: (?P<error>.+)"$'
)
FRACTIONAL_TIME_RE = re.compile(
    r"^(?P<head>[^.]+)\.(?P<fraction>\d+)(?P<suffix>Z|[+-]\d{2}:\d{2})?$"
)


def parse_target(target: str) -> tuple[str, int | None]:
    if target.startswith("["):
        end = target.find("]")
        if end >= 0:
            host = target[1:end]
            rest = target[end + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host.lower(), int(rest[1:])
            return host.lower(), None
    if ":" in target:
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            return host.rstrip(".").lower(), int(port)
    return target.rstrip(".").lower(), None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ip_bucket(value: str) -> str:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv4Address):
        network = ipaddress.ip_network(f"{address}/24", strict=False)
    else:
        network = ipaddress.ip_network(f"{address}/48", strict=False)
    return f"ip:{network}"


def safe_host(host: str) -> str:
    return ip_bucket(host) if is_ip(host) else host


def site_for(host: str) -> str:
    if host.startswith("ip:"):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    suffix3 = ".".join(labels[-3:])
    if suffix2 in MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    if suffix3 in MULTI_SUFFIXES and len(labels) >= 4:
        return ".".join(labels[-4:])
    return suffix2


def category_for(host: str, site: str) -> str:
    if host.startswith("ip:") or site.startswith("ip:"):
        return "ip-literal"
    text = f"{host} {site}"
    for category, patterns in CATEGORY_PATTERNS:
        if any(pattern in text for pattern in patterns):
            return category
    return "other"


def egress_group(using: str) -> str:
    using = using.strip()
    if using == "DIRECT":
        return "DIRECT"
    if "[" in using:
        return using.split("[", 1)[0].strip() or "proxy"
    return using or "unknown"


def parse_time(value: str) -> dt.datetime | None:
    normalized = normalize_time(value)
    try:
        return dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None


def normalize_time(value: str) -> str:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    match = FRACTIONAL_TIME_RE.match(value)
    if not match:
        return value
    fraction = match.group("fraction")[:6].ljust(6, "0")
    return f"{match.group('head')}.{fraction}{match.group('suffix') or ''}"


def time_bucket(timestamp: dt.datetime | None, minutes: int) -> str | None:
    if timestamp is None:
        return None
    minute = (timestamp.minute // minutes) * minutes
    bucketed = timestamp.replace(minute=minute, second=0, microsecond=0)
    if minutes == 60:
        return bucketed.strftime("%Y-%m-%dT%H:00%z")
    return bucketed.strftime("%Y-%m-%dT%H:%M%z")


def error_reason(error: str) -> str:
    lowered = error.lower()
    if "timeout" in lowered or "deadline exceeded" in lowered or "timed out" in lowered:
        return "timeout"
    if "refused" in lowered:
        return "refused"
    if "reset" in lowered:
        return "reset"
    if "no such host" in lowered or "dns" in lowered:
        return "dns"
    if "tls" in lowered:
        return "tls"
    return "other"


def iter_log_files(log_dir: Path) -> list[Path]:
    return sorted((log_dir / "service").glob("*.log"))


def access_event(row: dict[str, str]) -> dict[str, Any]:
    host, port = parse_target(row["target"])
    host = safe_host(host)
    timestamp = parse_time(row["ts"])
    site = site_for(host)
    return {
        "ts": row["ts"],
        "hour": time_bucket(timestamp, 60),
        "window5m": time_bucket(timestamp, 5),
        "proto": row["proto"],
        "host": host,
        "site": site,
        "port": port,
        "match": row["match"],
        "egress": egress_group(row["using"]),
        "category": category_for(host, site),
    }


def warning_event(row: dict[str, str]) -> dict[str, Any]:
    host, port = parse_target(row["target"])
    host = safe_host(host)
    timestamp = parse_time(row["ts"])
    site = site_for(host)
    return {
        "ts": row["ts"],
        "hour": time_bucket(timestamp, 60),
        "window5m": time_bucket(timestamp, 5),
        "proto": row["proto"],
        "host": host,
        "site": site,
        "port": port,
        "match": row["match"],
        "egress": row["policy"].strip() or "unknown",
        "category": category_for(host, site),
        "reason": error_reason(row["error"]),
    }


def parse_log_line(line: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    match = ACCESS_RE.match(line)
    if match:
        return "access", access_event(match.groupdict())
    match = WARNING_RE.match(line)
    if match:
        return "warning", warning_event(match.groupdict())
    return None, None


def access_key(row: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (row["ts"], row["proto"], row["host"], str(row["port"]), row["egress"])


def parse_logs(paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    events = []
    errors = []
    seen = set()
    lines = 0
    for path in paths:
        for line in path.read_text(errors="replace").splitlines():
            lines += 1
            kind, row = parse_log_line(line)
            if kind == "access":
                key = access_key(row)
                if key in seen:
                    continue
                seen.add(key)
                events.append(row)
                continue
            if kind == "warning":
                errors.append(row)
    return events, errors, lines


def top(counter: Counter[str], limit: int = 20) -> list[dict[str, Any]]:
    return [{"key": key, "count": count} for key, count in counter.most_common(limit)]


def time_distribution(counter: Counter[str], limit: int = 500) -> list[dict[str, Any]]:
    return [{"key": key, "count": counter[key]} for key in sorted(counter)[:limit]]


def top_domains(events: list[dict[str, Any]], errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    error_count = Counter(row["host"] for row in errors)
    for row in events:
        by_host[row["host"]].append(row)
    ranked = sorted(by_host.items(), key=lambda item: len(item[1]), reverse=True)
    output = []
    for host, rows in ranked[:80]:
        windows = Counter(row["window5m"] for row in rows if row.get("window5m"))
        hours = Counter(row["hour"] for row in rows if row.get("hour"))
        output.append(
            {
                "domain": host,
                "site": rows[0]["site"],
                "category": rows[0]["category"],
                "count": len(rows),
                "errors": error_count[host],
                "protocols": sorted({row["proto"] for row in rows}),
                "ports": sorted({row["port"] for row in rows if row["port"] is not None}),
                "egressGroups": sorted({row["egress"] for row in rows}),
                "matches": sorted({row["match"] for row in rows}),
                "firstSeen": min(row["ts"] for row in rows),
                "lastSeen": max(row["ts"] for row in rows),
                "activeHours": len(hours),
                "activeWindows5m": len(windows),
                "maxPer5m": max(windows.values()) if windows else 0,
            }
        )
    return output


def top_sites(events: list[dict[str, Any]], errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_site: dict[str, list[dict[str, Any]]] = defaultdict(list)
    site_errors = Counter(row["site"] for row in errors)
    for row in events:
        by_site[row["site"]].append(row)
    ranked = sorted(by_site.items(), key=lambda item: len(item[1]), reverse=True)
    output = []
    for site, rows in ranked[:50]:
        domains = Counter(row["host"] for row in rows)
        categories = Counter(row["category"] for row in rows)
        windows = Counter(row["window5m"] for row in rows if row.get("window5m"))
        hours = Counter(row["hour"] for row in rows if row.get("hour"))
        output.append(
            {
                "site": site,
                "category": categories.most_common(1)[0][0],
                "count": len(rows),
                "errors": site_errors[site],
                "topDomains": [key for key, _ in domains.most_common(8)],
                "egressGroups": sorted({row["egress"] for row in rows}),
                "matches": sorted({row["match"] for row in rows}),
                "activeHours": len(hours),
                "activeWindows5m": len(windows),
                "maxPer5m": max(windows.values()) if windows else 0,
            }
        )
    return output


def sample_pools(domains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_category: dict[str, list[str]] = defaultdict(list)
    for item in domains:
        domain = item["domain"]
        if not domain.startswith("ip:"):
            by_category[item["category"]].append(domain)
    pools = []
    for name, weight, purpose in pool_definitions():
        pool_domains = []
        if name == "long-tail":
            pool_domains = [
                item["domain"]
                for item in domains[20:100]
                if not item["domain"].startswith("ip:")
            ]
        else:
            for category in pool_categories(name):
                pool_domains.extend(by_category.get(category, []))
        pools.append(
            {
                "name": name,
                "weight": weight,
                "purpose": purpose,
                "domains": unique(pool_domains)[:24],
                "probeModes": ["dns", "tcp-connect", "tls-handshake", "https-head"],
            }
        )
    return pools


def pool_definitions() -> list[tuple[str, int, str]]:
    return [
        ("ai-critical", 20, "AI/chat paths; proxy quality and DNS correctness matter"),
        ("developer-critical", 20, "GitHub/dev tooling; high-frequency route stability"),
        ("work-direct", 15, "work/corp direct paths; should avoid unnecessary proxying"),
        ("media-cn-direct", 10, "CN media/music paths; validate direct and low side effects"),
        ("platform-background", 10, "Apple/Google/Microsoft background services"),
        ("long-tail", 5, "low-frequency domains for regression sampling"),
    ]


def pool_categories(name: str) -> tuple[str, ...]:
    return {
        "ai-critical": ("ai",),
        "developer-critical": ("developer",),
        "work-direct": ("work",),
        "media-cn-direct": ("music-media-cn",),
        "platform-background": ("apple", "google", "microsoft"),
    }.get(name, ("other",))


def unique(values: list[str]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def build_report(
    log_dir: Path,
    paths: list[Path],
    events: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    lines: int,
) -> dict[str, Any]:
    domains = top_domains(events, errors)
    timestamps = [row["ts"] for row in events]
    return {
        "schema": "dynet-clash-verge-access-profile/v1alpha1",
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "privacy": {
            "rawLinesStored": False,
            "sourceAddressesStored": False,
            "sourcePortsStored": False,
            "nodeNamesStored": False,
            "urlPathsStored": False,
            "note": "Only aggregated domains/sites/rules/egress groups/time buckets are stored.",
        },
        "source": {
            "logDir": str(log_dir).replace(str(Path.home()), "~"),
            "files": len(paths),
            "linesScanned": lines,
            "firstSeen": min(timestamps) if timestamps else None,
            "lastSeen": max(timestamps) if timestamps else None,
        },
        "summary": {
            "events": len(events),
            "errors": len(errors),
            "uniqueDomains": len({row["host"] for row in events}),
            "uniqueSites": len({row["site"] for row in events}),
        },
        "distribution": {
            "byProtocol": top(Counter(row["proto"] for row in events)),
            "byPort": top(Counter(str(row["port"]) for row in events if row["port"])),
            "byCategory": top(Counter(row["category"] for row in events)),
            "byEgressGroup": top(Counter(row["egress"] for row in events)),
            "byMatch": top(Counter(row["match"] for row in events)),
            "byHour": time_distribution(Counter(row["hour"] for row in events if row["hour"])),
            "byFiveMinute": time_distribution(
                Counter(row["window5m"] for row in events if row["window5m"]),
            ),
        },
        "topDomains": domains,
        "topSites": top_sites(events, errors),
        "errors": {
            "byReason": top(Counter(row["reason"] for row in errors)),
            "byDomain": top(Counter(row["host"] for row in errors)),
            "byEgressGroup": top(Counter(row["egress"] for row in errors)),
            "byHour": time_distribution(Counter(row["hour"] for row in errors if row["hour"])),
            "byFiveMinute": time_distribution(
                Counter(row["window5m"] for row in errors if row["window5m"]),
            ),
        },
        "experimentProfile": {
            "seedBasis": "stable random seed should be supplied by the experiment harness",
            "samplePools": sample_pools(domains),
        },
    }


def write_markdown(report: dict[str, Any], output: Path) -> None:
    lines = [
        "# Clash Verge Access Profile",
        "",
        "Generated from local Clash Verge Rev service logs. Stores aggregates only.",
        "",
        "## Summary",
        "",
        f"- Window: `{report['source']['firstSeen']}` to `{report['source']['lastSeen']}`",
        f"- Events: `{report['summary']['events']}`",
        f"- Errors: `{report['summary']['errors']}`",
        f"- Unique domains: `{report['summary']['uniqueDomains']}`",
        f"- Unique sites: `{report['summary']['uniqueSites']}`",
        "",
        "## Category Mix",
        "",
    ]
    for item in report["distribution"]["byCategory"]:
        lines.append(f"- `{item['key']}`: {item['count']}")
    lines.extend(["", "## Egress Mix", ""])
    for item in report["distribution"]["byEgressGroup"]:
        lines.append(f"- `{item['key']}`: {item['count']}")
    if report["distribution"]["byHour"]:
        lines.extend(["", "## Hourly Events", ""])
        for item in report["distribution"]["byHour"][:24]:
            lines.append(f"- `{item['key']}`: {item['count']}")
    lines.extend(["", "## Top Sites", ""])
    for item in report["topSites"][:20]:
        egress = ",".join(item["egressGroups"])
        lines.append(
            f"- `{item['site']}` [{item['category']}]: {item['count']} events, "
            f"{item['errors']} errors, active5m={item['activeWindows5m']}, "
            f"max5m={item['maxPer5m']}, egress={egress}"
        )
    lines.extend(["", "## Experiment Pools", ""])
    for pool in report["experimentProfile"]["samplePools"]:
        domains = ", ".join(f"`{domain}`" for domain in pool["domains"])
        lines.extend(
            [
                f"### {pool['name']}",
                "",
                f"- Weight: {pool['weight']}",
                f"- Purpose: {pool['purpose']}",
                f"- Domains: {domains}",
                "",
            ]
        )
    output.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--log-dir",
        default=Path.home()
        / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/logs",
    )
    parser.add_argument(
        "--output-json",
        default=".task/resources/clash-verge-access-profile.json",
    )
    parser.add_argument(
        "--output-md",
        default=".task/resources/clash-verge-access-profile.md",
    )
    args = parser.parse_args()

    log_dir = Path(args.log_dir).expanduser()
    paths = iter_log_files(log_dir)
    events, errors, lines = parse_logs(paths)
    report = build_report(log_dir, paths, events, errors, lines)
    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    write_markdown(report, Path(args.output_md))
    print(json.dumps(report["summary"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
