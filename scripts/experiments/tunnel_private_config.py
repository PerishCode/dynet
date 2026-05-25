from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tunnel_private.config.shape import (
    CONFIG_SCHEMA,
    dynet_proxy,
    dynet_trojan,
    metadata,
    safe_proxy,
    with_trojan_interface_name,
)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

CLASH_DIR = Path.home() / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"
MERGED_CONFIG = CLASH_DIR / "clash-verge.yaml"
PROVIDER_DIR = CLASH_DIR / "proxy-providers"
DEFAULT_DOH_CHAIN = {
    "tag": "alidns-doh",
    "type": "doh",
    "endpoint": "https://dns.alidns.com/dns-query",
    "bootstrapIps": ["223.5.5.5", "223.6.6.6"],
}

@dataclass
class ConfigInputs:
    group: dict[str, Any]
    all_candidates: list[dict[str, Any]]
    supported_candidates: list[dict[str, Any]]
    selected_candidates: list[dict[str, Any]]
    candidates: list[dict[str, Any]]
    private: dict[str, Any]
    resolution: dict[str, Any]


def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise SystemExit("PyYAML is required: uv --project scripts sync")
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise SystemExit(f"YAML root must be an object: {path}")
    return data


def write_json(path: Path, data: Any, secret: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
    if secret:
        os.chmod(path, 0o600)


def candidate_tag_offset(args: argparse.Namespace) -> int:
    return int(getattr(args, "candidate_offset", 0) or 0)


def tunnel_group(config: dict[str, Any], name: str) -> dict[str, Any]:
    for group in config.get("proxy-groups", []):
        if isinstance(group, dict) and group.get("name") == name:
            return group
    raise SystemExit(f"missing proxy group `{name}`")


def provider_path(provider_dir: Path, name: str) -> Path:
    path = provider_dir / f"{name}.yaml"
    if path.exists():
        return path
    raise SystemExit(f"missing proxy provider `{name}` at {path}")


def load_provider(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    proxies = data.get("proxies", [])
    return [item for item in proxies if isinstance(item, dict)]


def selected_tunnel_proxies(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    merged = load_yaml(Path(args.merged_config))
    group = tunnel_group(merged, args.tunnel_name)
    names = set(item for item in group.get("proxies", []) if isinstance(item, str))
    filter_text = args.filter if args.filter is not None else group.get("filter")
    pattern = re.compile(filter_text) if filter_text else None
    proxies = []
    for provider in group.get("use", []):
        for proxy in load_provider(provider_path(Path(args.provider_dir), str(provider))):
            name = str(proxy.get("name", ""))
            if names and name not in names:
                continue
            if pattern and not pattern.search(name):
                continue
            proxies.append(proxy)
    return group, proxies


def private_proxy(args: argparse.Namespace) -> dict[str, Any]:
    proxies = load_provider(Path(args.private_provider))
    selected = None
    for proxy in proxies:
        name = str(proxy.get("name", ""))
        if args.private_name and name == args.private_name:
            selected = proxy
            break
        if not args.private_name and args.private_contains in name:
            selected = proxy
            break
    if selected is None and len(proxies) == 1:
        selected = proxies[0]
    if selected is None:
        raise SystemExit("private provider did not contain one unambiguous node")
    selected = dict(selected)
    if args.private_server_ip:
        selected["server-ip"] = args.private_server_ip
    elif args.resolve_private_server:
        selected["server-ip"] = resolve_host(str(selected["server"]))
    selected = with_trojan_interface_name(selected, getattr(args, "trojan_interface_name", None))
    return selected


def resolve_host(host: str) -> str:
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as error:
        raise SystemExit(f"failed to resolve private server `{host}`: {error}") from error
    addresses = [item[4][0] for item in answers]
    for address in addresses:
        if "." in address:
            return address
    if addresses:
        return addresses[0]
    raise SystemExit(f"private server `{host}` resolved to no addresses")


def resolve_host_for_port(host: str, port: int) -> str:
    addresses = public_resolve_host(host)
    for address in addresses:
        try:
            with socket.create_connection((address, port), timeout=3):
                return address
        except OSError:
            continue
    if addresses:
        return addresses[0]
    raise SystemExit(f"server `{host}` resolved to no public addresses")


def public_resolve_host(host: str) -> list[str]:
    addresses = doh_a_records(host)
    if not addresses:
        addresses = system_addresses(host)
    return [address for address in unique(addresses) if is_global_ip(address)]


def doh_a_records(host: str) -> list[str]:
    query = urllib.parse.urlencode({"name": host, "type": "A"})
    request = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?{query}",
        headers={"accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return []
    answers = data.get("Answer", [])
    return [
        str(item.get("data"))
        for item in answers
        if isinstance(item, dict) and item.get("type") == 1 and item.get("data")
    ]


def system_addresses(host: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as error:
        raise SystemExit(f"failed to resolve server `{host}`: {error}") from error
    return [item[4][0] for item in answers]


def unique(values: list[str]) -> list[str]:
    rows = []
    for value in values:
        if value not in rows:
            rows.append(value)
    return rows


def is_global_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def supported_tunnel(proxy: dict[str, Any], supported: set[str]) -> bool:
    kind = str(proxy.get("type", "")).lower()
    network = str(proxy.get("network") or "tcp").lower()
    return kind in supported and network in {"", "tcp"}


def build_config(
    args: argparse.Namespace,
    candidates: list[dict[str, Any]],
    private: dict[str, Any],
    tag_offset: int = 0,
    private_path: bool = True,
) -> dict[str, Any]:
    outbounds: list[dict[str, Any]] = [{"tag": "direct", "type": "direct"}]
    edges = []
    for index, proxy in enumerate(candidates, start=1):
        tag = f"tunnel-{tag_offset + index:03d}"
        outbounds.append(dynet_proxy(proxy, tag))
        edges.append({"type": "candidate", "to": tag})
    outbounds.append(
        {
            "tag": "tunnel",
            "type": "plan",
            "capabilities": ["tcp", "dns", "domain-target", "ip-target", "probeable"],
            "payload": {
                "strategy": {
                    "source": "internal",
                    "key": args.strategy_key,
                    "version": "",
                    "options": {},
                },
                "selection": {"edges": edges},
            },
        }
    )
    rules = []
    routes = [{"outbound": "tunnel"}]
    if private_path:
        outbounds.extend(
            [
                dynet_proxy(private, "private"),
                {
                    "tag": "private-via-tunnel",
                    "type": "dialer",
                    "payload": {"bound": "tunnel", "target": "private"},
                },
            ]
        )
        if getattr(args, "tcp_route_plan_private", False):
            routes = tcp_private_routes(args.domain_suffix, args.domain, "private-via-tunnel")
            routes.append({"outbound": "direct"})
        else:
            rules = user_rules(args.domain_suffix, args.domain, "private-via-tunnel")
            routes = [{"outbound": "direct"}]
    return {
        "dns": default_dns_config(),
        "inbounds": [{"tag": "tun-in", "type": "tun"}],
        "outbounds": outbounds,
        "rules": rules,
        "routes": routes,
    }


def build_private_config(private: dict[str, Any]) -> dict[str, Any]:
    return {
        "dns": default_dns_config(),
        "inbounds": [{"tag": "tun-in", "type": "tun"}],
        "outbounds": [dynet_proxy(private, "private")],
        "routes": [{"outbound": "private"}],
    }


def default_dns_config() -> dict[str, Any]:
    return {"chains": [dict(DEFAULT_DOH_CHAIN)]}


def user_rules(suffixes: list[str], domains: list[str], outbound: str) -> list[dict[str, Any]]:
    rules = []
    for index, value in enumerate(domains, start=1):
        rules.append({"tag": f"identity-domain-{index}", "domain": value, "outbound": outbound})
    for index, value in enumerate(suffixes, start=1):
        rules.append({"tag": f"identity-suffix-{index}", "domainSuffix": value, "outbound": outbound})
    return rules

def tcp_private_routes(suffixes: list[str], domains: list[str], outbound: str) -> list[dict[str, Any]]:
    def route(key: str, value: str) -> dict[str, Any]:
        return {"inbound": "tun-in", "transport": "tcp", key: value, "outbound": outbound}
    return [route("domain", value) for value in domains] + [route("domainSuffix", value) for value in suffixes]

def config_inputs(args: argparse.Namespace) -> ConfigInputs:
    group, all_candidates = selected_tunnel_proxies(args)
    supported = set(args.supported_type or ["vmess", "trojan"])
    offset = int(getattr(args, "candidate_offset", 0) or 0)
    supported_candidates = [item for item in all_candidates if supported_tunnel(item, supported)]
    selected_candidates = list(supported_candidates[offset:])
    if args.limit:
        selected_candidates = selected_candidates[: args.limit]
    candidates = selected_candidates
    skipped: list[dict[str, Any]] = []
    if args.resolve_tunnel_server:
        candidates, skipped = resolve_tunnel_candidates(selected_candidates)
    candidates = [
        with_trojan_interface_name(candidate, getattr(args, "trojan_interface_name", None))
        for candidate in candidates
    ]
    if not candidates:
        if args.resolve_tunnel_server and skipped:
            raise SystemExit(
                "no usable Tunnel candidates after bootstrap resolution; "
                f"skipped {len(skipped)} candidate(s)"
            )
        raise SystemExit("no supported Tunnel candidates after filtering")
    return ConfigInputs(
        group=group,
        all_candidates=all_candidates,
        supported_candidates=supported_candidates,
        selected_candidates=selected_candidates,
        candidates=candidates,
        private=private_proxy(args),
        resolution=resolution_metadata(
            args.resolve_tunnel_server,
            supported_candidates,
            selected_candidates,
            candidates,
            skipped,
            offset,
            args.limit,
        ),
    )


def resolve_tunnel_candidates(
    candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    resolved = []
    skipped = []
    for index, proxy in enumerate(candidates, start=1):
        try:
            resolved.append(with_resolved_server_ip(proxy))
        except SystemExit as error:
            skipped.append(resolution_skip(proxy, index, error))
        except (KeyError, TypeError, ValueError) as error:
            skipped.append(resolution_skip(proxy, index, error))
    return resolved, skipped


def resolution_metadata(
    enabled: bool,
    supported: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    usable: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
    offset: int,
    limit: int | None,
) -> dict[str, Any]:
    return {
        "enabled": bool(enabled),
        "source": "cloudflare-doh-then-system",
        "policy": "skip-unusable-candidate-fail-when-empty",
        "input": len(selected),
        "usable": len(usable),
        "skipped": len(skipped),
        "selection": {
            "candidateOffset": offset,
            "candidateLimit": limit,
            "supportedBeforeOffset": len(supported),
            "selectedBeforeResolution": len(selected),
        },
        "skippedCandidates": skipped,
    }


def resolution_skip(proxy: dict[str, Any], index: int, error: BaseException) -> dict[str, Any]:
    error_type = resolution_error_type(error)
    return {
        "sourceIndex": index,
        "sourceTag": f"tunnel-source-{index:03d}",
        "candidate": safe_proxy(proxy, f"tunnel-source-{index:03d}"),
        "errorType": error_type,
        "reason": resolution_reason(error_type),
    }


def resolution_error_type(error: BaseException) -> str:
    message = str(error)
    if isinstance(error, (KeyError, TypeError, ValueError)):
        return "candidate-invalid"
    if "resolved to no public addresses" in message:
        return "no-public-address"
    if "failed to resolve" in message:
        return "resolve-failed"
    return "bootstrap-resolution-failed"


def resolution_reason(error_type: str) -> str:
    if error_type == "candidate-invalid":
        return "candidate is missing or has invalid bootstrap fields"
    if error_type == "no-public-address":
        return "candidate bootstrap resolved to no usable public address"
    if error_type == "resolve-failed":
        return "candidate bootstrap name resolution failed"
    return "candidate bootstrap resolution failed"


def with_resolved_server_ip(proxy: dict[str, Any]) -> dict[str, Any]:
    proxy = dict(proxy)
    if not (proxy.get("server-ip") or proxy.get("serverIp")):
        proxy["server-ip"] = resolve_host_for_port(str(proxy["server"]), int(proxy["port"]))
    return proxy
