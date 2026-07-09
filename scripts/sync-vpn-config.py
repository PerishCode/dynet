#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
import sys
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VPN_CONFIG = ROOT.parent / "vpn-config"
DEFAULT_OUTPUT = ROOT / "dynet.toml"
CLASH_SOURCE = Path("sources/clash")
PROFILE = "mac.yaml"
PROVIDER_SOURCES = {
    "airport": ("proxy-provider", "airport.yaml"),
    "private": ("profile-proxies", "perish.yml"),
}
ROUTED_RULESETS = {
    "bulk": "Common",
    "common": "Common",
    "github": "GitHub",
    "tunnel": "Tunnel",
    "direct": "Direct",
}
FALLBACK_ROUTE_SUFFIXES = {
    "geojs.io",
    "ifconfig.me",
    "ip2location.com",
    "ip.sb",
    "ipify.org",
    "ipinfo.io",
    "iplocation.net",
    "db-ip.com",
}
SUPPORTED_NODE_TYPES = {"ss", "trojan", "vmess", "vless"}


def toml_string(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def load_yaml(path):
    with path.open() as handle:
        return yaml.safe_load(handle) or {}


def slug(value, fallback):
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-._")
    return text or fallback


class PublicResolver:
    def __init__(self):
        self.cache = {}

    def resolve(self, value):
        text = str(value)
        if text in self.cache:
            return self.cache[text]
        try:
            address = ipaddress.ip_address(text)
            if address.is_global:
                self.cache[text] = text
                return text
        except ValueError:
            pass

        query = urllib.parse.urlencode({"name": text, "type": "A"})
        request = urllib.request.Request(
            f"https://cloudflare-dns.com/dns-query?{query}",
            headers={"accept": "application/dns-json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
        for answer in payload.get("Answer", []):
            if answer.get("type") != 1:
                continue
            try:
                address = ipaddress.ip_address(str(answer.get("data")))
            except ValueError:
                continue
            if address.is_global:
                self.cache[text] = str(address)
                return str(address)
        raise ValueError(f"failed to resolve public A record for node server {text!r}")


def node_id(provider, index, node):
    name = slug(node.get("name"), f"node-{index + 1}")
    return f"{provider}-{index + 1:03d}-{name}"


def common_node_fields(node, resolver):
    server = resolver.resolve(node["server"])
    return [
        ("server", server),
        ("port", int(node["port"])),
        ("udp", True),
    ]


def convert_ss(node, resolver):
    fields = [("type", "shadowsocks"), *common_node_fields(node, resolver)]
    fields.extend(
        [
            ("method", node.get("cipher")),
            ("password", node.get("password")),
        ]
    )
    return fields


def convert_trojan(node, resolver):
    fields = [("type", "trojan"), *common_node_fields(node, resolver)]
    fields.append(("password", node.get("password")))
    sni = node.get("sni") or node.get("servername")
    if sni:
        fields.append(("sni", sni))
    if node.get("skip-cert-verify") is not None:
        fields.append(("skip-cert-verify", bool(node.get("skip-cert-verify"))))
    return fields


def convert_vmess(node, resolver):
    if node.get("alterId") not in (0, "0"):
        raise ValueError("vmess alterId is not 0")
    if node.get("cipher") != "auto":
        raise ValueError("vmess cipher is not auto")
    if node.get("network") not in (None, "tcp"):
        raise ValueError("vmess network is not tcp")
    if node.get("tls") is True:
        raise ValueError("vmess tls is not supported")
    fields = [("type", "vmess"), *common_node_fields(node, resolver)]
    fields.extend(
        [
            ("uuid", node.get("uuid")),
            ("alterId", 0),
            ("cipher", "auto"),
        ]
    )
    return fields


def convert_vless(node, resolver):
    if node.get("flow") != "xtls-rprx-vision":
        raise ValueError("vless flow is not xtls-rprx-vision")
    if node.get("network") not in (None, "tcp"):
        raise ValueError("vless network is not tcp")
    if node.get("tls") is not True:
        raise ValueError("vless tls is not true")
    reality = node.get("reality-opts") or {}
    public_key = reality.get("public-key")
    short_id = reality.get("short-id")
    servername = node.get("sni") or node.get("servername")
    if not public_key or short_id is None or not servername:
        raise ValueError("vless reality fields are incomplete")
    fields = [("type", "vless"), *common_node_fields(node, resolver)]
    fields.extend(
        [
            ("uuid", node.get("uuid")),
            ("flow", "xtls-rprx-vision"),
            ("network", "tcp"),
            ("tls", True),
            ("servername", servername),
            ("client-fingerprint", node.get("client-fingerprint") or "chrome"),
            ("reality-opts.public-key", public_key),
            ("reality-opts.short-id", short_id),
        ]
    )
    return fields


CONVERTERS = {
    "ss": convert_ss,
    "trojan": convert_trojan,
    "vmess": convert_vmess,
    "vless": convert_vless,
}


def load_nodes(vpn_config, resolver):
    converted = {"airport": [], "private": []}
    skipped = Counter()
    skip_reasons = Counter()
    used_ids = set()

    for provider in converted:
        nodes = load_provider_nodes(vpn_config, provider)
        for index, node in enumerate(nodes):
            kind = node.get("type")
            if kind not in SUPPORTED_NODE_TYPES:
                skipped[kind or "unknown"] += 1
                continue
            if node.get("udp") is not True:
                skipped[f"{kind}:udp-disabled"] += 1
                continue
            try:
                fields = CONVERTERS[kind](node, resolver)
            except Exception as error:
                skipped[kind] += 1
                skip_reasons[str(error)] += 1
                continue
            base_id = node_id(provider, index, node)
            candidate_id = base_id
            suffix = 2
            while candidate_id in used_ids:
                candidate_id = f"{base_id}-{suffix}"
                suffix += 1
            used_ids.add(candidate_id)
            converted[provider].append((candidate_id, fields))
    return converted, skipped, skip_reasons


def load_provider_nodes(vpn_config, provider):
    source_kind, source_name = PROVIDER_SOURCES[provider]
    if source_kind == "proxy-provider":
        payload = load_yaml(vpn_config / CLASH_SOURCE / "proxy-providers" / source_name)
    elif source_kind == "profile-proxies":
        payload = load_yaml(vpn_config / CLASH_SOURCE / source_name)
    else:
        raise ValueError(f"unsupported provider source {source_kind!r}")
    return payload.get("proxies") or []


def parse_rule(line):
    parts = [part.strip() for part in str(line).split(",") if part.strip()]
    if len(parts) < 2:
        raise ValueError("rule is incomplete")
    kind, value = parts[0], parts[1]
    if kind == "DOMAIN-SUFFIX":
        return "domain-suffix", value.lstrip(".")
    if kind == "DOMAIN":
        return "domain-exact", value
    if kind == "IP-CIDR":
        return "ip-cidr", value
    raise ValueError(f"unsupported rule kind {kind}")


def load_rules(vpn_config):
    rule_dir = vpn_config / CLASH_SOURCE / "rule-providers"
    rules = []
    skipped = Counter()
    priority = 100_000
    for ruleset, group in ROUTED_RULESETS.items():
        payload = load_yaml(rule_dir / f"{ruleset}.yaml").get("payload") or []
        for index, line in enumerate(payload, start=1):
            try:
                matcher, value = parse_rule(line)
            except ValueError as error:
                skipped[str(error)] += 1
                continue
            if matcher in {"domain-exact", "domain-suffix"} and value in FALLBACK_ROUTE_SUFFIXES:
                skipped["fallback-owned-domain"] += 1
                continue
            rules.append(
                {
                    "id": f"{ruleset}-{index:04d}",
                    "priority": priority,
                    "match": matcher,
                    "value": value,
                    "group": group,
                }
            )
            priority -= 1
    reject_count = len(load_yaml(rule_dir / "reject.yaml").get("payload") or [])
    audit_ignore_count = len(load_yaml(rule_dir / "audit-ignore.yaml").get("payload") or [])
    return rules, skipped, reject_count, audit_ignore_count


def write_node(handle, node_id_value, fields):
    handle.write("\n[[forwarding.nodes]]\n")
    handle.write(f"id = {toml_string(node_id_value)}\n")
    reality_fields = []
    for key, value in fields:
        if key.startswith("reality-opts."):
            reality_fields.append((key.rsplit(".", 1)[1], value))
            continue
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, int):
            rendered = str(value)
        else:
            rendered = toml_string(value)
        handle.write(f"{key} = {rendered}\n")
    if reality_fields:
        handle.write("\n[forwarding.nodes.reality-opts]\n")
        for key, value in reality_fields:
            handle.write(f"{key} = {toml_string(value)}\n")


def write_group(handle, group_id, members, next_group=None):
    handle.write("\n[[forwarding.groups]]\n")
    handle.write(f"id = {toml_string(group_id)}\n")
    handle.write('mode = "smart"\n')
    if next_group:
        handle.write(f"next = {toml_string(next_group)}\n")
    handle.write("members = [")
    handle.write(", ".join(toml_string(member) for member in members))
    handle.write("]\n")


def write_rule(handle, rule):
    handle.write("\n[[forwarding.rules]]\n")
    handle.write(f"id = {toml_string(rule['id'])}\n")
    handle.write(f"priority = {rule['priority']}\n")
    handle.write(f"match = {toml_string(rule['match'])}\n")
    handle.write(f"value = {toml_string(rule['value'])}\n")
    handle.write(f"group = {toml_string(rule['group'])}\n")


def write_config(output, nodes, rules):
    airport_ids = [node_id for node_id, _ in nodes["airport"]]
    private_ids = [node_id for node_id, _ in nodes["private"]]
    if not airport_ids:
        raise SystemExit("no dynet-compatible airport nodes found")
    if not private_ids:
        raise SystemExit("no dynet-compatible private nodes found")

    with output.open("w") as handle:
        handle.write(
            """[control]
bind = "127.0.0.1:9977"

[ingress.dns]
bind = "127.0.0.1:1053"

[ingress.tcp]
bind = "127.0.0.1:18080"
upstream = "93.184.216.34:80"
max_sessions = 1024

[ingress.udp]
bind = "127.0.0.1:18443"
upstream = "1.1.1.1:443"
idle_timeout_ms = 30000
max_sessions = 1024

[ingress.socks5]
bind = "127.0.0.1:11080"
udp_advertise_ip = "192.168.5.2"
udp_idle_timeout_ms = 30000
max_sessions = 1024

[forwarding]
default_group = "Tunnel"
dns_race_timeout_ms = 5000

[[forwarding.dns_upstreams]]
id = "cloudflare-doh"
type = "https"
address = "1.1.1.1:443"
host = "cloudflare-dns.com"
path = "/dns-query"
priority = 0
"""
        )
        write_node(handle, "direct-node", [("type", "direct")])
        for provider_nodes in nodes.values():
            for node_id_value, fields in provider_nodes:
                write_node(handle, node_id_value, fields)
        write_group(handle, "Direct", ["direct-node"])
        write_group(handle, "Common", airport_ids)
        write_group(handle, "GitHub", airport_ids)
        write_group(handle, "Tunnel", airport_ids, next_group="Private")
        write_group(handle, "Private", private_ids)
        for rule in rules:
            write_rule(handle, rule)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate local dynet.toml from ../vpn-config Clash sources."
    )
    parser.add_argument("--vpn-config", type=Path, default=DEFAULT_VPN_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main():
    args = parse_args()
    vpn_config = args.vpn_config.resolve()
    output = args.output.resolve()
    resolver = PublicResolver()
    nodes, skipped_nodes, skip_reasons = load_nodes(vpn_config, resolver)
    rules, skipped_rules, reject_count, audit_ignore_count = load_rules(vpn_config)
    write_config(output, nodes, rules)
    print(
        "generated dynet.toml: "
        f"airport_nodes={len(nodes['airport'])} "
        f"private_nodes={len(nodes['private'])} "
        f"rules={len(rules)} "
        f"skipped_nodes={sum(skipped_nodes.values())} "
        f"skipped_rules={sum(skipped_rules.values())} "
        f"reject_rules_skipped={reject_count} "
        f"audit_ignore_rules_not_routed={audit_ignore_count}",
        file=sys.stderr,
    )
    if skipped_nodes:
        print(f"skipped node kinds: {dict(sorted(skipped_nodes.items()))}", file=sys.stderr)
    if skip_reasons:
        print(f"skipped node reasons: {dict(sorted(skip_reasons.items()))}", file=sys.stderr)
    if skipped_rules:
        print(f"skipped rule reasons: {dict(sorted(skipped_rules.items()))}", file=sys.stderr)


if __name__ == "__main__":
    main()
