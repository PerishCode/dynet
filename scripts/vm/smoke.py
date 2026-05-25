#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess

from common import (
    DEFAULT_VM_USER,
    ROOT,
    CommandError,
    Lab,
    add_lab_options,
    guest_ssh,
    join,
    lab_cli_args,
    logger,
    q,
    validate_name,
    vmctl_command,
)


COLD_START_CONFIG = """{
  "log": { "level": "info" },
  "dns": {
    "chains": [
      {
        "tag": "alidns-doh",
        "type": "doh",
        "endpoint": "https://dns.alidns.com/dns-query",
        "bootstrapIps": ["223.5.5.5", "223.6.6.6"]
      }
    ]
  },
  "inbounds": [
    { "tag": "mixed-in", "type": "mixed" }
  ],
  "outbounds": [
    { "tag": "direct", "type": "direct" }
  ],
  "routes": [
    { "inbound": "mixed-in", "outbound": "direct" }
  ]
}
"""

TCP_UDP_MODEL_CONFIG = """{
  "inbounds": [
    {
      "tag": "tcp-in",
      "type": "tcp",
      "payload": {
        "listen": "127.0.0.1",
        "listenPort": 1080
      }
    },
    {
      "tag": "udp-in",
      "type": "udp",
      "payload": {
        "listen": "127.0.0.1",
        "listenPort": 1053
      }
    }
  ],
  "outbounds": [
    {
      "tag": "tcp-out",
      "type": "tcp",
      "payload": {
        "server": "example.com",
        "serverPort": 443
      }
    },
    {
      "tag": "udp-out",
      "type": "udp",
      "payload": {
        "server": "1.1.1.1",
        "serverPort": 53
      }
    }
  ],
  "routes": [
    { "inbound": "tcp-in", "outbound": "tcp-out" },
    { "inbound": "udp-in", "outbound": "udp-out" }
  ]
}
"""

DNS_REVERSE_MODEL_CONFIG = """{
  "inbounds": [
    { "tag": "tun-in", "type": "tun" }
  ],
  "outbounds": [
    { "tag": "domain-out", "type": "direct" },
    { "tag": "fallback", "type": "direct" }
  ],
  "routes": [
    { "inbound": "tun-in", "domain": "example.com", "outbound": "domain-out" },
    { "inbound": "tun-in", "outbound": "fallback" }
  ]
}
"""


def api_health_command(port: int) -> str:
    return (
        "set -e; "
        f"port={int(port)}; "
        "out=/tmp/dynet-api-health.json; "
        "log=/tmp/dynet-api-serve.log; "
        "err=/tmp/dynet-api-serve.err; "
        "rm -f \"$out\" \"$log\" \"$err\"; "
        "(dynet api serve --bind 127.0.0.1:${port} --once >\"$log\" 2>\"$err\") & pid=$!; "
        "for i in $(seq 1 40); do "
        "if curl -fsS \"http://127.0.0.1:${port}/health\" >\"$out\"; then "
        "wait \"$pid\"; cat \"$out\"; printf \"\\n\"; exit 0; "
        "fi; "
        "sleep 0.25; "
        "done; "
        "kill \"$pid\" >/dev/null 2>&1 || true; "
        "wait \"$pid\" >/dev/null 2>&1 || true; "
        "cat \"$err\" >&2; "
        "exit 1"
    )


def network_access_command(dns_name: str, https_url: str) -> str:
    return (
        "set -e; "
        f"printf %s {q('[network] default route: ')}; "
        "ip -4 route show default | head -n1; "
        f"printf %s {q('[network] resolver: ')}; "
        "awk 'NF && $1 !~ /^#/ { print; exit }' /etc/resolv.conf; "
        f"printf %s {q(f'[network] dns {dns_name}: ')}; "
        f"getent ahostsv4 {q(dns_name)} | awk 'NR==1 {{ print $1; exit }}'; "
        f"printf %s {q(f'[network] https {https_url}: ')}; "
        "curl -fsS --connect-timeout 5 --max-time 15 --retry 1 "
        f"-o /dev/null -w 'http=%{{http_code}} remote=%{{remote_ip}}\\n' {q(https_url)}"
    )


def nft_dropin_command() -> str:
    return (
        "set -e; "
        "sudo mkdir -p /etc/nftables.d; "
        "sudo touch /etc/nftables.conf; "
        "if ! grep -q '/etc/nftables.d/\\*.nft' /etc/nftables.conf; then "
        "printf '\\ninclude \"/etc/nftables.d/*.nft\"\\n' | sudo tee -a /etc/nftables.conf >/dev/null; "
        "fi; "
        "test -d /etc/nftables.d; "
        "grep -q '/etc/nftables.d/\\*.nft' /etc/nftables.conf; "
        "printf '%s\\n' '[takeover] nftables drop-in mechanism ready'"
    )


def tcp_udp_model_command(label: str) -> str:
    config_path = f"/tmp/dynet-{label}-tcp-udp.json"
    return (
        "set -e; "
        f"config={q(config_path)}; "
        "cat > \"$config\" <<'EOF_DYNET_TCP_UDP_CONFIG'\n"
        f"{TCP_UDP_MODEL_CONFIG}EOF_DYNET_TCP_UDP_CONFIG\n"
        "dynet check --config \"$config\" --format json | "
        "jq -e '.network.schema == \"dynet-network/v1alpha1\" "
        "and (.network.inbounds | length) == 2 "
        "and (.network.outbounds | length) == 2 "
        "and (.diagnostics | length) == 0 "
        "and any(.network.inbounds[]; .tag == \"tcp-in\" and (.capabilities | index(\"tcp\"))) "
        "and any(.network.inbounds[]; .tag == \"udp-in\" and (.capabilities | index(\"udp\"))) "
        "and any(.network.outbounds[]; .tag == \"tcp-out\" and (.payloadFields | index(\"serverPort\"))) "
        "and any(.network.outbounds[]; .tag == \"udp-out\" and (.payloadFields | index(\"serverPort\")))' "
        ">/dev/null; "
        "dynet doctor --config \"$config\" --format json | "
        "jq -e '.checks[] | select(.name == \"network-model\" "
        "and .status == \"pass\" "
        "and .message == \"2 inbound model(s), 2 outbound model(s)\")' "
        ">/dev/null; "
        "dynet plan --config \"$config\" --format json | "
        "jq -e '.planSummary.rules == 2 "
        "and .plan.schema == \"dynet-plan/v1alpha1\" "
        "and .plan.stateSchema == \"dynet-state/v1alpha1\" "
        "and .plan.rules[0].match.inbound == \"tcp-in\" "
        "and .plan.rules[0].action.type == \"use-outbound\" "
        "and .plan.rules[0].action.tag == \"tcp-out\" "
        "and .plan.rules[1].match.inbound == \"udp-in\" "
        "and .plan.rules[1].action.type == \"use-outbound\" "
        "and .plan.rules[1].action.tag == \"udp-out\"' "
        ">/dev/null; "
        "printf '%s\\n' '[model] tcp/udp network model passed'"
    )


def dns_reverse_model_command(label: str, dns_name: str) -> str:
    config_path = f"/tmp/dynet-{label}-dns-reverse.json"
    return (
        "set -e; "
        f"domain={q(dns_name)}; "
        "ip=$(getent ahostsv4 \"$domain\" | awk 'NR==1 { print $1; exit }'); "
        "test -n \"$ip\"; "
        f"config={q(config_path)}; "
        "cat > \"$config\" <<'EOF_DYNET_DNS_REVERSE_CONFIG'\n"
        f"{DNS_REVERSE_MODEL_CONFIG}EOF_DYNET_DNS_REVERSE_CONFIG\n"
        "context=$(printf '{\"inbound\":\"tun-in\",\"destinationIp\":\"%s\"}' \"$ip\"); "
        "dynet plan --config \"$config\" --format json "
        "--context \"$context\" --dns-answer \"${domain}=${ip}\" | "
        "jq -e '.plan.rules[0].match.domain == \"example.com\" "
        "and .verdict.status == \"accept\" "
        "and .verdict.matchedRule == 1 "
        "and .verdict.outbound.tag == \"domain-out\"' "
        ">/dev/null; "
        "dynet plan --config \"$config\" --format json --context \"$context\" | "
        "jq -e '.verdict.status == \"accept\" "
        "and .verdict.matchedRule == 2 "
        "and .verdict.outbound.tag == \"fallback\"' "
        ">/dev/null; "
        "printf '%s\\n' \"[dns] reverse mapping route passed for ${domain}=${ip}\""
    )


def log_acceptance_command(config_path: str) -> str:
    return (
        "set -e; "
        "out=/tmp/dynet-log-acceptance.out; "
        "err=/tmp/dynet-log-acceptance.err; "
        "rm -f \"$out\" \"$err\"; "
        f"dynet plan --config {q(config_path)} --log-level debug >\"$out\" 2>\"$err\"; "
        "grep -q 'resolved config' \"$err\"; "
        "grep -q 'built plan' \"$err\"; "
        "grep -q 'dynet plan passed' \"$out\"; "
        "printf '%s\\n' '[logs] dynet debug tracing passed'"
    )


def takeover_env_command(config_path: str) -> str:
    return (
        "set -e; "
        "DYNET_TUN_NAME=dynet9 "
        "DYNET_DNS_PORT=1054 "
        "DYNET_STATE_DIR=/tmp/dynet-state "
        f"dynet install --check --config {q(config_path)} --format json | "
        "jq -e '.desiredState.takeover.schema == \"dynet-takeover/v1alpha1\" "
        "and .desiredState.takeover.config.tunName == \"dynet9\" "
        "and .desiredState.takeover.config.dnsPort == \"1054\" "
        "and .desiredState.takeover.config.manifestPath == \"/tmp/dynet-state/takeover/manifest.json\" "
        "and (.desiredState.takeover.config.envOverrides | length) == 3' "
        ">/dev/null; "
        "printf '%s\\n' '[takeover] env override rendering passed'"
    )


def runtime_boundary_command(config_path: str, dns_name: str) -> str:
    route_target = "203.0.113.10"
    return (
        "set -e; "
        f"config={q(config_path)}; "
        f"dns_name={q(dns_name)}; "
        "out=/tmp/dynet-runtime-boundary.json; "
        "err=/tmp/dynet-runtime-boundary.err; "
        "rm -f \"$out\" \"$err\"; "
        "cleanup() { "
        f"sudo ip route del {q(route_target)}/32 dev dynet0 >/dev/null 2>&1 || true; "
        "sudo dynet uninstall --format json >/dev/null 2>&1 || true; "
        "}; "
        "trap cleanup EXIT; "
        "sudo dynet install --config \"$config\" --format json | "
        "jq -e '.checks[] | select(.name==\"apply-engine\" and .status==\"pass\")' "
        ">/dev/null; "
        "sudo dynet run --config \"$config\" --format json "
        "--max-dns-queries 1 --timeout 20 "
        "--log-level debug >\"$out\" 2>\"$err\" & pid=$!; "
        "sleep 1; "
        f"sudo ip route replace {q(route_target)}/32 dev dynet0; "
        f"ping -c 1 -W 1 {q(route_target)} >/dev/null 2>&1 || true; "
        "DYNET_SMOKE_DNS_NAME=\"$dns_name\" python3 - <<'PY_DYNET_DNS'\n"
        "import os\n"
        "import random\n"
        "import socket\n"
        "name = os.environ['DYNET_SMOKE_DNS_NAME']\n"
        "query_id = random.randrange(0, 65536)\n"
        "packet = bytearray(query_id.to_bytes(2, 'big'))\n"
        "packet.extend(b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')\n"
        "for label in name.split('.'):\n"
        "    encoded = label.encode('ascii')\n"
        "    packet.append(len(encoded))\n"
        "    packet.extend(encoded)\n"
        "packet.extend(b'\\x00\\x00\\x01\\x00\\x01')\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "sock.settimeout(5)\n"
        "sock.sendto(bytes(packet), ('8.8.8.8', 53))\n"
        "data, _ = sock.recvfrom(4096)\n"
        "if len(data) < 12 or data[:2] != query_id.to_bytes(2, 'big'):\n"
        "    raise SystemExit('invalid DNS response')\n"
        "print('[runtime] dns probe bytes=%d' % len(data))\n"
        "PY_DYNET_DNS\n"
        "wait \"$pid\" || { cat \"$err\" >&2; exit 1; }; "
        "jq -e --arg dns_name \"$dns_name\" '.status == \"pass\" "
        "and .dnsQueries >= 1 "
        "and .dnsRecords >= 1 "
        "and .tunPackets >= 1 "
        "and any(.dnsReverse.records[]; .query == $dns_name)' "
        "<\"$out\" >/dev/null; "
        "grep -q 'dns.reverse_record' \"$err\"; "
        "grep -q 'dns.doh.query' \"$err\"; "
        "grep -q 'tun.packet' \"$err\"; "
        f"grep -q 'destination.*{route_target}' \"$err\"; "
        "cleanup; "
        "trap - EXIT; "
        "dynet verify --format json | "
        "jq -e 'all(.resources[]; .present == false)' >/dev/null; "
        "printf '%s\\n' '[runtime] tun/dns owned boundary passed'"
    )


def guest(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.guest, "guest")
    label = validate_name(args.label, "label")
    config_path = f"/tmp/dynet-{label}.json"
    write_config = (
        f"cat > {q(config_path)} <<'EOF_DYNET_CONFIG'\n"
        f"{COLD_START_CONFIG}EOF_DYNET_CONFIG"
    )
    guest_ssh(lab, name, write_config, user=args.user, source=args.source)

    commands = [
        "dynet version",
        network_access_command(args.dns_name, args.https_url),
        nft_dropin_command(),
        tcp_udp_model_command(label),
        dns_reverse_model_command(label, args.dns_name),
        f"dynet check --config {q(config_path)} --format json",
        f"dynet doctor --config {q(config_path)} --format json",
        f"dynet plan --config {q(config_path)} --format json",
        log_acceptance_command(config_path),
        takeover_env_command(config_path),
        f"dynet install --check --config {q(config_path)} --format json",
        (
            f"sudo dynet install --check --config {q(config_path)} --format json "
            "| jq -e '.checks[] | select(.name==\"artifact:nft-native-check\" "
            "and .status==\"pass\")' >/dev/null"
        ),
        runtime_boundary_command(config_path, args.runtime_dns_name),
        "dynet status --format json",
        "dynet verify --format json",
        "dynet repair --format json",
        "sudo dynet uninstall --format json",
        "dynet api capabilities --format json",
    ]
    if not args.no_api_serve:
        commands.append(api_health_command(args.api_port))
    for command in commands:
        logger.info("[smoke] %s", command)
        guest_ssh(lab, name, command, user=args.user, source=args.source)

    if args.collect:
        run_local(
            lab,
            [
                "collect",
                *lab_cli_args(lab),
                "guest",
                name,
                "--label",
                label,
                "--user",
                args.user,
                "--source",
                args.source,
            ]
        )
    if args.capture:
        run_local(
            lab,
            [
                "capture",
                *lab_cli_args(lab),
                "host",
                name,
                "--label",
                label,
                "--duration",
                str(args.capture_duration),
                "--filter",
                "icmp or arp",
                "--probe",
                "ping -c 1 192.168.122.1",
                "--user",
                args.user,
                "--source",
                args.source,
            ]
        )


def run_local(lab: Lab, args: list[str]) -> None:
    command = vmctl_command(*args)
    logger.info("run vmctl: %s", join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run dynet cold-start smoke checks in guests.")
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    guest_parser = subparsers.add_parser("guest", help="run cold-start checks in a guest")
    guest_parser.add_argument("guest")
    guest_parser.add_argument("--label", default="cold-start")
    guest_parser.add_argument("--user", default=DEFAULT_VM_USER)
    guest_parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest_parser.add_argument("--no-api-serve", action="store_true")
    guest_parser.add_argument("--api-port", type=int, default=19977)
    guest_parser.add_argument("--dns-name", default="example.com")
    guest_parser.add_argument("--runtime-dns-name", default="www.google.com")
    guest_parser.add_argument("--https-url", default="https://example.com/")
    guest_parser.add_argument("--collect", action="store_true")
    guest_parser.add_argument("--capture", action="store_true")
    guest_parser.add_argument("--capture-duration", type=int, default=4)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {"guest": guest}
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
