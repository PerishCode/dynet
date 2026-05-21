#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from common import (
    DEFAULT_VM_USER,
    ROOT,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_repo_resources,
    guest_ssh,
    join,
    logger,
    q,
    validate_name,
)
from private_probe import (
    build_artifact,
    build_secret_config,
    cleanup_guest_files,
    install_artifact,
    lab_args,
    target_family,
    write_guest_file,
    write_json,
)


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


def nft_dropin_command() -> str:
    return (
        "set -e; "
        "sudo mkdir -p /etc/nftables.d; "
        "sudo touch /etc/nftables.conf; "
        "if ! grep -q '/etc/nftables.d/\\*.nft' /etc/nftables.conf; then "
        "printf '\\ninclude \"/etc/nftables.d/*.nft\"\\n' | sudo tee -a /etc/nftables.conf >/dev/null; "
        "fi; "
        "test -d /etc/nftables.d; "
        "grep -q '/etc/nftables.d/\\*.nft' /etc/nftables.conf"
    )


def dns_probe_python(
    names: list[str],
    upstream_host: str,
    upstream_port: str,
    timeout: int,
) -> str:
    names_json = json.dumps(names)
    return (
        "DYNET_RUNTIME_DNS_NAMES="
        + q(names_json)
        + " python3 - <<'PY_DYNET_PRIVATE_DNS'\n"
        "import json\n"
        "import os\n"
        "import random\n"
        "import socket\n"
        f"upstream = ({upstream_host!r}, {int(upstream_port)!r})\n"
        f"timeout = {int(timeout)!r}\n"
        "names = json.loads(os.environ['DYNET_RUNTIME_DNS_NAMES'])\n"
        "for name in names:\n"
        "    query_id = random.randrange(0, 65536)\n"
        "    packet = bytearray(query_id.to_bytes(2, 'big'))\n"
        "    packet.extend(b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')\n"
        "    for label in name.split('.'):\n"
        "        encoded = label.encode('ascii')\n"
        "        packet.append(len(encoded))\n"
        "        packet.extend(encoded)\n"
        "    packet.extend(b'\\x00\\x00\\x01\\x00\\x01')\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    sock.settimeout(timeout)\n"
        "    sock.sendto(bytes(packet), upstream)\n"
        "    try:\n"
        "        data, _ = sock.recvfrom(4096)\n"
        "    except TimeoutError:\n"
        "        print('[runtime-private] dns %s timeout' % name)\n"
        "        continue\n"
        "    if len(data) < 12 or data[:2] != query_id.to_bytes(2, 'big'):\n"
        "        print('[runtime-private] dns %s invalid-response' % name)\n"
        "        continue\n"
        "    print('[runtime-private] dns %s bytes=%d' % (name, len(data)))\n"
        "PY_DYNET_PRIVATE_DNS\n"
    )


def tcp_probe_python(
    names: list[str],
    upstream_host: str,
    upstream_port: str,
    timeout: int,
    output_path: str,
) -> str:
    names_json = json.dumps(names)
    return (
        "DYNET_RUNTIME_TCP_NAMES="
        + q(names_json)
        + " DYNET_RUNTIME_TCP_OUT="
        + q(output_path)
        + " python3 - <<'PY_DYNET_PRIVATE_TCP'\n"
        "import json\n"
        "import os\n"
        "import random\n"
        "import socket\n"
        "import ssl\n"
        "import subprocess\n"
        "import time\n"
        f"upstream = ({upstream_host!r}, {int(upstream_port)!r})\n"
        f"timeout = {int(timeout)!r}\n"
        "names = json.loads(os.environ['DYNET_RUNTIME_TCP_NAMES'])\n"
        "out = os.environ['DYNET_RUNTIME_TCP_OUT']\n"
        "routes = []\n"
        "def read_name(data, offset):\n"
        "    labels = []\n"
        "    jumped = False\n"
        "    end = offset\n"
        "    seen = 0\n"
        "    while True:\n"
        "        if offset >= len(data):\n"
        "            raise ValueError('dns name exceeds packet')\n"
        "        length = data[offset]\n"
        "        if length & 0xc0 == 0xc0:\n"
        "            if offset + 1 >= len(data):\n"
        "                raise ValueError('dns pointer exceeds packet')\n"
        "            if not jumped:\n"
        "                end = offset + 2\n"
        "            offset = ((length & 0x3f) << 8) | data[offset + 1]\n"
        "            jumped = True\n"
        "            seen += 1\n"
        "            if seen > 16:\n"
        "                raise ValueError('dns pointer loop')\n"
        "            continue\n"
        "        offset += 1\n"
        "        if length == 0:\n"
        "            return '.'.join(labels), (end if jumped else offset)\n"
        "        label = data[offset:offset + length].decode('ascii', 'ignore')\n"
        "        labels.append(label.lower())\n"
        "        offset += length\n"
        "def dns_query(name):\n"
        "    query_id = random.randrange(0, 65536)\n"
        "    packet = bytearray(query_id.to_bytes(2, 'big'))\n"
        "    packet.extend(b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')\n"
        "    for label in name.split('.'):\n"
        "        encoded = label.encode('ascii')\n"
        "        packet.append(len(encoded))\n"
        "        packet.extend(encoded)\n"
        "    packet.extend(b'\\x00\\x00\\x01\\x00\\x01')\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    sock.settimeout(timeout)\n"
        "    started = time.monotonic()\n"
        "    sock.sendto(bytes(packet), upstream)\n"
        "    data, _ = sock.recvfrom(4096)\n"
        "    elapsed_ms = int((time.monotonic() - started) * 1000)\n"
        "    if len(data) < 12 or data[:2] != query_id.to_bytes(2, 'big'):\n"
        "        raise ValueError('invalid dns response')\n"
        "    qd = int.from_bytes(data[4:6], 'big')\n"
        "    an = int.from_bytes(data[6:8], 'big')\n"
        "    offset = 12\n"
        "    for _ in range(qd):\n"
        "        _, offset = read_name(data, offset)\n"
        "        offset += 4\n"
        "    addresses = []\n"
        "    for _ in range(an):\n"
        "        _, offset = read_name(data, offset)\n"
        "        rtype = int.from_bytes(data[offset:offset+2], 'big')\n"
        "        ttl = int.from_bytes(data[offset+4:offset+8], 'big')\n"
        "        rdlen = int.from_bytes(data[offset+8:offset+10], 'big')\n"
        "        offset += 10\n"
        "        rdata = data[offset:offset+rdlen]\n"
        "        offset += rdlen\n"
        "        if rtype == 1 and rdlen == 4:\n"
        "            addresses.append({'ip': '.'.join(str(b) for b in rdata), 'ttl': ttl})\n"
        "    return {'bytes': len(data), 'elapsedMs': elapsed_ms, 'addresses': addresses}\n"
        "def route_ip(ip):\n"
        "    subprocess.run(['sudo', 'ip', 'route', 'replace', ip + '/32', 'dev', 'dynet0'], check=True)\n"
        "    routes.append(ip)\n"
        "def https_head(name, ip):\n"
        "    context = ssl.create_default_context()\n"
        "    started = time.monotonic()\n"
        "    raw = socket.create_connection((ip, 443), timeout=timeout)\n"
        "    with context.wrap_socket(raw, server_hostname=name) as tls:\n"
        "        tls.settimeout(timeout)\n"
        "        request = ('HEAD / HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: dynet-private-runtime-probe/1\\r\\nConnection: close\\r\\n\\r\\n' % name).encode('ascii')\n"
        "        tls.sendall(request)\n"
        "        data = tls.recv(4096)\n"
        "    elapsed_ms = int((time.monotonic() - started) * 1000)\n"
        "    line = data.splitlines()[0].decode('iso-8859-1', 'replace') if data else ''\n"
        "    return {'elapsedMs': elapsed_ms, 'bytes': len(data), 'statusLine': line, 'ok': line.startswith('HTTP/')}\n"
        "results = []\n"
        "try:\n"
        "    for name in names:\n"
        "        item = {'name': name}\n"
        "        try:\n"
        "            dns = dns_query(name)\n"
        "            item['dns'] = dns\n"
        "            ip = dns['addresses'][0]['ip'] if dns['addresses'] else ''\n"
        "            item['ip'] = ip\n"
        "            if not ip:\n"
        "                raise RuntimeError('no A record')\n"
        "            route_ip(ip)\n"
        "            item['https'] = https_head(name, ip)\n"
        "        except Exception as exc:\n"
        "            item['error'] = str(exc)\n"
        "        results.append(item)\n"
        "finally:\n"
        "    for ip in routes:\n"
        "        subprocess.run(['sudo', 'ip', 'route', 'del', ip + '/32', 'dev', 'dynet0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "    with open(out, 'w') as fh:\n"
        "        json.dump({'schema': 'dynet-vm-private-runtime-tcp-probe/v1alpha1', 'results': results}, fh, sort_keys=True)\n"
        "    for item in results:\n"
        "        print('[runtime-private] tcp %s ok=%s error=%s' % (item.get('name'), item.get('https', {}).get('ok'), item.get('error', '')))\n"
        "PY_DYNET_PRIVATE_TCP\n"
    )


def udp_probe_python(target: str, timeout: int, output_path: str) -> str:
    host, port = split_host_port(target)
    return (
        "DYNET_RUNTIME_UDP_OUT="
        + q(output_path)
        + " python3 - <<'PY_DYNET_PRIVATE_UDP'\n"
        "import json\n"
        "import os\n"
        "import socket\n"
        "import subprocess\n"
        "import time\n"
        f"target = ({host!r}, {int(port)!r})\n"
        f"timeout = {int(timeout)!r}\n"
        "out = os.environ['DYNET_RUNTIME_UDP_OUT']\n"
        "packet = b'\\x1b' + (b'\\x00' * 47)\n"
        "result = {'schema': 'dynet-vm-private-runtime-udp-probe/v1alpha1', 'target': '%s:%s' % target}\n"
        "try:\n"
        "    subprocess.run(['sudo', 'ip', 'route', 'replace', target[0] + '/32', 'dev', 'dynet0'], check=True)\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    sock.settimeout(timeout)\n"
        "    started = time.monotonic()\n"
        "    sent = sock.sendto(packet, target)\n"
        "    data, _ = sock.recvfrom(512)\n"
        "    result.update({'ok': len(data) >= 48, 'sentBytes': sent, 'receivedBytes': len(data), 'elapsedMs': int((time.monotonic() - started) * 1000)})\n"
        "except Exception as exc:\n"
        "    result.update({'ok': False, 'error': str(exc)})\n"
        "finally:\n"
        "    subprocess.run(['sudo', 'ip', 'route', 'del', target[0] + '/32', 'dev', 'dynet0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "    with open(out, 'w') as fh:\n"
        "        json.dump(result, fh, sort_keys=True)\n"
        "    print('[runtime-private] udp target=%s:%s ok=%s error=%s' % (target[0], target[1], result.get('ok'), result.get('error', '')))\n"
        "PY_DYNET_PRIVATE_UDP\n"
    )


def ipv6_no_leak_probe_python(target: str, timeout: int, output_path: str) -> str:
    host, port = split_host_port(target)
    return (
        "DYNET_RUNTIME_IPV6_OUT="
        + q(output_path)
        + " python3 - <<'PY_DYNET_PRIVATE_IPV6'\n"
        "import json\n"
        "import os\n"
        "import socket\n"
        "import subprocess\n"
        "import time\n"
        f"target = ({host!r}, {int(port)!r})\n"
        f"timeout = {int(timeout)!r}\n"
        "out = os.environ['DYNET_RUNTIME_IPV6_OUT']\n"
        "result = {'schema': 'dynet-vm-private-runtime-ipv6-no-leak/v1alpha1', 'target': '[%s]:%s' % target}\n"
        "try:\n"
        "    subprocess.run(['sudo', 'ip', '-6', 'addr', 'replace', 'fd00:6177::1/64', 'dev', 'dynet0'], check=True)\n"
        "    subprocess.run(['sudo', 'ip', '-6', 'route', 'replace', target[0] + '/128', 'dev', 'dynet0'], check=True)\n"
        "    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)\n"
        "    sock.settimeout(timeout)\n"
        "    started = time.monotonic()\n"
        "    sent = sock.sendto(b'dynet-ipv6-no-leak', target)\n"
        "    try:\n"
        "        data, _ = sock.recvfrom(512)\n"
        "        result.update({'ok': False, 'sentBytes': sent, 'receivedBytes': len(data), 'elapsedMs': int((time.monotonic() - started) * 1000), 'error': 'unexpected IPv6 response'})\n"
        "    except TimeoutError:\n"
        "        result.update({'ok': True, 'sentBytes': sent, 'receivedBytes': 0, 'elapsedMs': int((time.monotonic() - started) * 1000), 'closed': 'timeout-no-response'})\n"
        "except Exception as exc:\n"
        "    result.update({'ok': False, 'error': str(exc)})\n"
        "finally:\n"
        "    subprocess.run(['sudo', 'ip', '-6', 'route', 'del', target[0] + '/128', 'dev', 'dynet0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "    subprocess.run(['sudo', 'ip', '-6', 'addr', 'del', 'fd00:6177::1/64', 'dev', 'dynet0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "    with open(out, 'w') as fh:\n"
        "        json.dump(result, fh, sort_keys=True)\n"
        "    print('[runtime-private] ipv6 target=%s:%s ok=%s error=%s' % (target[0], target[1], result.get('ok'), result.get('error', '')))\n"
        "PY_DYNET_PRIVATE_IPV6\n"
    )


def workload_probe_python(
    manifest_path: str,
    upstream_host: str,
    upstream_port: str,
    timeout: int,
    output_path: str,
    respect_schedule: bool,
) -> str:
    return (
        "DYNET_RUNTIME_WORKLOAD_MANIFEST="
        + q(manifest_path)
        + " DYNET_RUNTIME_WORKLOAD_OUT="
        + q(output_path)
        + " python3 - <<'PY_DYNET_PRIVATE_WORKLOAD'\n"
        "import json\n"
        "import os\n"
        "import random\n"
        "import socket\n"
        "import ssl\n"
        "import subprocess\n"
        "import time\n"
        "from collections import Counter, defaultdict\n"
        f"upstream = ({upstream_host!r}, {int(upstream_port)!r})\n"
        f"timeout = {int(timeout)!r}\n"
        f"respect_schedule = {bool(respect_schedule)!r}\n"
        "manifest_path = os.environ['DYNET_RUNTIME_WORKLOAD_MANIFEST']\n"
        "out = os.environ['DYNET_RUNTIME_WORKLOAD_OUT']\n"
        "manifest = json.load(open(manifest_path))\n"
        "entries = [item for item in manifest.get('entries', []) if isinstance(item, dict)]\n"
        "routes = set()\n"
        "dns_cache = {}\n"
        "def run_json(command):\n"
        "    data = subprocess.run(command, check=True, capture_output=True, text=True).stdout\n"
        "    return json.loads(data or '[]')\n"
        "def elapsed_ms(start):\n"
        "    return int((time.monotonic() - start) * 1000)\n"
        "def unix_ms():\n"
        "    return int(time.time() * 1000)\n"
        "def classify(exc):\n"
        "    text = ('%s: %s' % (type(exc).__name__, exc)).lower()\n"
        "    if isinstance(exc, socket.gaierror) or 'name or service not known' in text:\n"
        "        return 'dns'\n"
        "    if isinstance(exc, TimeoutError) or 'timed out' in text or 'timeout' in text:\n"
        "        return 'timeout'\n"
        "    if isinstance(exc, ssl.SSLCertVerificationError) or 'certificate' in text:\n"
        "        return 'certificate'\n"
        "    if isinstance(exc, ssl.SSLError) or 'ssl' in text:\n"
        "        return 'tls'\n"
        "    if 'refused' in text:\n"
        "        return 'refused'\n"
        "    if 'reset' in text:\n"
        "        return 'reset'\n"
        "    if 'network is unreachable' in text:\n"
        "        return 'network-unreachable'\n"
        "    return 'other'\n"
        "def route_snapshot(ip):\n"
        "    try:\n"
        "        rows = run_json(['ip', '-j', 'route', 'get', ip])\n"
        "        row = rows[0] if rows else {}\n"
        "        dev = row.get('dev')\n"
        "        return {'routeObserved': True, 'routeDev': dev, 'routeViaDynet': dev == 'dynet0', 'routeSourcePresent': bool(row.get('prefsrc') or row.get('src'))}\n"
        "    except Exception as exc:\n"
        "        return {'routeObserved': False, 'routeErrorType': classify(exc)}\n"
        "def tun_link_stats():\n"
        "    try:\n"
        "        rows = run_json(['ip', '-j', '-s', 'link', 'show', 'dev', 'dynet0'])\n"
        "        row = rows[0] if rows else {}\n"
        "        stats = row.get('stats64') or row.get('stats') or {}\n"
        "        rx = stats.get('rx') or {}\n"
        "        tx = stats.get('tx') or {}\n"
        "        return {'observed': True, 'rxPackets': int(rx.get('packets') or 0), 'txPackets': int(tx.get('packets') or 0), 'rxBytes': int(rx.get('bytes') or 0), 'txBytes': int(tx.get('bytes') or 0)}\n"
        "    except Exception as exc:\n"
        "        return {'observed': False, 'errorType': classify(exc)}\n"
        "def tun_delta(before, after):\n"
        "    if not before.get('observed') or not after.get('observed'):\n"
        "        return {'observed': False}\n"
        "    return {'observed': True, 'rxPackets': after.get('rxPackets', 0) - before.get('rxPackets', 0), 'txPackets': after.get('txPackets', 0) - before.get('txPackets', 0), 'rxBytes': after.get('rxBytes', 0) - before.get('rxBytes', 0), 'txBytes': after.get('txBytes', 0) - before.get('txBytes', 0)}\n"
        "def read_name(data, offset):\n"
        "    labels = []\n"
        "    jumped = False\n"
        "    end = offset\n"
        "    seen = 0\n"
        "    while True:\n"
        "        if offset >= len(data):\n"
        "            raise ValueError('dns name exceeds packet')\n"
        "        length = data[offset]\n"
        "        if length & 0xc0 == 0xc0:\n"
        "            if offset + 1 >= len(data):\n"
        "                raise ValueError('dns pointer exceeds packet')\n"
        "            if not jumped:\n"
        "                end = offset + 2\n"
        "            offset = ((length & 0x3f) << 8) | data[offset + 1]\n"
        "            jumped = True\n"
        "            seen += 1\n"
        "            if seen > 16:\n"
        "                raise ValueError('dns pointer loop')\n"
        "            continue\n"
        "        offset += 1\n"
        "        if length == 0:\n"
        "            return '.'.join(labels), (end if jumped else offset)\n"
        "        labels.append(data[offset:offset + length].decode('ascii', 'ignore').lower())\n"
        "        offset += length\n"
        "def dns_query(name):\n"
        "    query_id = random.randrange(0, 65536)\n"
        "    packet = bytearray(query_id.to_bytes(2, 'big'))\n"
        "    packet.extend(b'\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')\n"
        "    for label in name.split('.'):\n"
        "        encoded = label.encode('ascii')\n"
        "        packet.append(len(encoded))\n"
        "        packet.extend(encoded)\n"
        "    packet.extend(b'\\x00\\x00\\x01\\x00\\x01')\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    sock.settimeout(timeout)\n"
        "    sock.sendto(bytes(packet), upstream)\n"
        "    data, _ = sock.recvfrom(4096)\n"
        "    if len(data) < 12 or data[:2] != query_id.to_bytes(2, 'big'):\n"
        "        raise ValueError('invalid dns response')\n"
        "    qd = int.from_bytes(data[4:6], 'big')\n"
        "    an = int.from_bytes(data[6:8], 'big')\n"
        "    offset = 12\n"
        "    for _ in range(qd):\n"
        "        _, offset = read_name(data, offset)\n"
        "        offset += 4\n"
        "    addresses = []\n"
        "    ttls = []\n"
        "    for _ in range(an):\n"
        "        _, offset = read_name(data, offset)\n"
        "        rtype = int.from_bytes(data[offset:offset+2], 'big')\n"
        "        ttl = int.from_bytes(data[offset+4:offset+8], 'big')\n"
        "        rdlen = int.from_bytes(data[offset+8:offset+10], 'big')\n"
        "        offset += 10\n"
        "        rdata = data[offset:offset+rdlen]\n"
        "        offset += rdlen\n"
        "        if rtype == 1 and rdlen == 4:\n"
        "            addresses.append('.'.join(str(b) for b in rdata))\n"
        "            ttls.append(ttl)\n"
        "    return {'_addresses': addresses, 'dnsAnswers': an, 'aRecords': len(addresses), 'minTtl': min(ttls) if ttls else None}\n"
        "def route_ip(ip):\n"
        "    before = route_snapshot(ip)\n"
        "    subprocess.run(['sudo', 'ip', 'route', 'replace', ip + '/32', 'dev', 'dynet0'], check=True)\n"
        "    routes.add(ip)\n"
        "    after = route_snapshot(ip)\n"
        "    return {'routeInstalled': True, 'routeBefore': before, 'routeAfter': after, 'routeViaDynet': after.get('routeViaDynet') is True, 'routeDev': after.get('routeDev')}\n"
        "def tcp_connect(ip):\n"
        "    sock = socket.create_connection((ip, 443), timeout=timeout)\n"
        "    sock.settimeout(timeout)\n"
        "    return {'_socket': sock, 'connectedFamily': 'ipv4', 'peerMatchesSelectedAddress': sock.getpeername()[0] == ip}\n"
        "def tls_wrap(name, sock):\n"
        "    context = ssl.create_default_context()\n"
        "    try:\n"
        "        tls = context.wrap_socket(sock, server_hostname=name)\n"
        "    except Exception:\n"
        "        sock.close()\n"
        "        raise\n"
        "    tls.settimeout(timeout)\n"
        "    return {'_tls': tls, 'tlsVersion': tls.version()}\n"
        "def close_connected_socket(sock):\n"
        "    try:\n"
        "        sock.shutdown(socket.SHUT_RDWR)\n"
        "    except Exception:\n"
        "        pass\n"
        "    sock.close()\n"
        "    return {'closedAfterConnect': True}\n"
        "def http_request(name, tls, method):\n"
        "    request = ('%s / HTTP/1.1\\r\\nHost: %s\\r\\nUser-Agent: dynet-private-runtime-workload/1\\r\\nAccept: */*\\r\\nConnection: close\\r\\nCache-Control: no-cache\\r\\n\\r\\n' % (method, name)).encode('ascii')\n"
        "    tls.sendall(request)\n"
        "    limit = 8192 if method == 'GET' else 4096\n"
        "    data = b''\n"
        "    while len(data) < limit:\n"
        "        chunk = tls.recv(min(4096, limit - len(data)))\n"
        "        if not chunk:\n"
        "            break\n"
        "        data += chunk\n"
        "        if method == 'HEAD' and b'\\r\\n\\r\\n' in data:\n"
        "            break\n"
        "    line = data.split(b'\\r\\n', 1)[0]\n"
        "    parts = line.split()\n"
        "    if len(parts) < 2 or not parts[1].isdigit():\n"
        "        raise ValueError('invalid HTTP status line')\n"
        "    status = int(parts[1])\n"
        "    return {'statusCode': status, 'statusClass': '%dxx' % (status // 100), 'responseBytesRead': len(data), 'responseBodyStored': False}\n"
        "def public(value):\n"
        "    if not isinstance(value, dict):\n"
        "        return {}\n"
        "    return {key: item for key, item in value.items() if not key.startswith('_')}\n"
        "def run_stage(result, name, func):\n"
        "    started = time.monotonic()\n"
        "    stage = {'name': name, 'ok': False}\n"
        "    try:\n"
        "        value = func()\n"
        "        stage.update(public(value))\n"
        "        stage['ok'] = True\n"
        "        return value\n"
        "    except Exception as exc:\n"
        "        stage['errorType'] = classify(exc)\n"
        "        stage['errorClass'] = type(exc).__name__\n"
        "        raise\n"
        "    finally:\n"
        "        stage['elapsedMs'] = elapsed_ms(started)\n"
        "        result.setdefault('stages', []).append(stage)\n"
        "def cached_dns(result, domain, force):\n"
        "    if not force and domain in dns_cache:\n"
        "        value = dns_cache[domain]\n"
        "        result.setdefault('stages', []).append({'name': 'dns-cache', 'ok': True, 'elapsedMs': 0, 'cacheHit': True, **public(value)})\n"
        "        return value\n"
        "    value = run_stage(result, 'dns', lambda domain=domain: dns_query(domain))\n"
        "    if value.get('_addresses'):\n"
        "        dns_cache[domain] = value\n"
        "    return value\n"
        "def percentile(values, target):\n"
        "    if not values:\n"
        "        return None\n"
        "    values = sorted(values)\n"
        "    return values[round((len(values) - 1) * (target / 100))]\n"
        "def aggregate(rows):\n"
        "    total = len(rows)\n"
        "    success = sum(1 for row in rows if row.get('ok'))\n"
        "    latencies = [int(row.get('elapsedMs') or 0) for row in rows]\n"
        "    return {'count': total, 'success': success, 'failure': total - success, 'successRate': round(success / total, 4) if total else 0, 'latencyMs': {'p50': percentile(latencies, 50), 'p95': percentile(latencies, 95), 'max': max(latencies) if latencies else None}}\n"
        "def grouped(rows, field):\n"
        "    groups = defaultdict(list)\n"
        "    for row in rows:\n"
        "        groups[str(row.get(field) or 'unknown')].append(row)\n"
        "    return [{'key': key, **aggregate(value)} for key, value in sorted(groups.items())]\n"
        "def stage_groups(rows):\n"
        "    groups = defaultdict(list)\n"
        "    for row in rows:\n"
        "        for stage in row.get('stages', []):\n"
        "            groups[str(stage.get('name'))].append(stage)\n"
        "    return [{'key': key, **aggregate(value)} for key, value in sorted(groups.items())]\n"
        "def top_errors(rows):\n"
        "    counter = Counter(str(row.get('errorType')) for row in rows if row.get('errorType'))\n"
        "    return [{'key': key, 'count': count} for key, count in counter.most_common(20)]\n"
        "started = time.monotonic()\n"
        "results = []\n"
        "try:\n"
        "    for entry in entries:\n"
        "        offset = int(entry.get('scheduledOffsetMs') or 0)\n"
        "        if respect_schedule:\n"
        "            due = started + offset / 1000\n"
        "            now = time.monotonic()\n"
        "            if due > now:\n"
        "                time.sleep(due - now)\n"
        "                lag = 0\n"
        "            else:\n"
        "                lag = int((now - due) * 1000)\n"
        "        else:\n"
        "            lag = None\n"
        "        item_start = time.monotonic()\n"
        "        item_started_at = unix_ms()\n"
        "        domain = str(entry.get('domain', '')).lower().strip('.')\n"
        "        probe = str(entry.get('probe') or 'https-head')\n"
        "        result = {'id': entry.get('id'), 'startedAtUnixMs': item_started_at, 'bucket': entry.get('bucket'), 'behavior': entry.get('behavior'), 'groupId': entry.get('groupId'), 'domain': domain, 'probe': probe, 'scheduledOffsetMs': entry.get('scheduledOffsetMs'), 'scheduleLagMs': lag, 'stages': []}\n"
        "        tun_before = tun_link_stats()\n"
        "        sock = None\n"
        "        tls = None\n"
        "        try:\n"
        "            dns = cached_dns(result, domain, probe == 'dns')\n"
        "            result.update(public(dns))\n"
        "            addresses = dns.get('_addresses', [])\n"
        "            if probe != 'dns':\n"
        "                if not addresses:\n"
        "                    raise RuntimeError('no A record')\n"
        "                ip = addresses[0]\n"
        "                result['selectedAddressIndex'] = 0\n"
        "                result['selectedAddressCount'] = len(addresses)\n"
        "                result['selectedAddressStored'] = False\n"
                "                result.update(public(run_stage(result, 'route', lambda ip=ip: route_ip(ip))))\n"
        "                tcp = run_stage(result, 'tcp-connect', lambda ip=ip: tcp_connect(ip))\n"
        "                sock = tcp.get('_socket')\n"
        "                result.update(public(tcp))\n"
        "                if probe == 'tcp-connect':\n"
        "                    result.update(public(run_stage(result, 'tcp-close', lambda sock=sock: close_connected_socket(sock))))\n"
        "                    sock = None\n"
        "                if probe in {'tls-handshake', 'https-head', 'https-get'}:\n"
        "                    tls_value = run_stage(result, 'tls-handshake', lambda domain=domain, sock=sock: tls_wrap(domain, sock))\n"
        "                    sock = None\n"
        "                    tls = tls_value.get('_tls')\n"
        "                    result.update(public(tls_value))\n"
        "                    if probe in {'https-head', 'https-get'}:\n"
        "                        method = 'GET' if probe == 'https-get' else 'HEAD'\n"
        "                        http = run_stage(result, 'http-' + method.lower(), lambda domain=domain, tls=tls, method=method: http_request(domain, tls, method))\n"
        "                        result.update(public(http))\n"
        "            result['ok'] = True\n"
        "        except Exception as exc:\n"
        "            result['ok'] = False\n"
        "            result['errorType'] = classify(exc)\n"
        "            result['errorClass'] = type(exc).__name__\n"
        "            result['error'] = str(exc)[:180]\n"
        "            failed = next((stage for stage in reversed(result.get('stages', [])) if not stage.get('ok')), None)\n"
        "            result['errorStage'] = failed.get('name') if failed else 'probe'\n"
        "        finally:\n"
        "            if tls is not None:\n"
        "                tls.close()\n"
        "            if sock is not None:\n"
        "                sock.close()\n"
        "            result['tunWitness'] = tun_delta(tun_before, tun_link_stats())\n"
        "            result['elapsedMs'] = elapsed_ms(item_start)\n"
        "            result['finishedAtUnixMs'] = unix_ms()\n"
        "            results.append(result)\n"
        "finally:\n"
        "    for ip in sorted(routes):\n"
        "        subprocess.run(['sudo', 'ip', 'route', 'del', ip + '/32', 'dev', 'dynet0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "summary = {'schema': '" + WORKLOAD_PROBE_SCHEMA + "', 'manifestSchema': manifest.get('schema'), 'environment': manifest.get('environment'), 'seed': manifest.get('seed'), 'workload': manifest.get('workload', {}), 'privacy': {'identityInformationSent': False, 'cookiesSent': False, 'authorizationSent': False, 'responseBodiesStored': False, 'responseHeadersStored': False, 'resolvedIpAddressesStored': False}, 'totals': aggregate(results), 'byBucket': grouped(results, 'bucket'), 'byBehavior': grouped(results, 'behavior'), 'byProbe': grouped(results, 'probe'), 'byStage': stage_groups(results), 'errors': top_errors(results), 'durationActualMs': elapsed_ms(started), 'results': results}\n"
        "with open(out, 'w') as fh:\n"
        "    json.dump(summary, fh, sort_keys=True)\n"
        "print('[runtime-private] workload attempted=%d successRate=%s errors=%s' % (summary['totals']['count'], summary['totals']['successRate'], summary['errors']))\n"
        "PY_DYNET_PRIVATE_WORKLOAD\n"
    )


def split_host_port(value: str) -> tuple[str, int]:
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)


def load_workload_manifest(args: argparse.Namespace) -> dict | None:
    if not args.workload_manifest:
        return None
    path = Path(args.workload_manifest).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    manifest = json.loads(path.read_text())
    entries = workload_entries(manifest)
    if not entries:
        raise CommandError("--workload-manifest has no entries")
    probes = {str(entry.get("probe")) for entry in entries}
    unsupported = probes - {"dns", "tcp-connect", "tls-handshake", "https-head", "https-get"}
    if unsupported:
        raise CommandError(
            "--workload-manifest has unsupported probes: " + ", ".join(sorted(unsupported))
        )
    if any(probe != "dns" for probe in probes) and not args.tcp_forward:
        raise CommandError("--workload-manifest with TCP/TLS/HTTPS probes requires --tcp-forward")
    return manifest


def workload_entries(manifest: dict | None) -> list[dict]:
    if not isinstance(manifest, dict):
        return []
    return [
        item
        for item in manifest.get("entries", [])
        if isinstance(item, dict) and isinstance(item.get("domain"), str)
    ]


def workload_domains(manifest: dict | None) -> list[str]:
    domains = []
    seen = set()
    for entry in workload_entries(manifest):
        domain = str(entry["domain"]).lower().strip(".")
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def add_required_domain_suffixes(args: argparse.Namespace, names: list[str], manifest: dict | None) -> None:
    suffixes = {target_family(f"https://{name}/") for name in names}
    suffixes.update(target_family(f"https://{domain}/") for domain in workload_domains(manifest))
    args.domain_suffix = sorted(set(args.domain_suffix or []) | suffixes)


def augment_runtime_config(config_text: str, args: argparse.Namespace) -> str:
    if not args.udp_direct_probe:
        return config_text
    config = json.loads(config_text)
    host, _ = split_host_port(args.udp_target)
    outbounds = config.setdefault("outbounds", [])
    if not any(item.get("tag") == "direct-udp-probe" for item in outbounds if isinstance(item, dict)):
        outbounds.append(
            {
                "tag": "direct-udp-probe",
                "type": "direct",
                "metadata": {"purpose": "vm-runtime-udp-forwarding-probe"},
            }
        )
    routes = config.setdefault("routes", [])
    routes.insert(
        0,
        {
            "inbound": "tun-in",
            "transport": "udp",
            "ipCidr": host + "/32",
            "outbound": "direct-udp-probe",
        },
    )
    return json.dumps(config, sort_keys=True)


def runtime_command(
    label: str,
    remote_config: str,
    remote_quality: str | None,
    remote_workload: str | None,
    dns_names: list[str],
    args: argparse.Namespace,
) -> str:
    out = f"/tmp/dynet-{label}-private-runtime.json"
    err = f"/tmp/dynet-{label}-private-runtime.err"
    install = f"/tmp/dynet-{label}-private-install.json"
    uninstall = f"/tmp/dynet-{label}-private-uninstall.json"
    tcp_probe = f"/tmp/dynet-{label}-private-tcp-probe.json"
    udp_probe = f"/tmp/dynet-{label}-private-udp-probe.json"
    ipv6_probe = f"/tmp/dynet-{label}-private-ipv6-probe.json"
    workload_probe = f"/tmp/dynet-{label}-private-workload-probe.json"
    upstream_host, upstream_port = args.upstream_dns.rsplit(":", 1)
    run = [
        "sudo",
        args.dynet_bin,
        "run",
        "--config",
        remote_config,
        "--format",
        "json",
        "--upstream-dns",
        args.upstream_dns,
        "--timeout",
        str(args.timeout),
        "--log-level",
        "debug",
    ]
    if args.tcp_forward:
        run.append("--experimental-tcp-forward")
    if args.udp_forward:
        run.append("--experimental-udp-forward")
    elif not remote_workload:
        run.extend(
            [
                "--max-dns-queries",
                str(len(dns_names)),
                "--max-tun-packets",
                "1",
            ]
        )
    if args.udp_forward and not args.ipv6_no_leak:
        run.extend(["--max-udp-sessions", "1"])
    if remote_quality:
        run.extend(["--quality-state", remote_quality])
    probe = ""
    if args.udp_direct_probe:
        probe += udp_probe_python(args.udp_target, args.dns_timeout, udp_probe)
    if args.ipv6_no_leak:
        probe += ipv6_no_leak_probe_python(args.ipv6_target, args.dns_timeout, ipv6_probe)
    probe += (
        tcp_probe_python(dns_names, upstream_host, upstream_port, args.dns_timeout, tcp_probe)
        if args.tcp_forward
        else dns_probe_python(dns_names, upstream_host, upstream_port, args.dns_timeout)
    )
    if remote_workload:
        probe += workload_probe_python(
            remote_workload,
            upstream_host,
            upstream_port,
            args.dns_timeout,
            workload_probe,
            args.workload_respect_schedule,
        )
    tun_packet_probe = (
        ""
        if args.tcp_forward
        else (
            f"sudo ip route replace {q(args.tun_target)}/32 dev dynet0; "
            f"ping -c 1 -W 1 {q(args.tun_target)} >/dev/null 2>&1 || true; "
        )
    )
    return (
        "set -e; "
        f"out={q(out)}; err={q(err)}; install={q(install)}; uninstall={q(uninstall)}; "
        f"tcp_probe={q(tcp_probe)}; udp_probe={q(udp_probe)}; ipv6_probe={q(ipv6_probe)}; workload_probe={q(workload_probe)}; "
        "rm -f \"$out\" \"$err\" \"$install\" \"$uninstall\" \"$tcp_probe\" \"$udp_probe\" \"$ipv6_probe\" \"$workload_probe\"; "
        "pid=''; "
        "cleanup() { "
        "if [ -n \"$pid\" ]; then sudo kill \"$pid\" >/dev/null 2>&1 || true; wait \"$pid\" >/dev/null 2>&1 || true; fi; "
        f"sudo ip route del {q(args.tun_target)}/32 dev dynet0 >/dev/null 2>&1 || true; "
        f"sudo {q(args.dynet_bin)} uninstall --format json >\"$uninstall\" 2>/dev/null || true; "
        "}; "
        "trap cleanup EXIT; "
        f"sudo {q(args.dynet_bin)} install --config {q(remote_config)} --format json >\"$install\"; "
        f"{join(run)} >\"$out\" 2>\"$err\" & pid=$!; "
        "sleep 1; "
        f"{tun_packet_probe}"
        f"{probe}"
        "wait \"$pid\"; pid=''; "
        "cleanup; trap - EXIT"
    )


def command_guest(lab: Lab, args: argparse.Namespace) -> None:
    if args.repeat < 1:
        raise CommandError("--repeat must be at least 1")
    if args.udp_direct_probe and not args.udp_forward:
        raise CommandError("--udp-direct-probe requires --udp-forward")
    if args.repeat > 1:
        command_guest_repeat(lab, args)
        return

    guest = validate_name(args.guest, "guest")
    label = args.label or datetime.now(timezone.utc).strftime("vm-private-runtime-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    summary = run_guest_once(lab, args, guest, label, output_dir)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    if summary["totals"]["failed"]:
        raise SystemExit(1)


def command_guest_repeat(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    label = args.label or datetime.now(timezone.utc).strftime("vm-private-runtime-%Y%m%dT%H%M%SZ")
    label = validate_name(label, "label")
    output_dir = task_output_dir(args.output_dir, label)
    guard_repo_resources(
        "VM private runtime artifacts",
        [("vm-private-runtime", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    install_args = args
    if not args.skip_install:
        recorder = StageRecorder(output_dir / "stage-report.json", label)
        try:
            artifact = recorder.run("build-artifact", lambda: build_artifact(lab, install_args))
            recorder.run(
                "install-artifact", lambda: install_artifact(lab, guest, artifact, install_args)
            )
        except Exception as error:
            summary = build_repeat_summary(guest, label, output_dir, [], args)
            summary["failure"] = {
                "stage": latest_failed_stage(recorder.report),
                "errorType": type(error).__name__,
                "error": stage_error(error),
            }
            summary["stages"] = sanitize_report(recorder.report)
            summary["totals"]["failedRuns"] = 1
            write_json(output_dir / "summary.json", summary)
            write_repeat_markdown(output_dir / "summary.md", summary)
            print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
            raise SystemExit(1)

    runs = []
    run_args = copy.copy(args)
    run_args.skip_install = True
    for index in range(1, args.repeat + 1):
        run_label = validate_name(f"{label}-{index:02d}", "label")
        run_dir = output_dir / f"run-{index:02d}"
        summary = run_guest_once(lab, run_args, guest, run_label, run_dir)
        runs.append(summarize_repeat_run(summary, run_dir))
        repeat_summary = build_repeat_summary(guest, label, output_dir, runs, args)
        write_json(output_dir / "summary.json", repeat_summary)
        write_repeat_markdown(output_dir / "summary.md", repeat_summary)

    summary = build_repeat_summary(guest, label, output_dir, runs, args)
    write_json(output_dir / "summary.json", summary)
    write_repeat_markdown(output_dir / "summary.md", summary)
    print(json.dumps({"outputDir": str(output_dir), **summary["totals"]}, sort_keys=True))
    if summary["totals"]["failedRuns"]:
        raise SystemExit(1)


def run_guest_once(
    lab: Lab,
    args: argparse.Namespace,
    guest: str,
    label: str,
    output_dir: Path,
) -> dict:
    guard_repo_resources(
        "VM private runtime artifacts",
        [("vm-private-runtime", output_dir.parent)],
        RESOURCE_LIMITS["local-collect"],
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    recorder = StageRecorder(output_dir / "stage-report.json", label)

    dns_names = list(args.dns_name or DEFAULT_DNS_NAMES)
    workload_manifest = recorder.run("load-workload-manifest", lambda: load_workload_manifest(args))
    add_required_domain_suffixes(args, dns_names, workload_manifest)
    guest_files: list[str] = []
    command_result = None
    version = None
    meta: dict = {}
    report: dict = {}
    log_text = ""
    install_report: dict = {}
    uninstall_report: dict = {}
    tcp_probe_report = {}
    udp_probe_report = {}
    ipv6_probe_report = {}
    workload_probe_report = {}
    error: Exception | None = None

    try:
        if not args.skip_install:
            artifact = recorder.run("build-artifact", lambda: build_artifact(lab, args))
            recorder.run("install-artifact", lambda: install_artifact(lab, guest, artifact, args))

        config_text, meta = recorder.run(
            "build-secret-config", lambda: build_secret_config(args, output_dir)
        )
        config_text = recorder.run(
            "augment-runtime-config", lambda: augment_runtime_config(config_text, args)
        )
        remote_config = f"/tmp/dynet-{label}-private-config.json"
        remote_quality = f"/tmp/dynet-{label}-private-quality.json" if args.quality_state else None
        remote_report = f"/tmp/dynet-{label}-private-runtime.json"
        remote_log = f"/tmp/dynet-{label}-private-runtime.err"
        remote_install = f"/tmp/dynet-{label}-private-install.json"
        remote_uninstall = f"/tmp/dynet-{label}-private-uninstall.json"
        remote_tcp_probe = f"/tmp/dynet-{label}-private-tcp-probe.json"
        remote_udp_probe = f"/tmp/dynet-{label}-private-udp-probe.json"
        remote_ipv6_probe = f"/tmp/dynet-{label}-private-ipv6-probe.json"
        remote_workload = f"/tmp/dynet-{label}-private-workload-manifest.json" if workload_manifest else None
        remote_workload_probe = f"/tmp/dynet-{label}-private-workload-probe.json"
        guest_files = [
            remote_config,
            remote_report,
            remote_log,
            remote_install,
            remote_uninstall,
            remote_tcp_probe,
            remote_udp_probe,
            remote_ipv6_probe,
            remote_workload_probe,
        ] + ([remote_quality] if remote_quality else []) + ([remote_workload] if remote_workload else [])

        recorder.run(
            "prepare-nft-dropin",
            lambda: guest_ssh(lab, guest, nft_dropin_command(), user=args.user, source=args.source),
        )
        recorder.run(
            "write-secret-config",
            lambda: write_guest_file(
                lab,
                guest,
                remote_config,
                config_text,
                user=args.user,
                source=args.source,
            ),
        )
        if args.quality_state and remote_quality:
            recorder.run(
                "write-quality-state",
                lambda: write_guest_file(
                    lab,
                    guest,
                    remote_quality,
                    Path(args.quality_state).read_text(),
                    user=args.user,
                    source=args.source,
                ),
            )
        if workload_manifest and remote_workload:
            recorder.run(
                "write-workload-manifest",
                lambda: write_guest_file(
                    lab,
                    guest,
                    remote_workload,
                    json.dumps(workload_manifest, ensure_ascii=False, sort_keys=True),
                    user=args.user,
                    source=args.source,
                ),
            )
        version = recorder.run(
            "dynet-version",
            lambda: guest_ssh(
                lab,
                guest,
                f"{q(args.dynet_bin)} version",
                user=args.user,
                source=args.source,
                check=False,
                capture=True,
            ),
        )
        command = runtime_command(label, remote_config, remote_quality, remote_workload, dns_names, args)
        logger.info("run private runtime acceptance")
        command_result = recorder.run(
            "run-acceptance",
            lambda: guest_ssh(
                lab,
                guest,
                command,
                user=args.user,
                source=args.source,
                check=False,
                capture=True,
            ),
        )
        report = recorder.run(
            "collect-runtime-report",
            lambda: read_remote_json(lab, guest, remote_report, args),
        )
        log_text = recorder.run(
            "collect-runtime-log",
            lambda: read_remote_text(lab, guest, remote_log, args),
        )
        install_report = recorder.run(
            "collect-install-report",
            lambda: read_remote_json(lab, guest, remote_install, args),
        )
        uninstall_report = recorder.run(
            "collect-uninstall-report",
            lambda: read_remote_json(lab, guest, remote_uninstall, args),
        )
        if args.tcp_forward:
            tcp_probe_report = recorder.run(
                "collect-tcp-probe-report",
                lambda: read_remote_json(lab, guest, remote_tcp_probe, args),
            )
        if args.udp_direct_probe:
            udp_probe_report = recorder.run(
                "collect-udp-probe-report",
                lambda: read_remote_json(lab, guest, remote_udp_probe, args),
            )
        if args.ipv6_no_leak:
            ipv6_probe_report = recorder.run(
                "collect-ipv6-probe-report",
                lambda: read_remote_json(lab, guest, remote_ipv6_probe, args),
            )
        if workload_manifest:
            workload_probe_report = recorder.run(
                "collect-workload-probe-report",
                lambda: read_remote_json(lab, guest, remote_workload_probe, args),
            )
    except Exception as caught:
        error = caught
    finally:
        if guest_files:
            try:
                recorder.run(
                    "cleanup-guest-files",
                    lambda: cleanup_guest_files(
                        lab, guest, guest_files, user=args.user, source=args.source
                    ),
                )
            except Exception as cleanup_error:
                if error is None:
                    error = cleanup_error

    sanitized_report = sanitize_report(report)
    sanitized_install = sanitize_report(install_report)
    sanitized_uninstall = sanitize_report(uninstall_report)
    sanitized_tcp_probe = sanitize_report(tcp_probe_report)
    sanitized_udp_probe = sanitize_report(udp_probe_report)
    sanitized_ipv6_probe = sanitize_report(ipv6_probe_report)
    sanitized_workload_probe = sanitize_report(workload_probe_report)
    write_json(output_dir / "runtime-report.json", sanitized_report)
    write_json(output_dir / "install-report.json", sanitized_install)
    write_json(output_dir / "uninstall-report.json", sanitized_uninstall)
    if args.tcp_forward:
        write_json(output_dir / "tcp-probe.json", sanitized_tcp_probe)
    if args.udp_direct_probe:
        write_json(output_dir / "udp-probe.json", sanitized_udp_probe)
    if args.ipv6_no_leak:
        write_json(output_dir / "ipv6-probe.json", sanitized_ipv6_probe)
    if workload_manifest:
        write_json(output_dir / "workload-manifest.json", sanitize_report(workload_manifest))
        write_json(output_dir / "workload-probe.json", sanitized_workload_probe)
    (output_dir / "runtime-log.txt").write_text(sanitize_text(log_text))
    (output_dir / "command-stdout.txt").write_text(
        sanitize_text(command_result.stdout if command_result else "")
    )
    (output_dir / "command-stderr.txt").write_text(
        sanitize_text(command_result.stderr if command_result else "")
    )

    if error is not None:
        summary = build_stage_failure_summary(
            guest,
            label,
            version,
            command_result,
            meta,
            recorder.report,
            error,
            dns_names,
            workload_manifest,
            args,
        )
    else:
        summary = build_summary(
            guest,
            label,
            version,
            command_result,
            meta,
            sanitized_report,
            sanitized_install,
            sanitized_uninstall,
            sanitized_tcp_probe,
            sanitized_udp_probe,
            sanitized_ipv6_probe,
            sanitized_workload_probe,
            sanitize_text(log_text),
            recorder.report,
            dns_names,
            args,
        )
    write_json(output_dir / "summary.json", summary)
    write_markdown(output_dir / "summary.md", summary)
    return summary


def read_remote_json(lab: Lab, guest: str, path: str, args: argparse.Namespace) -> dict:
    text = read_remote_text(lab, guest, path, args)
    if not text.strip():
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        return {
            "schema": "dynet-runtime/invalid-json",
            "status": "deny",
            "reason": f"invalid JSON from {path}: {error}",
        }
    if isinstance(value, dict):
        return value
    return {"schema": "dynet-runtime/unexpected-json", "valueType": type(value).__name__}


def read_remote_text(lab: Lab, guest: str, path: str, args: argparse.Namespace) -> str:
    result = guest_ssh(
        lab,
        guest,
        f"cat {q(path)} 2>/dev/null || true",
        user=args.user,
        source=args.source,
        check=False,
        capture=True,
    )
    return result.stdout


def build_summary(
    guest: str,
    label: str,
    version: subprocess.CompletedProcess[str] | None,
    command_result: subprocess.CompletedProcess[str] | None,
    meta: dict,
    report: dict,
    install_report: dict,
    uninstall_report: dict,
    tcp_probe_report: dict,
    udp_probe_report: dict,
    ipv6_probe_report: dict,
    workload_probe_report: dict,
    log_text: str,
    stage_report: dict,
    dns_names: list[str],
    args: argparse.Namespace,
) -> dict:
    stability = stability_brief(
        report,
        log_text,
        tcp_probe_report,
        udp_probe_report,
        ipv6_probe_report,
        workload_probe_report,
    )
    checks = acceptance_checks(
        report,
        install_report,
        uninstall_report,
        tcp_probe_report,
        udp_probe_report,
        ipv6_probe_report,
        workload_probe_report,
        dns_names,
        args,
        stability,
    )
    failed = [item for item in checks if not item["passed"]]
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "guest": guest,
        "label": label,
        "dynetVersion": (version.stdout or version.stderr).strip().splitlines()[-1]
        if version and (version.stdout or version.stderr).strip()
        else "",
        "metadata": meta,
        "dnsNames": dns_names,
        "upstreamDns": args.upstream_dns,
        "qualityStateUsed": bool(args.quality_state),
        "commandExitCode": command_result.returncode if command_result else None,
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "remoteSecretConfigCleaned": True,
            "resolvedIpsRedacted": True,
        },
        "runtime": runtime_brief(report),
        "selection": selection_brief(report),
        "stages": stage_report,
        "stability": stability,
        "tcpProbe": tcp_probe_report if args.tcp_forward else {},
        "udpProbe": udp_probe_report if args.udp_direct_probe else {},
        "ipv6Probe": ipv6_probe_report if args.ipv6_no_leak else {},
        "workloadProbe": workload_probe_report if args.workload_manifest else {},
        "productForwarding": {
            "tcpForwardingImplemented": bool(args.tcp_forward),
            "udpForwardingImplemented": bool(args.udp_forward),
            "ipv6NoLeakGuardEnabled": bool(args.ipv6_no_leak),
            "evidence": product_forwarding_evidence(args),
        },
        "checks": checks,
        "totals": {
            "attempted": len(checks),
            "passed": len(checks) - len(failed),
            "failed": len(failed),
        },
    }


def build_stage_failure_summary(
    guest: str,
    label: str,
    version: subprocess.CompletedProcess[str] | None,
    command_result: subprocess.CompletedProcess[str] | None,
    meta: dict,
    stage_report: dict,
    error: Exception,
    dns_names: list[str],
    workload_manifest: dict | None,
    args: argparse.Namespace,
) -> dict:
    failed_stage = latest_failed_stage(stage_report)
    checks = [
        check("pre-runtime-stages", False),
        check("remote-secret-config-cleanup", True),
    ]
    return {
        "schema": "dynet-vm-private-runtime-run/v1alpha1",
        "guest": guest,
        "label": label,
        "dynetVersion": (version.stdout or version.stderr).strip().splitlines()[-1]
        if version and (version.stdout or version.stderr).strip()
        else "",
        "metadata": meta,
        "dnsNames": dns_names,
        "upstreamDns": args.upstream_dns,
        "qualityStateUsed": bool(args.quality_state),
        "commandExitCode": command_result.returncode if command_result else None,
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
            "remoteSecretConfigCleaned": True,
            "resolvedIpsRedacted": True,
        },
        "runtime": runtime_brief({}),
        "selection": {"events": []},
        "stages": sanitize_report(stage_report),
        "stability": stability_brief({}, "", {}, {}, {}, {}),
        "tcpProbe": {},
        "udpProbe": {},
        "ipv6Probe": {},
        "workloadProbe": {"manifestLoaded": bool(workload_manifest)},
        "productForwarding": {
            "tcpForwardingImplemented": bool(args.tcp_forward),
            "udpForwardingImplemented": bool(args.udp_forward),
            "ipv6NoLeakGuardEnabled": bool(args.ipv6_no_leak),
            "evidence": "runtime was not reached; see stage report",
        },
        "failure": {
            "stage": failed_stage,
            "errorType": type(error).__name__,
            "error": stage_error(error),
        },
        "checks": checks,
        "totals": {
            "attempted": len(checks),
            "passed": 0,
            "failed": len(checks),
        },
    }


def summarize_repeat_run(summary: dict, run_dir: Path) -> dict:
    failed = int(summary.get("totals", {}).get("failed") or 0)
    stability = summary.get("stability", {})
    runtime = summary.get("runtime", {})
    return {
        "label": summary.get("label"),
        "path": str(run_dir),
        "passed": failed == 0,
        "failedChecks": failed,
        "failedStage": summary.get("failure", {}).get("stage"),
        "commandExitCode": summary.get("commandExitCode"),
        "runtimeStatus": runtime.get("status"),
        "tcpSessions": runtime.get("tcpSessions"),
        "tcpSessionFailures": runtime.get("tcpSessionFailures"),
        "tcpUpstreamBytes": runtime.get("tcpUpstreamBytes"),
        "tcpDownstreamBytes": runtime.get("tcpDownstreamBytes"),
        "udpSessions": runtime.get("udpSessions"),
        "udpSessionFailures": runtime.get("udpSessionFailures"),
        "udpUpstreamBytes": runtime.get("udpUpstreamBytes"),
        "udpDownstreamBytes": runtime.get("udpDownstreamBytes"),
        "udpDroppedPackets": runtime.get("udpDroppedPackets"),
        "ipv6PacketsDenied": runtime.get("ipv6PacketsDenied"),
        "httpsOk": stability.get("httpsOk"),
        "udpOk": stability.get("udpOk"),
        "ipv6NoLeakOk": stability.get("ipv6NoLeakOk"),
        "workloadSuccessRate": stability.get("workloadSuccessRate"),
        "closeReasons": stability.get("closeReasons", {}),
        "receiveWindowChallengeAcks": stability.get("receiveWindowChallengeAcks", 0),
        "dnsEarlyTimeouts": stability.get("dnsEarlyTimeouts", 0),
        "protocolShortReadErrors": stability.get("protocolShortReadErrors", 0),
        "pendingFrameTimeouts": stability.get("pendingFrameTimeouts", 0),
        "udpFailureTypes": stability.get("udpFailureTypes", {}),
        "ipDenials": stability.get("ipDenials", 0),
    }


def build_repeat_summary(
    guest: str,
    label: str,
    output_dir: Path,
    runs: list[dict],
    args: argparse.Namespace,
) -> dict:
    failed_runs = [run for run in runs if not run.get("passed")]
    totals = {
        "runs": len(runs),
        "passedRuns": len(runs) - len(failed_runs),
        "failedRuns": len(failed_runs),
        "receiveWindowChallengeAcks": sum(
            int(run.get("receiveWindowChallengeAcks") or 0) for run in runs
        ),
        "dnsEarlyTimeouts": sum(int(run.get("dnsEarlyTimeouts") or 0) for run in runs),
        "protocolShortReadErrors": sum(
            int(run.get("protocolShortReadErrors") or 0) for run in runs
        ),
        "pendingFrameTimeouts": sum(int(run.get("pendingFrameTimeouts") or 0) for run in runs),
        "udpSessionFailures": sum(int(run.get("udpSessionFailures") or 0) for run in runs),
        "udpDroppedPackets": sum(int(run.get("udpDroppedPackets") or 0) for run in runs),
        "ipv6PacketsDenied": sum(int(run.get("ipv6PacketsDenied") or 0) for run in runs),
        "ipDenials": sum(int(run.get("ipDenials") or 0) for run in runs),
        "workloadFailedRuns": sum(
            1
            for run in runs
            if run.get("workloadSuccessRate") is not None
            and float(run.get("workloadSuccessRate") or 0) < float(args.workload_min_success_rate)
        ),
    }
    return {
        "schema": "dynet-vm-private-runtime-repeat/v1alpha1",
        "guest": guest,
        "label": label,
        "outputDir": str(output_dir),
        "tcpForward": bool(args.tcp_forward),
        "udpForward": bool(args.udp_forward),
        "udpDirectProbe": bool(args.udp_direct_probe),
        "ipv6NoLeak": bool(args.ipv6_no_leak),
        "qualityStateUsed": bool(args.quality_state),
        "runs": runs,
        "totals": totals,
    }


def acceptance_checks(
    report: dict,
    install_report: dict,
    uninstall_report: dict,
    tcp_probe_report: dict,
    udp_probe_report: dict,
    ipv6_probe_report: dict,
    workload_probe_report: dict,
    dns_names: list[str],
    args: argparse.Namespace,
    stability: dict,
) -> list[dict]:
    events = report.get("events", [])
    event_kinds = {event.get("kind") for event in events if isinstance(event, dict)}
    queries = {
        str(event.get("fields", {}).get("query"))
        for event in events
        if isinstance(event, dict) and isinstance(event.get("fields"), dict)
    }
    checks = [
        check("install-apply", has_lifecycle_pass(install_report, "apply-engine")),
        check("runtime-pass", report.get("status") == "pass"),
        check("tun-observed", int(report.get("tunPackets") or 0) >= 1),
        check("dns-queries", int(report.get("dnsQueries") or 0) >= len(dns_names)),
        check("dns-proxied", int(report.get("proxiedDnsQueries") or 0) >= len(dns_names)),
        check("dns-records", int(report.get("dnsRecords") or 0) >= len(dns_names)),
        check("rule-bypass", {"rule-matched", "plan-bypassed"}.issubset(event_kinds)),
        check("dialer-selected", "dialer-cascade-selected" in event_kinds),
        check("all-dns-names-observed", all(name in queries for name in dns_names)),
        check("uninstall-cleanup", has_lifecycle_pass(uninstall_report, "uninstall-engine")),
    ]
    if args.tcp_forward:
        tcp_results = [
            item
            for item in tcp_probe_report.get("results", [])
            if isinstance(item, dict)
        ]
        tcp_ok_names = {
            item.get("name")
            for item in tcp_results
            if item.get("https", {}).get("ok") is True
        }
        checks.extend(
            [
                check(
                    "tcp-sessions",
                    int(report.get("tcpSessions") or 0) >= len(dns_names),
                ),
                check(
                    "tcp-upstream-bytes",
                    int(report.get("tcpUpstreamBytes") or 0) > 0,
                ),
                check(
                    "tcp-downstream-bytes",
                    int(report.get("tcpDownstreamBytes") or 0) > 0,
                ),
                check(
                    "tcp-session-events",
                    {
                        "tcp-session-started",
                        "tcp-session-attributed",
                        "tcp-session-established",
                        "tcp-session-payload-first-write",
                    }.issubset(event_kinds),
                ),
                check(
                    "tcp-blackbox-https",
                    all(name in tcp_ok_names for name in dns_names),
                ),
                check(
                    "tcp-no-session-failures",
                    int(report.get("tcpSessionFailures") or 0) == 0
                    and "tcp-session-failed" not in event_kinds,
                ),
                check(
                    "tcp-session-closed",
                    int(stability.get("tcpClosedSessions") or 0) >= len(dns_names),
                ),
                check(
                    "tcp-no-protocol-short-read",
                    int(stability.get("protocolShortReadErrors") or 0) == 0,
                ),
            ]
        )
    if args.udp_forward:
        checks.extend(
            [
                check(
                    "udp-session-events",
                    "udp-session-started" in event_kinds
                    and (
                        "udp-session-established" in event_kinds
                        or "udp-session-denied" in event_kinds
                        or "udp-session-failed" in event_kinds
                    ),
                ),
                check(
                    "udp-attribution-events",
                    "udp-session-attributed" in event_kinds
                    and (
                        {"rule-matched", "plan-bypassed"}.issubset(event_kinds)
                        or "route-matched" in event_kinds
                    ),
                ),
            ]
        )
        if args.udp_direct_probe:
            checks.extend(
                [
                    check("udp-direct-blackbox", udp_probe_report.get("ok") is True),
                    check("udp-sessions", int(report.get("udpSessions") or 0) >= 1),
                    check("udp-upstream-bytes", int(report.get("udpUpstreamBytes") or 0) > 0),
                    check(
                        "udp-downstream-bytes",
                        int(report.get("udpDownstreamBytes") or 0) > 0,
                    ),
                    check("udp-no-session-failures", int(report.get("udpSessionFailures") or 0) == 0),
                ]
            )
        else:
            checks.append(
                check(
                    "udp-fail-closed",
                    "udp-session-denied" in event_kinds
                    or int(report.get("udpDroppedPackets") or 0) > 0,
                )
            )
    if args.ipv6_no_leak:
        checks.extend(
            [
                check("ipv6-blackbox-no-response", ipv6_probe_report.get("ok") is True),
                check("ipv6-denied-counter", int(report.get("ipv6PacketsDenied") or 0) >= 1),
                check("ipv6-denied-event", "ip-packet-denied" in event_kinds),
            ]
        )
    if args.workload_manifest:
        workload_results = [
            item
            for item in workload_probe_report.get("results", [])
            if isinstance(item, dict)
        ]
        workload_domains_seen = {
            str(item.get("domain"))
            for item in workload_results
            if isinstance(item.get("domain"), str)
        }
        successful_non_dns = [
            item
            for item in workload_results
            if item.get("probe") != "dns" and item.get("ok") is True
        ]
        checks.extend(
            [
                check("workload-attempted", int(workload_probe_report.get("totals", {}).get("count") or 0) > 0),
                check(
                    "workload-success-rate",
                    float(workload_probe_report.get("totals", {}).get("successRate") or 0)
                    >= float(args.workload_min_success_rate),
                ),
                check(
                    "workload-dns-observed",
                    all(domain in queries for domain in workload_domains_seen),
                ),
                check(
                    "workload-tcp-sessions",
                    int(report.get("tcpSessions") or 0)
                    >= len(dns_names) + len(successful_non_dns),
                ),
            ]
        )
    return checks


def check(name: str, passed: bool) -> dict:
    return {"name": name, "passed": bool(passed)}


def product_forwarding_evidence(args: argparse.Namespace) -> str:
    parts = []
    if args.tcp_forward:
        parts.append("TCP session lifecycle and byte counters are enabled")
    if args.udp_forward:
        if args.udp_direct_probe:
            parts.append("UDP direct black-box probe and UDP session counters are enabled")
        else:
            parts.append("UDP forwarding gate is enabled; unsupported paths must fail closed")
    if args.ipv6_no_leak:
        parts.append("IPv6 no-leak probe and ip-packet-denied events are enabled")
    if args.workload_manifest:
        parts.append("workload manifest replay is enabled through the same TUN/Private runtime")
    if not parts:
        return "runtime reports TUN packet observation and DNS hijack only; forwarding experiments were not enabled"
    return "; ".join(parts)


def has_lifecycle_pass(report: dict, name: str) -> bool:
    for item in report.get("checks", []):
        if item.get("name") == name and item.get("status") == "pass":
            return True
    return False


def runtime_brief(report: dict) -> dict:
    return {
        "status": report.get("status"),
        "reason": report.get("reason"),
        "tunPackets": report.get("tunPackets"),
        "dnsQueries": report.get("dnsQueries"),
        "routeDecisions": report.get("routeDecisions"),
        "proxiedDnsQueries": report.get("proxiedDnsQueries"),
        "dnsRecords": report.get("dnsRecords"),
        "ipv6PacketsDenied": report.get("ipv6PacketsDenied"),
        "tcpSessions": report.get("tcpSessions"),
        "tcpSessionFailures": report.get("tcpSessionFailures"),
        "tcpUpstreamBytes": report.get("tcpUpstreamBytes"),
        "tcpDownstreamBytes": report.get("tcpDownstreamBytes"),
        "udpSessions": report.get("udpSessions"),
        "udpSessionFailures": report.get("udpSessionFailures"),
        "udpUpstreamBytes": report.get("udpUpstreamBytes"),
        "udpDownstreamBytes": report.get("udpDownstreamBytes"),
        "udpDroppedPackets": report.get("udpDroppedPackets"),
    }


def selection_brief(report: dict) -> dict:
    rows = []
    for event in report.get("events", []):
        if not isinstance(event, dict):
            continue
        kind = event.get("kind")
        if kind not in {
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
        }:
            continue
        fields = event.get("fields", {})
        if isinstance(fields, dict):
            rows.append({"kind": kind, "fields": fields})
    return {"events": rows}


def fields(event: dict) -> dict[str, str]:
    value = event.get("fields", {})
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def stability_brief(
    report: dict,
    log_text: str,
    tcp_probe_report: dict,
    udp_probe_report: dict,
    ipv6_probe_report: dict,
    workload_probe_report: dict,
) -> dict:
    events = [event for event in report.get("events", []) if isinstance(event, dict)]
    close_reasons: Counter[str] = Counter()
    failure_types: Counter[str] = Counter()
    udp_close_reasons: Counter[str] = Counter()
    udp_failure_types: Counter[str] = Counter()
    ip_denials = 0
    session_marks: dict[str, dict[str, int]] = {}
    for event in events:
        kind = str(event.get("kind"))
        event_fields = fields(event)
        session = event_fields.get("session")
        if kind == "ip-packet-denied":
            ip_denials += 1
        if kind == "tcp-session-closed":
            close_reasons[event_fields.get("reason", "<unknown>")] += 1
        if kind == "tcp-session-failed":
            failure_types[event_fields.get("errorType", "<unknown>")] += 1
        if kind == "udp-session-closed":
            udp_close_reasons[event_fields.get("reason", "<unknown>")] += 1
        if kind in {"udp-session-denied", "udp-session-failed"}:
            udp_failure_types[event_fields.get("errorType", "<unknown>")] += 1
        if session and kind.startswith("tcp-session-"):
            timestamp = event.get("emittedAtUnixMs")
            if isinstance(timestamp, int):
                session_marks.setdefault(session, {})[kind] = timestamp

    session_timings = []
    for session, marks in sorted(session_marks.items()):
        start = marks.get("tcp-session-started")
        if start is None:
            continue
        row = {"session": session}
        for key, value in {
            "attributedMs": marks.get("tcp-session-attributed"),
            "establishedMs": marks.get("tcp-session-established"),
            "firstPayloadMs": marks.get("tcp-session-payload-first-write"),
            "firstDownstreamMs": marks.get("tcp-session-payload-received"),
            "closedMs": marks.get("tcp-session-closed"),
            "failedMs": marks.get("tcp-session-failed"),
        }.items():
            if value is not None:
                row[key] = value - start
        session_timings.append(row)

    tcp_results = [
        item for item in tcp_probe_report.get("results", []) if isinstance(item, dict)
    ]
    https_ok = {
        str(item.get("name")): bool(item.get("https", {}).get("ok"))
        for item in tcp_results
    }
    workload_totals = workload_probe_report.get("totals", {})
    result = {
        name: log_text.count(pattern) for name, pattern in STABILITY_PATTERNS.items()
    }
    result.update(
        {
            "tcpClosedSessions": sum(close_reasons.values()),
            "closeReasons": dict(close_reasons),
            "tcpFailureTypes": dict(failure_types),
            "udpCloseReasons": dict(udp_close_reasons),
            "udpFailureTypes": dict(udp_failure_types),
            "ipDenials": ip_denials,
            "udpOk": bool(udp_probe_report.get("ok")) if udp_probe_report else None,
            "ipv6NoLeakOk": bool(ipv6_probe_report.get("ok")) if ipv6_probe_report else None,
            "workloadSuccessRate": workload_totals.get("successRate")
            if workload_probe_report
            else None,
            "workloadErrors": workload_probe_report.get("errors", [])
            if workload_probe_report
            else [],
            "httpsOk": https_ok,
            "sessionTimings": session_timings,
        }
    )
    return result


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


def write_markdown(path: Path, summary: dict) -> None:
    lines = [
        "# VM Private Runtime Acceptance",
        "",
        f"- guest: `{summary['guest']}`",
        f"- dns names: `{', '.join(summary['dnsNames'])}`",
        f"- attempted checks: `{summary['totals']['attempted']}`",
        f"- passed: `{summary['totals']['passed']}`",
        f"- failed: `{summary['totals']['failed']}`",
        f"- remote secret config cleaned: `{summary['privacy']['remoteSecretConfigCleaned']}`",
        "",
        "## Runtime",
        "",
    ]
    for key, value in summary["runtime"].items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Checks", ""])
    for item in summary["checks"]:
        lines.append(f"- `{item['name']}` passed=`{item['passed']}`")
    if summary.get("failure"):
        lines.extend(
            [
                "",
                "## Failure",
                "",
                f"- stage: `{summary['failure'].get('stage')}`",
                f"- errorType: `{summary['failure'].get('errorType')}`",
                f"- error: `{summary['failure'].get('error')}`",
            ]
        )
    if summary.get("stability"):
        lines.extend(["", "## Stability", ""])
        for key, value in summary["stability"].items():
            if key == "sessionTimings":
                continue
            lines.append(f"- {key}: `{value}`")
    if summary.get("workloadProbe"):
        workload = summary["workloadProbe"]
        lines.extend(["", "## Workload", ""])
        totals = workload.get("totals", {})
        lines.append(f"- attempted: `{totals.get('count')}`")
        lines.append(f"- success rate: `{totals.get('successRate')}`")
        lines.append(f"- errors: `{workload.get('errors', [])}`")
        for item in workload.get("byBehavior", []):
            lines.append(
                f"- behavior `{item['key']}` success={item['success']}/{item['count']} "
                f"rate={item['successRate']}"
            )
    lines.extend(["", "## Product Forwarding", "", summary["productForwarding"]["evidence"]])
    path.write_text("\n".join(lines) + "\n")


def write_repeat_markdown(path: Path, summary: dict) -> None:
    lines = [
        "# VM Private Runtime Repeat Acceptance",
        "",
        f"- guest: `{summary['guest']}`",
        f"- runs: `{summary['totals']['runs']}`",
        f"- passed runs: `{summary['totals']['passedRuns']}`",
        f"- failed runs: `{summary['totals']['failedRuns']}`",
        f"- receive-window challenge ACKs: `{summary['totals']['receiveWindowChallengeAcks']}`",
        f"- DNS early timeouts: `{summary['totals']['dnsEarlyTimeouts']}`",
        f"- protocol short-read errors: `{summary['totals']['protocolShortReadErrors']}`",
        f"- UDP session failures: `{summary['totals']['udpSessionFailures']}`",
        f"- UDP dropped packets: `{summary['totals']['udpDroppedPackets']}`",
        f"- IPv6 packets denied: `{summary['totals']['ipv6PacketsDenied']}`",
        f"- workload failed runs: `{summary['totals'].get('workloadFailedRuns')}`",
        "",
        "## Runs",
        "",
    ]
    for run in summary["runs"]:
        lines.append(
            f"- `{run['label']}` passed=`{run['passed']}` "
            f"failedChecks=`{run['failedChecks']}` tcpFailures=`{run['tcpSessionFailures']}` "
            f"udpFailures=`{run['udpSessionFailures']}` ipv6Denied=`{run['ipv6PacketsDenied']}` "
            f"httpsOk=`{run['httpsOk']}` udpOk=`{run['udpOk']}` "
            f"ipv6NoLeakOk=`{run['ipv6NoLeakOk']}` workloadSR=`{run['workloadSuccessRate']}` "
            f"stage=`{run['failedStage']}`"
        )
    path.write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run dynet Private cascade runtime acceptance inside a disposable VM guest."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    guest = subparsers.add_parser("guest")
    guest.add_argument("guest")
    guest.add_argument("--label")
    guest.add_argument("--output-dir")
    guest.add_argument("--user", default=DEFAULT_VM_USER)
    guest.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest.add_argument("--dns-name", action="append")
    guest.add_argument("--quality-state")
    guest.add_argument("--skip-install", action="store_true")
    guest.add_argument("--artifact")
    guest.add_argument("--target", default="x86_64-unknown-linux-gnu")
    guest.add_argument("--release", action="store_true")
    guest.add_argument("--dynet-bin", default="/usr/local/bin/dynet")
    guest.add_argument("--timeout", type=int, default=30)
    guest.add_argument("--dns-timeout", type=int, default=35)
    guest.add_argument("--upstream-dns", default="8.8.8.8:53")
    guest.add_argument("--tcp-forward", action="store_true")
    guest.add_argument("--udp-forward", action="store_true")
    guest.add_argument("--udp-direct-probe", action="store_true")
    guest.add_argument("--udp-target", default="1.1.1.1:123")
    guest.add_argument("--ipv6-no-leak", action="store_true")
    guest.add_argument("--ipv6-target", default="[2606:4700:4700::1111]:443")
    guest.add_argument("--workload-manifest")
    guest.add_argument("--workload-min-success-rate", type=float, default=0.75)
    guest.add_argument(
        "--no-workload-respect-schedule",
        action="store_false",
        dest="workload_respect_schedule",
        help="ignore workload manifest scheduled offsets inside the VM runtime probe",
    )
    guest.add_argument("--repeat", type=int, default=1)
    guest.add_argument("--tun-target", default="203.0.113.10")
    guest.add_argument("--tunnel-name", default="Tunnel")
    guest.add_argument("--filter", default="Basic-美国")
    guest.add_argument("--limit", type=int, default=4)
    guest.add_argument("--strategy-key", default="cascade-quality")
    guest.add_argument(
        "--no-resolve-tunnel-server",
        action="store_false",
        dest="resolve_tunnel_server",
        help="do not resolve airport server bootstrap IPs into the temporary secret config",
    )
    guest.add_argument("--domain", action="append", default=[])
    guest.add_argument("--domain-suffix", action="append", default=[])
    guest.add_argument("--supported-type", action="append", default=["vmess", "trojan"])
    guest.set_defaults(resolve_tunnel_server=True)
    guest.set_defaults(workload_respect_schedule=True)
    guest.set_defaults(handler=command_guest)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    args.handler(lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
