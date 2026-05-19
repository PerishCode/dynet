#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone

from common import (
    DEFAULT_VM_USER,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_local_resources,
    guard_remote_resources,
    guest_ssh,
    q,
    safe_local_lab_dir,
    validate_name,
)


HOST_COMMANDS: dict[str, str] = {
    "host.txt": "date -Is; hostname; uname -a; uptime",
    "host-route.txt": "ip route; printf '\\n'; ip -brief addr",
    "host-resolver.txt": "cat /etc/resolv.conf",
    "host-nft.txt": "nft list ruleset",
    "virsh-domain.txt": "virsh dominfo {guest}; printf '\\n'; virsh domifaddr {guest} --source lease; printf '\\n'; virsh domifaddr {guest} --source agent || true",
    "virsh-net.txt": "virsh net-list --all; printf '\\n'; virsh net-info default || true",
    "virsh-pool.txt": "virsh pool-list --all --details",
    "virt-log.txt": "journalctl -u libvirtd -n 200 --no-pager || true",
}

GUEST_COMMANDS: dict[str, str] = {
    "guest.txt": "date -Is; hostname; uname -a; cat /etc/os-release",
    "guest-network.txt": "ip -brief addr; printf '\\n'; ip route; printf '\\n'; resolvectl status 2>/dev/null || cat /etc/resolv.conf",
    "guest-services.txt": "systemctl status qemu-guest-agent --no-pager || true; printf '\\n'; cloud-init status --long || true",
    "guest-processes.txt": "ps -ef; printf '\\n'; ss -lntup || true",
    "guest-dynet.txt": "command -v dynet; dynet version; dynet check --format json",
    "guest-journal.txt": "journalctl -n 300 --no-pager || true",
}


def remote_write(lab: Lab, path: str, content: str) -> None:
    path = lab.assert_path(path)
    lab.ssh(f"cat > {q(path)}", input_text=content, dry_run_ok=True)


def capture_host(lab: Lab, guest: str, remote_dir: str) -> None:
    for filename, template in HOST_COMMANDS.items():
        command = template.format(guest=guest)
        wrapped = f"set +e; {command}; printf '\\n[exit_code] %s\\n' \"$?\""
        result = lab.ssh(wrapped, capture=True)
        text = (result.stdout or "") + (result.stderr or "")
        remote_write(lab, f"{remote_dir}/{filename}", text)


def capture_guest(
    lab: Lab,
    guest: str,
    remote_dir: str,
    *,
    user: str,
    source: str,
) -> None:
    for filename, command in GUEST_COMMANDS.items():
        wrapped = f"set +e; {command}; printf '\\n[exit_code] %s\\n' \"$?\""
        result = guest_ssh(lab, guest, wrapped, user=user, source=source, capture=True)
        text = (result.stdout or "") + (result.stderr or "")
        remote_write(lab, f"{remote_dir}/{filename}", text)


def collect_guest(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    user = args.user
    source = args.source

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label = validate_name(args.label or "smoke", "label")
    name = f"{guest}-{label}-{stamp}"
    remote_dir = lab.path("artifacts", "collect", name)
    remote_tar = f"{remote_dir}.tar.gz"
    local_dir = None
    if not args.no_fetch:
        local_dir = safe_local_lab_dir(args.output, "collect")

    guard_remote_resources(
        lab,
        "remote evidence collection cache",
        [("collect", lab.path("artifacts", "collect"))],
        RESOURCE_LIMITS["collect"],
    )
    if local_dir is not None:
        guard_local_resources(
            "local evidence collection cache",
            [("collect", local_dir)],
            RESOURCE_LIMITS["local-collect"],
        )

    lab.ssh(f"install -d -m 0755 {q(remote_dir)}", dry_run_ok=True)
    capture_host(lab, guest, remote_dir)
    capture_guest(lab, guest, remote_dir, user=user, source=source)
    lab.ssh(
        f"tar -C {q(lab.path('artifacts', 'collect'))} -czf {q(remote_tar)} {q(name)}",
        dry_run_ok=True,
    )

    print(remote_tar)
    if local_dir is not None:
        local_path = local_dir / f"{name}.tar.gz"
        lab.scp_from_host(remote_tar, local_path)
        print(local_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect dynet lab evidence bundles.")
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    guest_parser = subparsers.add_parser("guest", help="collect host and guest evidence")
    guest_parser.add_argument("guest")
    guest_parser.add_argument("--label")
    guest_parser.add_argument("--user", default=DEFAULT_VM_USER)
    guest_parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    guest_parser.add_argument("--output", help="local output directory")
    guest_parser.add_argument("--no-fetch", action="store_true")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {"guest": collect_guest}
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
