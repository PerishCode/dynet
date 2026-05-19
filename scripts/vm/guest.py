#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys

from common import (
    DEFAULT_VM_USER,
    CommandError,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    ensure_guest_key,
    guest_ip,
    guest_ssh_command,
    guard_remote_resources,
    join,
    q,
    read_guest_public_key,
    require_catalog_image,
    split_remote_command,
    validate_name,
)


def key_ensure(lab: Lab, _: argparse.Namespace) -> None:
    ensure_guest_key(lab)


def status(lab: Lab, _: argparse.Namespace) -> None:
    command = (
        "set -e; "
        "printf 'domains\\n'; virsh list --all; "
        "printf '\\nnetworks\\n'; virsh net-list --all; "
        "printf '\\npools\\n'; virsh pool-list --all"
    )
    lab.ssh(command)


def render_cloud_init(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "guest")
    image = require_catalog_image(args.image)
    user = args.user or image.default_user
    public_key = read_guest_public_key(lab)
    seed_dir = lab.path("seed", name)
    user_data_path = lab.path("seed", name, "user-data")
    meta_data_path = lab.path("seed", name, "meta-data")
    seed_iso = lab.path("seed", name + ".iso")
    guard_remote_resources(
        lab,
        "cloud-init seed cache",
        [("seed", lab.path("seed"))],
        RESOURCE_LIMITS["seed"],
    )
    user_data = f"""#cloud-config
hostname: {name}
manage_etc_hosts: true
ssh_pwauth: false
users:
  - default
  - name: {user}
    groups: [sudo]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - {public_key}
package_update: true
packages:
  - ca-certificates
  - curl
  - dnsutils
  - iproute2
  - jq
  - qemu-guest-agent
  - tcpdump
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
"""
    meta_data = f"""instance-id: {name}
local-hostname: {name}
"""
    command = (
        "set -e; "
        f"install -d -m 0755 {q(seed_dir)}; "
        f"cat > {q(user_data_path)}; "
        f"cat > {q(meta_data_path)} <<'EOF_META'\n"
        f"{meta_data}EOF_META\n"
        f"cloud-localds {q(seed_iso)} "
        f"{q(user_data_path)} {q(meta_data_path)}"
    )
    lab.ssh(command, input_text=user_data, dry_run_ok=True)


def define(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "guest")
    image = require_catalog_image(args.image)
    disk = lab.path("vms", f"{name}.qcow2")
    seed = lab.path("seed", f"{name}.iso")
    network = validate_name(args.network, "network")
    command = (
        "set -e; "
        f"test -s {q(disk)} || "
        f"(echo 'guest overlay missing: {disk}; run image overlay {image.name} {name}' >&2; exit 1); "
        f"test -s {q(seed)} || "
        f"(echo 'cloud-init seed missing: {seed}; run guest cloud-init {name}' >&2; exit 1); "
        f"virsh net-info {q(network)} | grep -q '^Active:.*yes' || "
        f"(echo 'network is not active: {network}; decide before starting it' >&2; exit 1); "
        "virt-install "
        f"--name {q(name)} "
        f"--memory {int(args.memory)} "
        f"--vcpus {int(args.vcpus)} "
        "--import "
        f"--disk path={q(disk)},format=qcow2,bus=virtio "
        f"--disk path={q(seed)},device=cdrom "
        f"--network network={q(network)},model=virtio "
        f"--osinfo {q(image.osinfo)} "
        "--graphics none "
        "--noautoconsole"
    )
    lab.ssh(command, dry_run_ok=True)


def start(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "guest")
    lab.ssh(f"virsh start {q(name)}", dry_run_ok=True)


def shutdown(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "guest")
    lab.ssh(f"virsh shutdown {q(name)}", dry_run_ok=True)


def destroy(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "guest")
    if not args.yes:
        raise CommandError("destroy requires --yes")
    lab.ssh(f"virsh destroy {q(name)}", dry_run_ok=True)


def undefine(lab: Lab, args: argparse.Namespace) -> None:
    name = validate_name(args.name, "guest")
    if not args.yes:
        raise CommandError("undefine requires --yes")
    lab.ssh(f"virsh undefine {q(name)} --nvram --remove-all-storage", dry_run_ok=True)


def ip(lab: Lab, args: argparse.Namespace) -> None:
    print(guest_ip(lab, args.name, source=args.source))


def ssh(lab: Lab, args: argparse.Namespace) -> None:
    user, source, remote_command = split_remote_command(
        args.remote_command,
        user=args.user,
        source=args.source,
    )
    command = " ".join(remote_command) if remote_command else None
    remote = guest_ssh_command(
        lab,
        args.name,
        user=user,
        command=command,
        source=source,
    )
    lab.ssh(join(remote), dry_run_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage dynet disposable VM guests on the lab host."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("key-ensure", help="ensure the host-side guest SSH key")
    subparsers.add_parser("status", help="show libvirt domains, networks, and pools")

    cloud_init = subparsers.add_parser(
        "cloud-init", help="render cloud-init seed files for a guest"
    )
    cloud_init.add_argument("name")
    cloud_init.add_argument("--image", default="ubuntu-24.04")
    cloud_init.add_argument("--user")

    define_parser = subparsers.add_parser("define", help="define/import a guest")
    define_parser.add_argument("name")
    define_parser.add_argument("--image", default="ubuntu-24.04")
    define_parser.add_argument("--user")
    define_parser.add_argument("--memory", type=int, default=2048)
    define_parser.add_argument("--vcpus", type=int, default=2)
    define_parser.add_argument("--network", default="default")

    for command_name, help_text in (
        ("start", "start a defined guest"),
        ("shutdown", "ask a guest to shut down"),
    ):
        sub = subparsers.add_parser(command_name, help=help_text)
        sub.add_argument("name")

    for command_name, help_text in (
        ("destroy", "force-stop a guest"),
        ("undefine", "remove a guest definition and storage"),
    ):
        sub = subparsers.add_parser(command_name, help=help_text)
        sub.add_argument("name")
        sub.add_argument("--yes", action="store_true", help="confirm destructive action")

    ip_parser = subparsers.add_parser("ip", help="print guest IPv4 address")
    ip_parser.add_argument("name")
    ip_parser.add_argument("--source", default="lease", choices=["lease", "agent"])

    ssh_parser = subparsers.add_parser("ssh", help="run a command in a guest via host")
    ssh_parser.add_argument("name")
    ssh_parser.add_argument("--user", default=DEFAULT_VM_USER)
    ssh_parser.add_argument("--source", default="lease", choices=["lease", "agent"])
    ssh_parser.add_argument("remote_command", nargs=argparse.REMAINDER)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {
        "key-ensure": key_ensure,
        "status": status,
        "cloud-init": render_cloud_init,
        "define": define,
        "start": start,
        "shutdown": shutdown,
        "destroy": destroy,
        "undefine": undefine,
        "ip": ip,
        "ssh": ssh,
    }
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
