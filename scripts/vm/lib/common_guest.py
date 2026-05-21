from __future__ import annotations

import posixpath
import subprocess
from typing import Sequence

from common import (
    DEFAULT_VM_USER,
    GUEST_SSH_OPTS,
    CommandError,
    Lab,
    join,
    q,
    validate_name,
)


def guest_key_path(lab: Lab) -> str:
    return lab.path("seed", "dynet-lab_ed25519")


def guest_known_hosts_path(lab: Lab) -> str:
    return lab.path("seed", "known_hosts")


def ensure_guest_key(lab: Lab) -> None:
    key = guest_key_path(lab)
    command = (
        f"set -e; install -d -m 0755 {q(lab.path('seed'))}; "
        f"test -f {q(key)} || ssh-keygen -q -t ed25519 -N '' "
        f"-C dynet-lab -f {q(key)}; chmod 0600 {q(key)}; "
        f"chmod 0644 {q(key + '.pub')}; cat {q(key + '.pub')}"
    )
    result = lab.ssh(command, capture=True, dry_run_ok=True)
    if result.stdout:
        print(result.stdout.strip())


def read_guest_public_key(lab: Lab) -> str:
    public_key_path = guest_key_path(lab) + ".pub"
    result = lab.ssh(
        f"if test -f {q(public_key_path)}; then cat {q(public_key_path)}; fi",
        capture=True,
    )
    public_key = result.stdout.strip()
    if not public_key:
        raise CommandError("guest public key is missing; run guest key-ensure first")
    return public_key


def guest_ip(lab: Lab, name: str, source: str = "lease") -> str:
    validate_name(name, "guest")
    source = validate_name(source, "address source")
    command = (
        f"virsh domifaddr {q(name)} --source {q(source)} 2>/dev/null "
        "| awk '/ipv4/ { split($4, a, \"/\"); "
        "if ($1 != \"lo\" && a[1] != \"127.0.0.1\") { print a[1]; exit } }'"
    )
    result = lab.ssh(command, capture=True)
    address = result.stdout.strip()
    if not address:
        raise CommandError(f"could not resolve IPv4 address for guest {name!r} via {source!r}")
    return address


def guest_ssh_command(
    lab: Lab,
    name: str,
    *,
    user: str = DEFAULT_VM_USER,
    command: str | None = None,
    source: str = "lease",
) -> list[str]:
    address = guest_ip(lab, name, source=source)
    remote: list[str] = [
        "ssh",
        *GUEST_SSH_OPTS,
        "-o",
        f"UserKnownHostsFile={guest_known_hosts_path(lab)}",
        "-i",
        guest_key_path(lab),
        f"{user}@{address}",
    ]
    if command:
        remote.append(f"sh -lc {q(command)}")
    return remote


def guest_ssh(
    lab: Lab,
    name: str,
    command: str,
    *,
    user: str = DEFAULT_VM_USER,
    source: str = "lease",
    check: bool = True,
    capture: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return lab.ssh(
        join(guest_ssh_command(lab, name, user=user, command=command, source=source)),
        check=check,
        capture=capture,
        input_text=input_text,
        dry_run_ok=True,
    )


def guest_scp_from_host(
    lab: Lab,
    name: str,
    host_path: str,
    guest_path: str,
    *,
    user: str = DEFAULT_VM_USER,
    source: str = "lease",
) -> None:
    address = guest_ip(lab, name, source=source)
    host_path = lab.assert_path(host_path)
    command = join(
        [
            "scp",
            *GUEST_SSH_OPTS,
            "-o",
            f"UserKnownHostsFile={guest_known_hosts_path(lab)}",
            "-i",
            guest_key_path(lab),
            host_path,
            f"{user}@{address}:{guest_path}",
        ]
    )
    lab.ssh(command, dry_run_ok=True)


def guest_scp_to_host(
    lab: Lab,
    name: str,
    guest_path: str,
    host_path: str,
    *,
    user: str = DEFAULT_VM_USER,
    source: str = "lease",
) -> None:
    address = guest_ip(lab, name, source=source)
    host_path = lab.assert_path(host_path)
    lab.ssh(f"install -d -m 0755 {q(posixpath.dirname(host_path))}", dry_run_ok=True)
    command = join(
        [
            "scp",
            *GUEST_SSH_OPTS,
            "-o",
            f"UserKnownHostsFile={guest_known_hosts_path(lab)}",
            "-i",
            guest_key_path(lab),
            f"{user}@{address}:{guest_path}",
            host_path,
        ]
    )
    lab.ssh(command, dry_run_ok=True)


def split_remote_command(
    tokens: Sequence[str],
    *,
    user: str = DEFAULT_VM_USER,
    source: str = "lease",
) -> tuple[str, str, list[str]]:
    rest = list(tokens)
    while rest:
        if rest[0] == "--":
            return user, source, rest[1:]
        if rest[0] == "--user" and len(rest) >= 2:
            user = rest[1]
            rest = rest[2:]
            continue
        if rest[0].startswith("--user="):
            user = rest[0].split("=", 1)[1]
            rest = rest[1:]
            continue
        if rest[0] == "--source" and len(rest) >= 2:
            source = rest[1]
            rest = rest[2:]
            continue
        if rest[0].startswith("--source="):
            source = rest[0].split("=", 1)[1]
            rest = rest[1:]
            continue
        break
    return user, source, rest
