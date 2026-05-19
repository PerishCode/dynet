#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from common import (
    CommandError,
    IMAGE_CATALOG,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    assert_local_lab_path,
    guard_local_resources,
    guard_remote_resources,
    logger,
    q,
    require_catalog_image,
    safe_local_lab_dir,
    validate_name,
)


@dataclass(frozen=True)
class RemoteBucket:
    name: str
    label: str
    parts: tuple[str, ...]
    selector: str
    limit_key: str
    default_days: int


@dataclass(frozen=True)
class LocalBucket:
    name: str
    label: str
    parts: tuple[str, ...]
    patterns: tuple[str, ...]
    limit_key: str
    default_days: int


REMOTE_BUCKETS: dict[str, RemoteBucket] = {
    "incoming": RemoteBucket(
        "incoming",
        "incoming artifact cache",
        ("artifacts", "incoming"),
        "-type f",
        "incoming",
        7,
    ),
    "collect": RemoteBucket(
        "collect",
        "remote evidence collection cache",
        ("artifacts", "collect"),
        "\\( -type f -name '*.tar.gz' -o -type d \\)",
        "collect",
        7,
    ),
    "pcap": RemoteBucket(
        "pcap",
        "remote packet capture cache",
        ("artifacts", "pcap"),
        "-type f -name '*.pcap'",
        "pcap",
        7,
    ),
    "partial-images": RemoteBucket(
        "partial-images",
        "partial image downloads",
        ("images",),
        "-type f -name '*.partial'",
        "images",
        1,
    ),
}


LOCAL_BUCKETS: dict[str, LocalBucket] = {
    "collect": LocalBucket(
        "collect",
        "local evidence collection cache",
        ("collect",),
        ("*.tar.gz",),
        "local-collect",
        7,
    ),
    "pcap": LocalBucket(
        "pcap",
        "local packet capture cache",
        ("pcap",),
        ("*.pcap",),
        "local-pcap",
        7,
    ),
}


def remote_bucket_path(lab: Lab, bucket: RemoteBucket) -> str:
    return lab.path(*bucket.parts)


def older_than_days(args: argparse.Namespace, default: int) -> int:
    value = default if args.older_than_days is None else int(args.older_than_days)
    if value < 0:
        raise CommandError("--older-than-days must be >= 0")
    return value


def remote_age_expr(args: argparse.Namespace, default: int) -> str:
    if args.all:
        return ""
    return f"-mtime +{older_than_days(args, default)}"


def report(lab: Lab, _: argparse.Namespace) -> None:
    for bucket in REMOTE_BUCKETS.values():
        guard_remote_resources(
            lab,
            bucket.label,
            [(bucket.name, remote_bucket_path(lab, bucket))],
            RESOURCE_LIMITS[bucket.limit_key],
            enforce=False,
        )
    guard_remote_resources(
        lab,
        "vm overlay and snapshot storage",
        [("vms", lab.path("vms"))],
        RESOURCE_LIMITS["vms"],
        enforce=False,
    )
    guard_remote_resources(
        lab,
        "cloud-init seed cache",
        [("seed", lab.path("seed"))],
        RESOURCE_LIMITS["seed"],
        enforce=False,
    )
    for bucket in LOCAL_BUCKETS.values():
        local_dir = safe_local_lab_dir(None, *bucket.parts)
        guard_local_resources(
            bucket.label,
            [(bucket.name, local_dir)],
            RESOURCE_LIMITS[bucket.limit_key],
            enforce=False,
        )


def list_remote_candidates(
    lab: Lab,
    bucket: RemoteBucket,
    args: argparse.Namespace,
) -> list[str]:
    base = remote_bucket_path(lab, bucket)
    age = remote_age_expr(args, bucket.default_days)
    command = (
        "set -e\n"
        f"base={q(base)}\n"
        'if [ -d "$base" ]; then\n'
        f"  find \"$base\" -mindepth 1 -maxdepth 1 {bucket.selector} {age} -print | sort\n"
        "fi"
    )
    result = lab.ssh(command, capture=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def delete_remote_candidates(
    lab: Lab,
    bucket: RemoteBucket,
    args: argparse.Namespace,
) -> None:
    base = remote_bucket_path(lab, bucket)
    age = remote_age_expr(args, bucket.default_days)
    delete_script = (
        'base="$1"; shift; '
        'for target do '
        'case "$target" in "$base"/*) rm -rf -- "$target" ;; '
        '*) echo "unsafe cleanup target: $target" >&2; exit 1 ;; '
        "esac; "
        "done"
    )
    command = (
        "set -e\n"
        f"base={q(base)}\n"
        'if [ -d "$base" ]; then\n'
        f"  find \"$base\" -mindepth 1 -maxdepth 1 {bucket.selector} {age} "
        f"-exec sh -c {q(delete_script)} sh \"$base\" {{}} +\n"
        "fi"
    )
    lab.ssh(command, dry_run_ok=True)


def prune_remote(lab: Lab, args: argparse.Namespace) -> None:
    bucket = REMOTE_BUCKETS[args.bucket]
    base = remote_bucket_path(lab, bucket)
    guard_remote_resources(
        lab,
        bucket.label,
        [(bucket.name, base)],
        RESOURCE_LIMITS[bucket.limit_key],
        enforce=False,
    )
    candidates = list_remote_candidates(lab, bucket, args)
    if not candidates:
        print("no remote cleanup candidates")
        return
    print("remote cleanup candidates:")
    for candidate in candidates:
        print(candidate)
    if not args.yes:
        logger.info("preview only; pass --yes to delete")
        return
    delete_remote_candidates(lab, bucket, args)
    guard_remote_resources(
        lab,
        bucket.label,
        [(bucket.name, base)],
        RESOURCE_LIMITS[bucket.limit_key],
        enforce=False,
    )


def local_bucket_dir(bucket: LocalBucket) -> Path:
    return safe_local_lab_dir(None, *bucket.parts)


def list_local_candidates(bucket: LocalBucket, args: argparse.Namespace) -> list[Path]:
    base = local_bucket_dir(bucket)
    guard_local_resources(
        bucket.label,
        [(bucket.name, base)],
        RESOURCE_LIMITS[bucket.limit_key],
        enforce=False,
    )
    if not base.exists():
        return []
    cutoff = None if args.all else time.time() - older_than_days(args, bucket.default_days) * 86400
    candidates: list[Path] = []
    for child in base.iterdir():
        if not any(child.match(pattern) for pattern in bucket.patterns):
            continue
        if cutoff is not None and child.lstat().st_mtime > cutoff:
            continue
        candidates.append(assert_local_lab_path(child))
    return sorted(candidates)


def prune_local(_: Lab, args: argparse.Namespace) -> None:
    bucket = LOCAL_BUCKETS[args.bucket]
    candidates = list_local_candidates(bucket, args)
    if not candidates:
        print("no local cleanup candidates")
        return
    print("local cleanup candidates:")
    for candidate in candidates:
        print(candidate)
    if not args.yes:
        logger.info("preview only; pass --yes to delete")
        return
    for candidate in candidates:
        candidate = assert_local_lab_path(candidate)
        if candidate.is_symlink() or candidate.is_file():
            candidate.unlink()
        elif candidate.is_dir():
            shutil.rmtree(candidate)
    bucket_dir = local_bucket_dir(bucket)
    guard_local_resources(
        bucket.label,
        [(bucket.name, bucket_dir)],
        RESOURCE_LIMITS[bucket.limit_key],
        enforce=False,
    )


def clean_image(lab: Lab, args: argparse.Namespace) -> None:
    image = require_catalog_image(args.image)
    dest = lab.path("images", image.filename)
    checksum = dest + ".sha256"
    guard_remote_resources(
        lab,
        "image cache",
        [("images", lab.path("images"))],
        RESOURCE_LIMITS["images"],
        enforce=False,
    )
    if not args.yes:
        raise CommandError("image cleanup requires --yes")
    check_script = (
        'image="$1"; shift; '
        'for disk do '
        'if qemu-img info -U "$disk" 2>/dev/null | grep -Fq "$image"; then '
        'echo "image is still referenced by overlay: $disk" >&2; exit 1; '
        "fi; "
        "done"
    )
    overlay_check = (
        "set -e\n"
        f"image={q(dest)}\n"
        f"if [ -d {q(lab.path('vms'))} ]; then\n"
        f"  find {q(lab.path('vms'))} -maxdepth 1 -type f -name '*.qcow2' "
        f"-exec sh -c {q(check_script)} sh \"$image\" {{}} +\n"
        "fi\n"
        f"rm -f -- {q(dest)} {q(checksum)}"
    )
    lab.ssh(overlay_check, dry_run_ok=True)


def clean_overlay(lab: Lab, args: argparse.Namespace) -> None:
    guest = validate_name(args.guest, "guest")
    disk = lab.path("vms", f"{guest}.qcow2")
    guard_remote_resources(
        lab,
        "vm overlay and snapshot storage",
        [("vms", lab.path("vms"))],
        RESOURCE_LIMITS["vms"],
        enforce=False,
    )
    if not args.yes:
        raise CommandError("overlay cleanup requires --yes")
    command = (
        "set -e\n"
        f"disk={q(disk)}\n"
        f"if virsh dominfo {q(guest)} >/dev/null 2>&1; then\n"
        f"  echo 'domain still exists; use guest undefine {guest} --yes for defined guests' >&2\n"
        "  exit 1\n"
        "fi\n"
        "virsh list --all --name | while IFS= read -r domain; do\n"
        "  [ -n \"$domain\" ] || continue\n"
        "  if virsh domblklist \"$domain\" --details 2>/dev/null | awk '{print $4}' | grep -Fxq \"$disk\"; then\n"
        "    echo \"overlay is still referenced by domain: $domain\" >&2\n"
        "    exit 1\n"
        "  fi\n"
        "done\n"
        f"rm -f -- {q(disk)}"
    )
    lab.ssh(command, dry_run_ok=True)


def add_prune_options(parser: argparse.ArgumentParser, default_days: int) -> None:
    parser.add_argument("--older-than-days", type=int, default=None)
    parser.add_argument(
        "--all",
        action="store_true",
        help="ignore age and include all matching files in the bucket",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="delete the listed candidates",
    )
    parser.set_defaults(default_days=default_days)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report and safely prune dynet lab cache artifacts."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("report", help="show remote and local lab resource usage")

    remote_parser = subparsers.add_parser(
        "prune-remote",
        help="preview or delete old remote cache artifacts",
    )
    remote_parser.add_argument("bucket", choices=sorted(REMOTE_BUCKETS))
    add_prune_options(remote_parser, 7)

    local_parser = subparsers.add_parser(
        "prune-local",
        help="preview or delete old local dist/lab artifacts",
    )
    local_parser.add_argument("bucket", choices=sorted(LOCAL_BUCKETS))
    add_prune_options(local_parser, 7)

    image_parser = subparsers.add_parser(
        "image",
        help="remove a catalog image if no overlay still references it",
    )
    image_parser.add_argument("image", choices=sorted(IMAGE_CATALOG))
    image_parser.add_argument("--yes", action="store_true")

    overlay_parser = subparsers.add_parser(
        "overlay",
        help="remove an orphan qcow2 overlay for an undefined guest",
    )
    overlay_parser.add_argument("guest")
    overlay_parser.add_argument("--yes", action="store_true")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {
        "report": report,
        "prune-remote": prune_remote,
        "prune-local": prune_local,
        "image": clean_image,
        "overlay": clean_overlay,
    }
    handlers[args.command](lab, args)


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        logger.error("%s", error)
        raise SystemExit(2)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
