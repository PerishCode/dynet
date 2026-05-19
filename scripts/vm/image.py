#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess

from common import (
    CommandError,
    IMAGE_CATALOG,
    Lab,
    RESOURCE_LIMITS,
    add_lab_options,
    guard_remote_resources,
    logger,
    q,
    require_catalog_image,
    validate_name,
)


def catalog(_: Lab, __: argparse.Namespace) -> None:
    for image in IMAGE_CATALOG.values():
        print(f"{image.name}\t{image.filename}\t{image.default_user}\t{image.note}")


def list_images(lab: Lab, _: argparse.Namespace) -> None:
    command = (
        f"set -e; install -d -m 0755 {q(lab.path('images'))} {q(lab.path('vms'))}; "
        f"printf 'images\\n'; "
        f"find {q(lab.path('images'))} -maxdepth 1 -type f "
        "-printf '%f\\t%s bytes\\n' | sort; "
        f"printf 'overlays\\n'; "
        f"find {q(lab.path('vms'))} -maxdepth 1 -type f -name '*.qcow2' "
        "-printf '%f\\t%s bytes\\n' | sort"
    )
    lab.ssh(command)


def ensure(lab: Lab, args: argparse.Namespace) -> None:
    image = require_catalog_image(args.image)
    dest = lab.path("images", image.filename)
    tmp = f"{dest}.partial"
    guard_remote_resources(
        lab,
        "image cache",
        [("images", lab.path("images"))],
        RESOURCE_LIMITS["images"],
    )
    command = (
        "set -e; "
        f"install -d -m 0755 {q(lab.path('images'))}; "
        f"if [ ! -s {q(dest)} ]; then "
        f"curl -fL --retry 3 --speed-limit 102400 --speed-time 60 "
        f"--continue-at - -o {q(tmp)} {q(image.url)}; "
        f"mv {q(tmp)} {q(dest)}; "
        "fi; "
        f"qemu-img info {q(dest)} >/dev/null; "
        f"sha256sum {q(dest)} > {q(dest + '.sha256')}; "
        f"qemu-img info {q(dest)}"
    )
    lab.ssh(command, dry_run_ok=True)


def info(lab: Lab, args: argparse.Namespace) -> None:
    image = require_catalog_image(args.image)
    path = lab.path("images", image.filename)
    lab.ssh(f"qemu-img info {q(path)}")


def overlay(lab: Lab, args: argparse.Namespace) -> None:
    image = require_catalog_image(args.image)
    name = validate_name(args.name, "overlay")
    base = lab.path("images", image.filename)
    dest = lab.path("vms", f"{name}.qcow2")
    guard_remote_resources(
        lab,
        "vm overlay storage",
        [("vms", lab.path("vms")), ("images", lab.path("images"))],
        RESOURCE_LIMITS["vms"],
    )
    force = "rm -f " + q(dest) + "; " if args.force else ""
    command = (
        "set -e; "
        f"test -s {q(base)} || "
        f"(echo 'base image missing: {base}; run image ensure {image.name}' >&2; exit 1); "
        f"install -d -m 0755 {q(lab.path('vms'))}; "
        f"if [ -e {q(dest)} ] && [ {str(args.force).lower()} != true ]; then "
        f"echo 'overlay already exists: {dest}' >&2; exit 1; "
        "fi; "
        f"{force}"
        f"qemu-img create -f qcow2 -F qcow2 -b {q(base)} {q(dest)}; "
        f"qemu-img info {q(dest)}"
    )
    lab.ssh(command, dry_run_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage dynet lab cloud images and VM overlays."
    )
    add_lab_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("catalog", help="show built-in cloud image catalog")
    subparsers.add_parser("list", help="list remote cached images and overlays")

    ensure_parser = subparsers.add_parser("ensure", help="download/cache a base image")
    ensure_parser.add_argument("image", help="catalog image name")

    info_parser = subparsers.add_parser("info", help="show qemu-img info")
    info_parser.add_argument("image", help="catalog image name")

    overlay_parser = subparsers.add_parser(
        "overlay", help="create a qcow2 overlay from a cached base image"
    )
    overlay_parser.add_argument("image", help="catalog image name")
    overlay_parser.add_argument("name", help="overlay/guest name")
    overlay_parser.add_argument(
        "--force", action="store_true", help="replace an existing overlay file"
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    lab = Lab.from_args(args)
    handlers = {
        "catalog": catalog,
        "list": list_images,
        "ensure": ensure,
        "info": info,
        "overlay": overlay,
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
