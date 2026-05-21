from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

from common import (
    LOCAL_LAB_ROOT,
    ROOT,
    CommandError,
    Lab,
    ResourceLimit,
    ResourceStat,
    _assert_local_under,
    format_bytes,
    logger,
    q,
)


def remote_resource_lines(lab: Lab, label: str, raw_path: str) -> list[str]:
    path = lab.assert_path(raw_path)
    return [
        f"label={q(label)}",
        f"path={q(path)}",
        'probe="$path"',
        'while [ ! -e "$probe" ] && [ "$probe" != "$root" ]; do probe=$(dirname "$probe"); done',
        'probe_real=$(readlink -f "$probe")',
        'case "$probe_real" in "$root_real"|"$root_real"/*) ;; *) echo "resource path escapes lab root: $path -> $probe_real" >&2; exit 87;; esac',
        'if [ -e "$path" ]; then',
        '  path_real=$(readlink -f "$path")',
        '  case "$path_real" in "$root_real"|"$root_real"/*) ;; *) echo "resource path escapes lab root: $path -> $path_real" >&2; exit 87;; esac',
        '  bytes=$(du -sb "$path" | awk \'{print $1}\')',
        '  if [ -d "$path" ]; then',
        '    files=$(find "$path" -xdev -type f | wc -l)',
        '    dirs=$(find "$path" -xdev -type d | wc -l)',
        '  else',
        "    files=1",
        "    dirs=0",
        "  fi",
        "else",
        "  bytes=0",
        "  files=0",
        "  dirs=0",
        "fi",
        'printf "%s\\t%s\\t%s\\t%s\\t%s\\n" "$label" "$bytes" "$files" "$dirs" "$path"',
    ]


def remote_resource_stats(lab: Lab, entries: Sequence[tuple[str, str]]) -> list[ResourceStat]:
    if not entries:
        return []
    lines = [
        "set -e",
        f"root={q(lab.root)}",
        'root_real=$(readlink -f "$root")',
        'test -n "$root_real"',
    ]
    for label, raw_path in entries:
        lines.extend(remote_resource_lines(lab, label, raw_path))
    result = lab.ssh("\n".join(lines), capture=True)
    stats: list[ResourceStat] = []
    for line in result.stdout.splitlines():
        label, byte_text, file_text, dir_text, path = line.split("\t", 4)
        stats.append(
            ResourceStat(
                label=label,
                path=path,
                bytes=int(byte_text.strip()),
                files=int(file_text.strip()),
                dirs=int(dir_text.strip()),
            )
        )
    return stats


def local_tree_usage(path: Path) -> tuple[int, int, int]:
    total_bytes = 0
    files = 0
    dirs = 0
    for current, dirnames, filenames in os.walk(path, followlinks=False):
        dirs += 1
        current_path = Path(current)
        for name in filenames:
            child = current_path / name
            try:
                total_bytes += child.lstat().st_size
                files += 1
            except FileNotFoundError:
                continue
        symlink_dirs = []
        for name in list(dirnames):
            child = current_path / name
            if child.is_symlink():
                symlink_dirs.append(name)
                try:
                    total_bytes += child.lstat().st_size
                    files += 1
                except FileNotFoundError:
                    continue
        for name in symlink_dirs:
            dirnames.remove(name)
    return total_bytes, files, dirs


def local_path_usage(path: Path) -> tuple[int, int, int]:
    if not path.exists():
        return 0, 0, 0
    if path.is_file() or path.is_symlink():
        return path.lstat().st_size, 1, 0
    return local_tree_usage(path)


def local_resource_stats(
    entries: Sequence[tuple[str, Path]],
    *,
    base: Path | None = None,
) -> list[ResourceStat]:
    base = (base or LOCAL_LAB_ROOT).resolve(strict=False)
    stats: list[ResourceStat] = []
    for label, path in entries:
        path = _assert_local_under(path, base)
        total_bytes, files, dirs = local_path_usage(path)
        stats.append(ResourceStat(label=label, path=str(path), bytes=total_bytes, files=files, dirs=dirs))
    return stats


def _resource_messages(
    title: str,
    stats: Sequence[ResourceStat],
    limit: ResourceLimit,
) -> tuple[list[str], list[str]]:
    total_bytes = sum(item.bytes for item in stats)
    total_files = sum(item.files for item in stats)
    warnings: list[str] = []
    failures: list[str] = []
    if total_bytes >= limit.fail_bytes:
        failures.append(
            f"{title} uses {format_bytes(total_bytes)}; fail threshold is {format_bytes(limit.fail_bytes)}"
        )
    elif total_bytes >= limit.warn_bytes:
        warnings.append(
            f"{title} uses {format_bytes(total_bytes)}; warning threshold is {format_bytes(limit.warn_bytes)}"
        )
    if limit.fail_files is not None and total_files >= limit.fail_files:
        failures.append(f"{title} has {total_files} files; fail threshold is {limit.fail_files}")
    elif limit.warn_files is not None and total_files >= limit.warn_files:
        warnings.append(f"{title} has {total_files} files; warning threshold is {limit.warn_files}")
    return warnings, failures


def report_resources(
    title: str,
    stats: Sequence[ResourceStat],
    limit: ResourceLimit | None = None,
    *,
    enforce: bool = True,
) -> None:
    logger.info("[resource] %s", title)
    for item in stats:
        logger.info("  %s: %s -> %s files, %s dirs, %s", item.label, item.path, item.files, item.dirs, format_bytes(item.bytes))
    total_bytes = sum(item.bytes for item in stats)
    total_files = sum(item.files for item in stats)
    logger.info("  total: %s files, %s", total_files, format_bytes(total_bytes))
    if limit is None:
        return
    logger.info("  thresholds: warn %s, fail %s", format_bytes(limit.warn_bytes), format_bytes(limit.fail_bytes))
    warnings, failures = _resource_messages(title, stats, limit)
    for message in warnings:
        logger.warning("%s", message)
    for message in failures:
        logger.error("%s", message)
    if failures and enforce:
        raise CommandError(f"resource guard failed for {title}")


def guard_remote_resources(
    lab: Lab,
    title: str,
    entries: Sequence[tuple[str, str]],
    limit: ResourceLimit,
    *,
    enforce: bool = True,
) -> list[ResourceStat]:
    stats = remote_resource_stats(lab, entries)
    report_resources(title, stats, limit, enforce=enforce)
    return stats


def guard_local_resources(
    title: str,
    entries: Sequence[tuple[str, Path]],
    limit: ResourceLimit,
    *,
    enforce: bool = True,
    base: Path | None = None,
) -> list[ResourceStat]:
    stats = local_resource_stats(entries, base=base)
    report_resources(title, stats, limit, enforce=enforce)
    return stats


def guard_repo_resources(
    title: str,
    entries: Sequence[tuple[str, Path]],
    limit: ResourceLimit,
    *,
    enforce: bool = True,
) -> list[ResourceStat]:
    stats = local_resource_stats(entries, base=ROOT.resolve(strict=False))
    report_resources(title, stats, limit, enforce=enforce)
    return stats
