from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def summary_json_path(path: Path) -> Path:
    return path / "summary.json" if path.is_dir() else path


def load_json(path: Path) -> Any:
    with path.open() as fh:
        return json.load(fh)


def load_summary(path: Path) -> dict[str, Any]:
    summary_path = summary_json_path(path)
    if not summary_path.exists():
        return {}
    data = load_json(summary_path)
    return data if isinstance(data, dict) else {}


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
