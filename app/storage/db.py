from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def report_dir() -> Path:
    path = Path(os.getenv("CODEAUDIT_REPORT_DIR", "data/reports"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def list_reports() -> list[dict[str, Any]]:
    reports = []
    for path in sorted(report_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        data = json.loads(path.read_text(encoding="utf-8"))
        reports.append({"report_id": data["report_id"], "mode": data["mode"], "summary": data["summary"], "json_path": str(path)})
    return reports


def get_report(report_id: str) -> dict[str, Any] | None:
    path = report_dir() / f"{report_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
