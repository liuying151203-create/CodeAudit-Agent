from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

REPORT_FILE_PATTERN = re.compile(r"^(?P<report_id>[0-9a-f]{8})\.(json|md|sarif)$")


@dataclass(frozen=True)
class ReportRetentionPolicy:
    enabled: bool = True
    max_reports: int = 100
    max_age_days: int = 30

    @classmethod
    def from_env(cls) -> "ReportRetentionPolicy":
        return cls(
            enabled=os.getenv("CODEAUDIT_REPORT_RETENTION_ENABLED", "true").lower() in {"1", "true", "yes", "on"},
            max_reports=_positive_env_int("CODEAUDIT_REPORT_MAX_COUNT", 100),
            max_age_days=_positive_env_int("CODEAUDIT_REPORT_MAX_AGE_DAYS", 30),
        )


@dataclass(frozen=True)
class ReportRetentionResult:
    retained_reports: int
    pruned_reports: int
    deleted_files: int


def prune_reports(
    directory: Path,
    policy: ReportRetentionPolicy | None = None,
    protected_report_ids: set[str] | None = None,
    now: float | None = None,
) -> ReportRetentionResult:
    policy = policy or ReportRetentionPolicy.from_env()
    protected = protected_report_ids or set()
    root = directory.resolve()
    if not policy.enabled or not root.exists() or not root.is_dir():
        return ReportRetentionResult(retained_reports=_report_count(root), pruned_reports=0, deleted_files=0)

    grouped: dict[str, list[Path]] = {}
    for path in root.iterdir():
        if not path.is_file():
            continue
        match = REPORT_FILE_PATTERN.fullmatch(path.name)
        if match:
            grouped.setdefault(match.group("report_id"), []).append(path)
    modified = {
        report_id: max(path.stat().st_mtime for path in paths)
        for report_id, paths in grouped.items()
    }
    cutoff = (now if now is not None else time.time()) - policy.max_age_days * 86400
    delete_ids = {
        report_id
        for report_id, timestamp in modified.items()
        if timestamp < cutoff and report_id not in protected
    }
    remaining = sorted(
        ((report_id, timestamp) for report_id, timestamp in modified.items() if report_id not in delete_ids),
        key=lambda item: item[1],
        reverse=True,
    )
    for report_id, _ in remaining[policy.max_reports :]:
        if report_id not in protected:
            delete_ids.add(report_id)

    deleted_files = 0
    for report_id in sorted(delete_ids):
        for path in grouped[report_id]:
            resolved = path.resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            resolved.unlink(missing_ok=True)
            deleted_files += 1
    return ReportRetentionResult(
        retained_reports=len(grouped) - len(delete_ids),
        pruned_reports=len(delete_ids),
        deleted_files=deleted_files,
    )


def _report_count(directory: Path) -> int:
    if not directory.exists() or not directory.is_dir():
        return 0
    return len(
        {
            match.group("report_id")
            for path in directory.iterdir()
            if path.is_file() and (match := REPORT_FILE_PATTERN.fullmatch(path.name))
        }
    )


def _positive_env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default
