from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any


class SarifValidationError(ValueError):
    pass


def validate_sarif_document(payload: dict[str, Any]) -> list[str]:
    """Validate the GitHub Code Scanning subset emitted by this project."""
    errors: list[str] = []
    if payload.get("version") != "2.1.0":
        errors.append("version must be SARIF 2.1.0")
    runs = payload.get("runs")
    if not isinstance(runs, list) or not runs:
        return [*errors, "runs must contain at least one analysis run"]

    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"runs[{run_index}] must be an object")
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        if not str(driver.get("name") or "").strip():
            errors.append(f"runs[{run_index}].tool.driver.name is required")
        rules = driver.get("rules") or []
        rule_ids = [str(rule.get("id") or "") for rule in rules if isinstance(rule, dict)]
        if len(rule_ids) != len(set(rule_ids)):
            errors.append(f"runs[{run_index}] contains duplicate rule ids")

        results = run.get("results") or []
        if not isinstance(results, list):
            errors.append(f"runs[{run_index}].results must be an array")
            continue
        for result_index, result in enumerate(results):
            prefix = f"runs[{run_index}].results[{result_index}]"
            if not isinstance(result, dict):
                errors.append(f"{prefix} must be an object")
                continue
            rule_id = str(result.get("ruleId") or "")
            if not rule_id or rule_id not in rule_ids:
                errors.append(f"{prefix}.ruleId must reference a declared rule")
            if not str((result.get("message") or {}).get("text") or "").strip():
                errors.append(f"{prefix}.message.text is required")
            locations = result.get("locations") or []
            if not locations:
                errors.append(f"{prefix}.locations must contain a source location")
                continue
            physical = (locations[0].get("physicalLocation") or {}) if isinstance(locations[0], dict) else {}
            uri = str((physical.get("artifactLocation") or {}).get("uri") or "")
            path = PurePosixPath(uri)
            if not uri or path.is_absolute() or ".." in path.parts:
                errors.append(f"{prefix} must use a repository-relative artifact uri")
            region = physical.get("region") or {}
            start_line = region.get("startLine")
            end_line = region.get("endLine", start_line)
            if not isinstance(start_line, int) or start_line < 1:
                errors.append(f"{prefix}.region.startLine must be a positive integer")
            if not isinstance(end_line, int) or not isinstance(start_line, int) or end_line < start_line:
                errors.append(f"{prefix}.region.endLine must not precede startLine")
    return errors


def assert_valid_sarif(payload: dict[str, Any]) -> None:
    errors = validate_sarif_document(payload)
    if errors:
        raise SarifValidationError("; ".join(errors))

