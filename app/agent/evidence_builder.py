from __future__ import annotations

import re
from typing import Any

from app.context.context_extractor import extract_evidence
from app.schemas.enums import AuditStageName
from app.schemas.evidence import Evidence
from app.schemas.execution import ToolRunResult

SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(\b(?:api[_-]?key|token|password|passwd|private[_-]?key|secret)\b\s*[:=]\s*)(['\"]?)[^\s,'\"]+\2"
)


def build_stage_evidence(
    results: list[ToolRunResult],
    files: list[dict[str, Any]],
    stage: AuditStageName,
    risk_types: list[str],
    existing: list[Evidence],
    max_context_lines: int,
) -> tuple[list[Evidence], int]:
    evidence_by_id = {item.evidence_id: item for item in existing}
    before = len(evidence_by_id)
    for result in results:
        for finding in result.findings:
            if (finding.risk_type or finding.category) not in set(risk_types):
                continue
            evidence = extract_evidence(finding, files)
            evidence = evidence.model_copy(
                update={
                    "code_snippet": redact_sensitive_text(evidence.code_snippet),
                    "code_context": redact_sensitive_text(evidence.code_context),
                    "surrounding_lines": [redact_sensitive_text(line) for line in evidence.surrounding_lines],
                    "source_tool": result.tool_name,
                    "source_call_id": result.call_id,
                    "stage": stage,
                }
            )
            finding.evidence_ids = [evidence.evidence_id]
            evidence_by_id[evidence.evidence_id] = evidence
        for index, observation in enumerate(result.observations, start=1):
            if not observation.file_path:
                continue
            content_lines = observation.content.splitlines()[:max_context_lines]
            content = redact_sensitive_text("\n".join(content_lines))
            evidence_id = f"evidence:{result.call_id or result.tool_name}:{observation.file_path}:{index}"
            evidence_by_id[evidence_id] = Evidence(
                evidence_id=evidence_id,
                finding_id=f"stage:{stage.value}",
                file_path=observation.file_path,
                start_line=observation.start_line,
                end_line=observation.end_line,
                code_snippet=content,
                code_context=content,
                source_tool=result.tool_name,
                source_call_id=result.call_id,
                stage=stage,
                changed_line=bool(observation.metadata.get("changed_line")),
                is_changed_line=bool(observation.metadata.get("changed_line")),
            )
    return list(evidence_by_id.values()), len(evidence_by_id) - before


def redact_sensitive_text(text: str) -> str:
    return SECRET_VALUE_PATTERN.sub(r"\1<redacted>", text)
