from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.schemas.project import ProjectProfile, VulnKnowledge

DEFAULT_TOP_K = 6


def retrieve_vulnerability_knowledge(
    profile: ProjectProfile,
    user_task: str = "",
    kb_dir: str | Path = "knowledge_base",
    top_k: int = DEFAULT_TOP_K,
) -> list[VulnKnowledge]:
    root = Path(kb_dir)
    if not root.exists():
        return []
    candidates: list[VulnKnowledge] = []
    for path in sorted(root.glob("*.md")):
        parsed = _parse_document(path)
        score, reasons = _score_document(parsed, profile, user_task)
        if score < 0.2:
            continue
        candidates.append(
            VulnKnowledge(
                knowledge_id=str(parsed["metadata"].get("id") or path.stem),
                title=str(parsed["title"]),
                file_path=path.as_posix(),
                risk_type=str(parsed["metadata"].get("risk_type") or "") or None,
                languages=_as_list(parsed["metadata"].get("languages")),
                frameworks=_as_list(parsed["metadata"].get("frameworks")),
                dangerous_patterns=parsed["sections"].get("危险代码模式", []),
                recommended_capabilities=_as_list(parsed["metadata"].get("capabilities")),
                audit_focus=parsed["sections"].get("审计关注点", []),
                fix_guidance=parsed["sections"].get("修复建议", []),
                relevance_score=score,
                match_reasons=reasons,
                matched_risk_types=[str(parsed["metadata"].get("risk_type"))] if parsed["metadata"].get("risk_type") else [],
                content=str(parsed["body"]),
            )
        )
    return sorted(candidates, key=lambda item: (-item.relevance_score, item.knowledge_id))[:top_k]


def rerank_knowledge(knowledge: list[VulnKnowledge], ordered_ids: list[str]) -> list[VulnKnowledge]:
    order = {knowledge_id: index for index, knowledge_id in enumerate(ordered_ids)}
    return sorted(knowledge, key=lambda item: (order.get(item.knowledge_id, len(order)), -item.relevance_score, item.knowledge_id))


def _parse_document(path: Path) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8", errors="ignore")
    metadata, body = _parse_front_matter(content)
    return {
        "metadata": metadata,
        "title": _first_heading(body) or path.stem.replace("_", " ").title(),
        "sections": _parse_sections(body),
        "body": body.strip(),
    }


def _parse_front_matter(content: str) -> tuple[dict[str, Any], str]:
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, content
    metadata: dict[str, Any] = {}
    end_index = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end_index = index
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = _parse_value(value.strip())
    if end_index is None:
        return {}, content
    return metadata, "\n".join(lines[end_index + 1 :])


def _parse_value(value: str) -> Any:
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
    return value.strip("\"'")


def _parse_sections(content: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in content.splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections.setdefault(current, [])
        elif current and line.strip().startswith("- "):
            sections[current].append(line.strip()[2:].strip())
        elif current and line.strip() and not line.startswith("#"):
            sections[current].append(line.strip())
    return sections


def _score_document(parsed: dict[str, Any], profile: ProjectProfile, user_task: str) -> tuple[float, list[str]]:
    metadata = parsed["metadata"]
    risk_type = str(metadata.get("risk_type") or "")
    languages = _as_list(metadata.get("languages"))
    frameworks = _as_list(metadata.get("frameworks"))
    keywords = _as_list(metadata.get("keywords"))
    profile_risks = {_normalize(item) for item in profile.risk_surfaces}
    profile_languages = {_normalize(item) for item in profile.languages}
    profile_frameworks = {_normalize(item) for item in profile.frameworks}
    signals = set(profile.security_signals)
    task = _normalize(user_task)
    score = 0.0
    directly_relevant = False
    reasons: list[str] = []

    if _normalize(risk_type) in profile_risks:
        score += 0.5
        directly_relevant = True
        reasons.append(f"risk surface matched: {risk_type}")
    signal_risk = _SIGNAL_RISKS.get(_normalize(risk_type), set())
    if signals & signal_risk:
        score += 0.2
        directly_relevant = True
        reasons.append(f"security signal matched: {', '.join(sorted(signals & signal_risk))}")
    if profile_languages & {_normalize(item) for item in languages}:
        score += 0.1
        reasons.append("language matched")
    if profile_frameworks & {_normalize(item) for item in frameworks}:
        score += 0.1
        reasons.append("framework matched")
    matched_keywords = [keyword for keyword in keywords if _normalize(keyword) and _normalize(keyword) in task]
    if matched_keywords:
        score += 0.2
        directly_relevant = True
        reasons.append(f"task keyword matched: {', '.join(matched_keywords)}")
    if _critical_file_match(risk_type, profile):
        score += 0.15
        directly_relevant = True
        reasons.append("security-related file category matched")
    if risk_type == "Secrets":
        score += 0.15
        directly_relevant = True
        reasons.append("baseline secret audit")
    return (min(round(score, 3), 1.0), reasons) if directly_relevant else (0.0, [])


def _critical_file_match(risk_type: str, profile: ProjectProfile) -> bool:
    if risk_type == "SQL Injection":
        return bool(profile.db_files)
    if risk_type == "Broken Access Control":
        return bool(profile.route_files or profile.auth_files)
    if risk_type == "Path Traversal":
        return bool(profile.upload_files)
    return False


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def _first_heading(content: str) -> str | None:
    for line in content.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return None


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


_SIGNAL_RISKS = {
    "sql injection": {"dynamic_sql_construction"},
    "command execution": {"command_execution_api"},
    "secrets": {"secret_like_identifier"},
    "path traversal": {"filesystem_input"},
    "unsafe deserialization": {"unsafe_deserialization_api"},
    "broken access control": set(),
}
