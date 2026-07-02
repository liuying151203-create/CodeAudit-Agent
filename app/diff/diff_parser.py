from __future__ import annotations

from typing import Any


def parse_unified_diff(diff_text: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    new_line_no = 0
    content_lines: list[str] = []
    changed_lines: list[int] = []
    in_hunk = False

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current:
                current["content"] = "\n".join(content_lines)
                current["changed_lines"] = changed_lines
                files.append(current)
            current = {"path": line.split(" b/")[-1] if " b/" in line else line, "source": "diff"}
            content_lines = []
            changed_lines = []
            in_hunk = False
        elif current and line.startswith("+++ b/"):
            current["path"] = line[6:]
        elif current and line.startswith("@@"):
            new_line_no = _parse_hunk_new_start(line)
            in_hunk = True
        elif current and in_hunk and line.startswith("+") and not line.startswith("+++"):
            content_lines.append(line[1:])
            changed_lines.append(len(content_lines))
            new_line_no += 1
        elif current and in_hunk and line.startswith("-") and not line.startswith("---"):
            continue
        elif current and in_hunk and not line.startswith("\\"):
            if line.startswith(" "):
                content_lines.append(line[1:])
            else:
                content_lines.append(line)
            new_line_no += 1

    if current:
        current["content"] = "\n".join(content_lines)
        current["changed_lines"] = changed_lines
        files.append(current)
    return [item for item in files if item.get("path", "").endswith(".py")]


def _parse_hunk_new_start(header: str) -> int:
    try:
        new_part = header.split(" +", 1)[1].split(" ", 1)[0]
        return int(new_part.split(",", 1)[0])
    except (IndexError, ValueError):
        return 0
