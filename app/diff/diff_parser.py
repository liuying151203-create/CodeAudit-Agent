from __future__ import annotations

from typing import Any


def parse_unified_diff(diff_text: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    new_line_no = 0
    content_lines: list[str] = []
    changed_lines: list[int] = []
    changed_original_lines: list[int] = []
    line_map: dict[str, int] = {}
    in_hunk = False

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current:
                _finish_file(current, content_lines, changed_lines, changed_original_lines, line_map, files)
            current = {"path": line.split(" b/")[-1] if " b/" in line else line, "source": "diff"}
            content_lines = []
            changed_lines = []
            changed_original_lines = []
            line_map = {}
            in_hunk = False
        elif current and line.startswith("+++ b/"):
            current["path"] = line[6:]
        elif current and line.startswith("@@"):
            new_line_no = _parse_hunk_new_start(line)
            in_hunk = True
        elif current and in_hunk and line.startswith("+") and not line.startswith("+++"):
            content_lines.append(line[1:])
            changed_lines.append(len(content_lines))
            changed_original_lines.append(new_line_no)
            line_map[str(len(content_lines))] = new_line_no
            new_line_no += 1
        elif current and in_hunk and line.startswith("-") and not line.startswith("---"):
            continue
        elif current and in_hunk and not line.startswith("\\"):
            if line.startswith(" "):
                content_lines.append(line[1:])
            else:
                content_lines.append(line)
            line_map[str(len(content_lines))] = new_line_no
            new_line_no += 1

    if current:
        _finish_file(current, content_lines, changed_lines, changed_original_lines, line_map, files)
    return [item for item in files if item.get("path", "").lower().endswith((".java", ".py", ".xml"))]


def _finish_file(
    current: dict[str, Any],
    content_lines: list[str],
    changed_lines: list[int],
    changed_original_lines: list[int],
    line_map: dict[str, int],
    files: list[dict[str, Any]],
) -> None:
    current["content"] = "\n".join(content_lines)
    current["changed_lines"] = list(changed_lines)
    current["changed_original_lines"] = list(changed_original_lines)
    current["line_map"] = dict(line_map)
    files.append(current)


def _parse_hunk_new_start(header: str) -> int:
    try:
        new_part = header.split(" +", 1)[1].split(" ", 1)[0]
        return int(new_part.split(",", 1)[0])
    except (IndexError, ValueError):
        return 0
