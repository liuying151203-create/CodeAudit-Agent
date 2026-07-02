from pathlib import Path

from app.diff.diff_parser import parse_unified_diff


def test_parse_sample_diff():
    files = parse_unified_diff(Path("data/sample_repos/sample.diff").read_text(encoding="utf-8"))
    assert files
    assert files[0]["path"] == "app.py"
    assert files[0]["changed_lines"]
