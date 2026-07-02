from __future__ import annotations

import subprocess
from pathlib import Path


def load_git_diff(repo_path: str, diff_mode: str = "cached") -> str:
    repo = Path(repo_path).resolve()
    args = ["git", "-C", str(repo), "diff", "--cached"] if diff_mode == "cached" else ["git", "-C", str(repo), "diff", "HEAD~1", "HEAD"]
    completed = subprocess.run(args, capture_output=True, text=True, check=False, timeout=15)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git diff failed")
    return completed.stdout
