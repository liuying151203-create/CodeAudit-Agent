from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from app.agent.graph import run_audit
from app.integrations.github import render_pr_comment
from app.reporting.sarif import validate_sarif_document
from app.schemas.report import AuditReport


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codeaudit", description="CodeAudit-Agent command line integration")
    commands = parser.add_subparsers(dest="command", required=True)

    repo = commands.add_parser("repo", help="Audit a local repository")
    repo.add_argument("--repo-path", default=".")
    repo.add_argument("--user-task")
    repo.add_argument("--metadata-file")

    diff = commands.add_parser("diff", help="Audit a unified diff or a local Git diff")
    diff.add_argument("--repo-path")
    diff.add_argument("--diff-file")
    diff.add_argument("--diff-mode", choices=["cached", "head"], default="cached")
    diff.add_argument("--user-task")
    diff.add_argument("--metadata-file")

    validate = commands.add_parser("validate-sarif", help="Validate CodeAudit SARIF output")
    validate.add_argument("sarif_file")

    comment = commands.add_parser("pr-comment", help="Render a sanitized PR comment from an audit report")
    comment.add_argument("report_file")
    comment.add_argument("--output", required=True)
    comment.add_argument("--max-findings", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate-sarif":
        payload = json.loads(Path(args.sarif_file).read_text(encoding="utf-8"))
        errors = validate_sarif_document(payload)
        if errors:
            for error in errors:
                print(f"SARIF error: {error}", file=sys.stderr)
            return 2
        print(f"Valid SARIF 2.1.0: {args.sarif_file}")
        return 0
    if args.command == "pr-comment":
        report = AuditReport.model_validate_json(Path(args.report_file).read_text(encoding="utf-8"))
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_pr_comment(report, max(1, args.max_findings)), encoding="utf-8")
        print(str(output))
        return 0

    state: dict[str, Any] = {
        "mode": "repo_scan" if args.command == "repo" else "diff_scan",
        "repo_path": args.repo_path,
        "user_task": args.user_task,
        "traces": [],
        "errors": [],
    }
    if args.command == "diff":
        state["diff_mode"] = args.diff_mode
        if args.diff_file:
            state["diff_text"] = Path(args.diff_file).read_text(encoding="utf-8")
    report: AuditReport = run_audit(state)["final_report"]
    metadata = {
        "report_id": report.report_id,
        "summary": report.summary,
        "json_path": report.json_path,
        "markdown_path": report.markdown_path,
        "sarif_path": report.sarif_path,
        "confirmed": report.metrics.confirmed_findings,
        "needs_review": len(report.needs_review_findings),
    }
    if args.metadata_file:
        path = Path(args.metadata_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as output:
            for key, value in metadata.items():
                output.write(f"{key}={str(value).replace(chr(13), ' ').replace(chr(10), ' ')}\n")
    print(json.dumps(metadata, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
