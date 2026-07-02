# Workflow

1. Route request to `repo_scan` or `diff_scan`.
2. Load files or changed diff lines.
3. Run builtin static rules.
4. Extract context for every finding.
5. Analyze risk and exploit scenario.
6. Review false positives.
7. Generate fix suggestions.
8. Write Markdown and JSON reports.
