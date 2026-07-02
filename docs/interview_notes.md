# Interview Notes

## Difference From Generic GPT Code Review

Generic GPT review often sends broad code context directly to an LLM and asks for suggestions. CodeAudit-Agent is scanner-first: deterministic tools create candidate findings, then the Agent extracts evidence and asks the analyzer to reason only over those findings.

## LangGraph Role

LangGraph provides explicit workflow orchestration. Each node has a clear responsibility, state transition, and trace. This makes the process explainable and easier to extend.

## Tool Calling

The Agent invokes tools such as `RepoLoaderTool`, `GitDiffTool`, `StaticScanTool`, `ContextExtractorTool`, `RiskAnalyzeTool`, `FalsePositiveReviewTool`, `FixSuggestTool`, and `ReportWriterTool`. Tool boundaries make the workflow modular and testable.

## Component Responsibilities

- Scanner: detects concrete risky patterns.
- Analyzer: explains risk reason, exploit scenario, confidence, and severity.
- Reviewer: checks likely false positives.
- FixAdvisor: proposes safe coding patterns and patch hints.
- Reporter: writes Markdown/JSON reports and exposes trace data.

## Reducing LLM Hallucination

The LLM is never asked to scan the whole repository directly. It receives scanner findings and evidence, and its output should be validated through Pydantic schemas. The MVP also works without an LLM API by using deterministic templates.

## False Positive Filtering

The review node checks evidence and rule metadata before final recommendations are generated. In later versions, this can combine scanner confidence, test-file heuristics, dataflow, and LLM review.

## Git Diff Detection

`GitDiffTool` accepts pasted unified diff text or loads Git diff from a repository. `diff_parser` reconstructs changed Python file content and records added lines, so the scanner focuses on changed lines for PR-style precheck.

## Why Audited Code Is Not Executed

Running unknown project code can trigger malicious commands, network calls, data deletion, or environment leakage. The MVP only reads text and generates patch hints instead of modifying user code.

## Future Integrations

Semgrep and Bandit can be normalized into the `Finding` schema. SARIF export can support GitHub code scanning. A GitHub Action can run `diff_scan` on pull requests and publish report comments.
