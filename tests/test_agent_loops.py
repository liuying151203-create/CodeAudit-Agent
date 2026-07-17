import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from unittest.mock import patch

from app.agent.graph import run_audit
from app.agent.reasoner import fallback_reasoner_decision, parse_reasoner_decision
from app.agent.tools import AuditReasonerTool
from app.schemas import (
    AuditBudget,
    AuditDecisionType,
    AuditLoopRuntime,
    AuditStageName,
    AuditStagePlan,
    Evidence,
    ProjectProfile,
)


class AgentLoopTests(unittest.TestCase):
    def setUp(self):
        self.diff_text = Path("data/sample_repos/sample.diff").read_text(encoding="utf-8")

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_diff_scan_runs_stage_and_reasoner_loops(self, _llm, _which):
        with TemporaryDirectory() as report_dir, patch.dict(os.environ, {"CODEAUDIT_REPORT_DIR": report_dir}):
            state = run_audit({"mode": "diff_scan", "diff_text": self.diff_text, "traces": [], "errors": []})
            markdown = Path(state["final_report"].markdown_path).read_text(encoding="utf-8")

        report = state["final_report"]
        self.assertEqual([item.stage_name for item in report.audit_stage_results], ["secret", "command", "file"])
        self.assertTrue(all(item.metrics["tool_rounds"] <= state["budget"].max_tool_rounds_per_stage for item in report.audit_stage_results))
        self.assertEqual(len(report.findings), 4)
        self.assertEqual(report.metrics.tool_call_count, len(state["validated_tool_calls"]))
        decisions = [trace.decision for trace in report.traces if trace.decision]
        self.assertIn("CALL_TOOL", decisions)
        self.assertGreaterEqual(decisions.count("EMIT_FINDING"), 4)
        self.assertEqual(decisions.count("completed"), 3)
        self.assertIn("decision=CALL_TOOL", markdown)
        self.assertIn("rounds=", markdown)

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_zero_tool_budget_finishes_without_looping(self, _llm, _which):
        with TemporaryDirectory() as report_dir, patch.dict(os.environ, {"CODEAUDIT_REPORT_DIR": report_dir}):
            state = run_audit(
                {
                    "mode": "diff_scan",
                    "diff_text": self.diff_text,
                    "budget": AuditBudget(max_tool_rounds_per_stage=0),
                    "traces": [],
                    "errors": [],
                }
            )

        self.assertFalse(state["validated_tool_calls"])
        self.assertTrue(state["audit_stage_results"])
        self.assertTrue(all(str(getattr(item.status, "value", item.status)) == "budget_exhausted" for item in state["audit_stage_results"]))

    def test_reasoner_rejects_unknown_evidence_and_blocks_calls_after_budget(self):
        stage = AuditStagePlan(stage=AuditStageName.INJECTION, risk_types=["SQL Injection"], target_files=["app.py"])
        evidence = Evidence(
            evidence_id="evidence-1",
            finding_id="stage:injection",
            file_path="app.py",
            start_line=1,
            end_line=5,
            code_context="query = input",
            stage=AuditStageName.INJECTION,
        )
        invalid = parse_reasoner_decision(
            {
                "decision": "EMIT_FINDING",
                "finding": {
                    "rule_id": "LLM_SQL",
                    "risk_type": "SQL Injection",
                    "severity": "high",
                    "confidence": 0.9,
                    "file_path": "app.py",
                    "line_start": 2,
                    "line_end": 2,
                    "message": "unsafe query",
                    "evidence_ids": ["invented-evidence"],
                },
            },
            stage,
            [evidence],
            ["app.py"],
            AuditBudget(),
            AuditLoopRuntime(),
        )
        blocked = parse_reasoner_decision(
            {"decision": "CALL_TOOL", "tool_request": {"required_capability": "extract_call_chain", "target_files": ["app.py"]}},
            stage,
            [evidence],
            ["app.py"],
            AuditBudget(max_tool_rounds_per_stage=1),
            AuditLoopRuntime(current_round=1),
        )

        self.assertIsNone(invalid)
        self.assertEqual(blocked.decision, AuditDecisionType.FINISH_STAGE)
        self.assertEqual(blocked.decision_source, "budget")

    def test_no_progress_terminates_stage(self):
        decision = fallback_reasoner_decision(
            AuditStagePlan(stage=AuditStageName.AUTH, risk_types=["Broken Access Control"], target_files=["routes.py"]),
            [],
            [],
            [],
            ["routes.py"],
            AuditBudget(),
            AuditLoopRuntime(no_progress_rounds=2),
            "LLM unavailable",
        )

        self.assertEqual(decision.decision, AuditDecisionType.FINISH_STAGE)
        self.assertEqual(decision.decision_source, "no_new_evidence")

    @patch("app.agent.tools._call_llm_json_with_usage")
    @patch("app.agent.tools._llm_enabled", return_value=True)
    def test_reasoner_accepts_valid_llm_tool_decision(self, _llm_enabled, llm_call):
        llm_call.return_value = (
            {
                "decision": "CALL_TOOL",
                "reason": "Need route context",
                "tool_request": {
                    "required_capability": "extract_route_auth_context",
                    "target_files": ["routes.py"],
                    "risk_types": ["Broken Access Control"],
                    "reason": "Check authorization",
                },
            },
            None,
            123,
        )
        stage = AuditStagePlan(stage=AuditStageName.AUTH, risk_types=["Broken Access Control"], target_files=["routes.py"])

        decision = AuditReasonerTool().run(
            stage,
            [],
            [],
            [],
            [{"path": "routes.py", "content": "def route(): pass"}],
            AuditBudget(),
            AuditLoopRuntime(audit_started_at=monotonic(), stage_started_at=monotonic()),
            [],
        )

        self.assertEqual(decision.decision, AuditDecisionType.CALL_TOOL)
        self.assertEqual(decision.decision_source, "llm")
        self.assertEqual(decision.token_usage, 123)
        self.assertEqual(decision.tool_request.required_capability, "extract_route_auth_context")


if __name__ == "__main__":
    unittest.main()
