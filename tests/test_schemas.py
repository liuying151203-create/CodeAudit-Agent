import unittest

from pydantic import ValidationError

from app.agent.tools import _to_markdown
from app.schemas import (
    AuditBudget,
    AuditDecision,
    AuditDecisionType,
    AuditPlan,
    AuditReport,
    AuditStageName,
    AuditStagePlan,
    FindingDraft,
    Finding,
    ProfileScope,
    ProjectProfile,
    Severity,
    ToolRequest,
    ToolRunResult,
)


class SchemaTests(unittest.TestCase):
    def test_mutable_defaults_are_isolated(self):
        first = ProjectProfile()
        second = ProjectProfile()

        first.languages.append("Python")

        self.assertEqual(first.languages, ["Python"])
        self.assertEqual(second.languages, [])

    def test_project_profile_validates_confidence(self):
        with self.assertRaises(ValidationError):
            ProjectProfile(profile_confidence=1.1)

        profile = ProjectProfile(profile_scope=ProfileScope.DIFF_ONLY, profile_confidence=0.5)
        self.assertEqual(profile.profile_scope, ProfileScope.DIFF_ONLY)

    def test_audit_plan_round_trip(self):
        plan = AuditPlan(
            summary="Check injection risks",
            stages=[
                AuditStagePlan(
                    stage=AuditStageName.INJECTION,
                    priority=Severity.HIGH,
                    risk_types=["SQL Injection"],
                    required_capabilities=["scan_sql_patterns"],
                )
            ],
        )

        restored = AuditPlan.model_validate_json(plan.model_dump_json())

        self.assertEqual(restored.stages[0].stage, AuditStageName.INJECTION)
        self.assertEqual(restored.stages[0].required_capabilities, ["scan_sql_patterns"])

    def test_call_tool_decision_requires_request(self):
        with self.assertRaises(ValidationError):
            AuditDecision(decision=AuditDecisionType.CALL_TOOL, reason="Need context")

        decision = AuditDecision(
            decision=AuditDecisionType.CALL_TOOL,
            reason="Need context",
            tool_request=ToolRequest(
                stage=AuditStageName.INJECTION,
                required_capability="extract_call_chain",
                target_files=["app.py"],
                reason="Trace input to SQL",
            ),
        )
        self.assertEqual(decision.tool_request.required_capability, "extract_call_chain")

    def test_emit_finding_decision_requires_finding(self):
        finding = FindingDraft(
            rule_id="LLM_SQL_INJECTION",
            risk_type="SQL Injection",
            severity=Severity.HIGH,
            confidence=0.9,
            file_path="app.py",
            line_start=10,
            line_end=10,
            message="User input reaches a string-built query.",
            evidence_ids=["evidence-1"],
            stage=AuditStageName.INJECTION,
        )
        decision = AuditDecision(decision=AuditDecisionType.EMIT_FINDING, reason="Evidence is sufficient", finding=finding)

        self.assertEqual(decision.finding.evidence_ids, ["evidence-1"])

    def test_legacy_finding_populates_risk_type(self):
        finding = Finding(
            finding_id="finding-1",
            rule_id="RULE_1",
            file_path="app.py",
            line_start=1,
            line_end=1,
            severity="high",
            category="SQL Injection",
            message="Unsafe query",
            evidence_text="query + input",
        )

        self.assertEqual(finding.risk_type, "SQL Injection")

    def test_tool_result_and_budget_round_trip(self):
        result = ToolRunResult(tool_name="semgrep", status="skipped", skipped_reason="not installed")
        budget = AuditBudget(max_tool_rounds_per_stage=3)

        restored_result = ToolRunResult.model_validate_json(result.model_dump_json())
        restored_budget = AuditBudget.model_validate_json(budget.model_dump_json())

        self.assertEqual(restored_result.status, "skipped")
        self.assertEqual(restored_budget.max_tool_rounds_per_stage, 3)

    def test_audit_report_preserves_structured_state_snapshot(self):
        report = AuditReport(
            report_id="report-1",
            mode="repo_scan",
            summary="No findings",
            state_snapshot={
                "request": {"mode": "repo_scan", "repo_path": "demo"},
                "project_context": {},
                "planning": {},
                "execution": {},
                "findings": {},
                "runtime": {"budget": AuditBudget().model_dump(mode="json")},
            },
        )

        restored = AuditReport.model_validate_json(report.model_dump_json())

        self.assertEqual(restored.state_snapshot["request"]["repo_path"], "demo")
        self.assertEqual(restored.state_snapshot["runtime"]["budget"]["max_tool_rounds_per_stage"], 2)

    def test_markdown_report_renders_audit_plan(self):
        report = AuditReport(
            report_id="report-1",
            mode="repo_scan",
            summary="No findings",
            audit_plan=AuditPlan(
                summary="Check injection risks",
                stages=[
                    AuditStagePlan(
                        stage=AuditStageName.INJECTION,
                        priority=Severity.HIGH,
                        risk_types=["SQL Injection"],
                        target_files=["app.py"],
                        required_capabilities=["scan_sql_patterns"],
                        evidence_goals=["Trace input to query execution"],
                    )
                ],
            ),
        )

        markdown = _to_markdown(report, {})

        self.assertIn("## Audit Plan", markdown)
        self.assertIn("### injection", markdown)
        self.assertIn("scan_sql_patterns", markdown)


if __name__ == "__main__":
    unittest.main()
