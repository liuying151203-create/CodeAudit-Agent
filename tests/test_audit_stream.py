import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.agent.graph import run_audit, stream_audit
from frontend.ui_data import event_rows, finding_origin, runtime_status, tool_result_rows


class AuditStreamTests(unittest.TestCase):
    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_stream_emits_real_node_updates_and_final_report(self, _llm, _which):
        diff_text = Path("data/sample_repos/sample.diff").read_text(encoding="utf-8")
        with TemporaryDirectory() as report_dir, patch.dict(os.environ, {"CODEAUDIT_REPORT_DIR": report_dir}):
            updates = list(stream_audit({"mode": "diff_scan", "diff_text": diff_text}))

        events = [event for event, _ in updates]
        final_state = updates[-1][1]
        node_names = [event.node_name for event in events]
        self.assertEqual(node_names[0], "router")
        self.assertEqual(node_names[-1], "report")
        self.assertIn("tool_selector", node_names)
        self.assertIn("audit_reasoner", node_names)
        self.assertIn("finding_assessor", node_names)
        self.assertEqual(events[-1].progress, 1.0)
        self.assertTrue(all(left.progress <= right.progress for left, right in zip(events, events[1:])))
        self.assertIn("final_report", final_state)
        self.assertEqual(len(final_state["final_report"].findings), 4)

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_synchronous_api_consumes_the_same_stream(self, _llm, _which):
        diff_text = Path("data/sample_repos/sample.diff").read_text(encoding="utf-8")
        with TemporaryDirectory() as report_dir, patch.dict(os.environ, {"CODEAUDIT_REPORT_DIR": report_dir}):
            state = run_audit({"mode": "diff_scan", "diff_text": diff_text})

        self.assertEqual(state["final_report"].metrics.confirmed_findings, 4)

    @patch("app.agent.graph.StateGraph", None)
    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_stream_protocol_survives_without_langgraph(self, _llm, _which):
        diff_text = Path("data/sample_repos/sample.diff").read_text(encoding="utf-8")
        with TemporaryDirectory() as report_dir, patch.dict(os.environ, {"CODEAUDIT_REPORT_DIR": report_dir}):
            updates = list(stream_audit({"mode": "diff_scan", "diff_text": diff_text}))

        self.assertEqual(updates[0][0].node_name, "router")
        self.assertEqual(updates[-1][0].node_name, "report")
        self.assertEqual(updates[-1][0].progress, 1.0)

    def test_ui_presenters_expose_runtime_and_structured_rows(self):
        status = runtime_status()
        self.assertIn("langgraph", status)
        self.assertIn("llm", status)
        self.assertTrue(status["fallback"]["available"])

        rows = event_rows([])
        self.assertEqual(rows, [])
        self.assertEqual(tool_result_rows([]), [])

    def test_finding_origin_prefers_llm_and_external_provenance(self):
        from app.schemas import Finding, FindingProvenance

        finding = Finding(
            finding_id="finding-1",
            rule_id="LLM_SQL",
            file_path="app.py",
            line_start=1,
            line_end=1,
            severity="high",
            category="SQL Injection",
            message="Unsafe query",
            evidence_text="query + input",
            source="llm",
            provenance=[FindingProvenance(source_type="llm", source_name="audit_reasoner")],
        )

        self.assertEqual(finding_origin(finding), "LLM 补充")


if __name__ == "__main__":
    unittest.main()
