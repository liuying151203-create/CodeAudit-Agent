import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.agent.graph import run_audit
from app.agent.prompt_context import PromptContextSanitizer
from app.agent.tools import FindingAssessorTool, FindingMergerTool
from app.context.context_extractor import extract_evidence
from app.diff.diff_parser import parse_unified_diff
from app.schemas import AuditStageName, Evidence, Finding, FindingStatus, ToolRunResult


class FindingQualityTests(unittest.TestCase):
    def _finding(self, **updates):
        values = {
            "finding_id": "finding-1",
            "rule_id": "PY_SQL_STRING_BUILD",
            "file_path": "app.py",
            "line_start": 5,
            "line_end": 5,
            "severity": "high",
            "category": "SQL Injection",
            "message": "String-built SQL query.",
            "evidence_text": "query = 'SELECT ' + name",
            "source": "custom_rule_scanner",
            "evidence_ids": ["evidence-1"],
            "stage": AuditStageName.INJECTION,
            "confidence": 0.85,
        }
        values.update(updates)
        return Finding(**values)

    def test_diff_parser_retains_original_new_file_lines(self):
        diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -38,2 +40,3 @@
 context()
""" + '+pass' + 'word = "SensitiveFixtureValue"\n+run(password)\n'

        file_item = parse_unified_diff(diff)[0]

        self.assertEqual(file_item["changed_lines"], [2, 3])
        self.assertEqual(file_item["changed_original_lines"], [41, 42])
        self.assertEqual(file_item["line_map"], {"1": 40, "2": 41, "3": 42})

    def test_evidence_extracts_python_and_java_scope(self):
        python_file = {
            "path": "app.py",
            "content": "import sqlite3\n\nclass UserRepo:\n    def load_user(self, name):\n        return self.db.execute('SELECT ' + name)\n",
        }
        python_evidence = extract_evidence(self._finding(), [python_file])
        java_finding = self._finding(
            finding_id="java-1",
            rule_id="JAVA_SQL",
            file_path="UserRepo.java",
            line_start=6,
            line_end=6,
        )
        java_file = {
            "path": "UserRepo.java",
            "content": (
                "package demo;\nimport org.springframework.jdbc.core.JdbcTemplate;\n"
                "public class UserRepo {\n  public User find(String name) {\n"
                "    String sql = \"SELECT \" + name;\n    return jdbc.query(sql);\n  }\n}\n"
            ),
        }
        java_evidence = extract_evidence(java_finding, [java_file])

        self.assertEqual(python_evidence.class_name, "UserRepo")
        self.assertEqual(python_evidence.function_name, "load_user")
        self.assertIn("import sqlite3", python_evidence.imports)
        self.assertIn("load_user -> self.db.execute", python_evidence.dataflow_steps)
        self.assertEqual(java_evidence.class_name, "UserRepo")
        self.assertEqual(java_evidence.function_name, "find")
        self.assertTrue(any("jdbc.query" in item for item in java_evidence.dataflow_steps))

    def test_prompt_context_sanitizer_masks_common_secret_forms(self):
        sanitizer = PromptContextSanitizer()
        token = "sk-" + "abcdefghijklmnop"
        raw = 'pass' + 'word = "SensitiveFixtureValue"\nAuthorization: Bearer abc.def.ghi\nkey = "' + token + '"'

        sanitized = sanitizer.sanitize_code(raw)

        self.assertNotIn("SensitiveFixtureValue", sanitized)
        self.assertNotIn("abc.def.ghi", sanitized)
        self.assertNotIn("sk-abcdefghijklmnop", sanitized)
        self.assertIn("<redacted>", sanitized)

    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_assessor_keeps_evidenceless_hypothesis_out_of_confirmed_findings(self, _enabled):
        finding = self._finding(evidence_ids=[])

        batch = FindingAssessorTool().run([finding], [])

        self.assertEqual(batch.findings[0].status, FindingStatus.NEEDS_REVIEW)
        self.assertFalse(batch.review_results[0].evidence_ids)

    def test_merger_preserves_tool_provenance_and_lifecycle(self):
        finding = self._finding()
        second = finding.model_copy(
            update={
                "finding_id": "finding-2",
                "rule_id": "SEMGREP_SQL",
                "source": "semgrep",
                "sources": ["semgrep"],
                "source_rule_ids": ["SEMGREP_SQL"],
            }
        )

        merged = FindingMergerTool().run(
            [
                ToolRunResult(call_id="call-1", tool_name="custom_rule_scanner", status="success", findings=[finding]),
                ToolRunResult(call_id="call-2", tool_name="semgrep", status="success", findings=[second]),
            ]
        )[0]

        self.assertEqual(merged.status, FindingStatus.MERGED)
        self.assertIn(FindingStatus.CANDIDATE, merged.status_history)
        self.assertIn(FindingStatus.MERGED, merged.status_history)
        self.assertEqual({item.tool_call_id for item in merged.provenance}, {"call-1", "call-2"})
        self.assertEqual({item.source_type for item in merged.provenance}, {"builtin_tool", "external_tool"})

    @patch("app.agent.tools._call_llm_json_with_usage")
    @patch("app.agent.tools._llm_enabled", return_value=True)
    def test_assessor_uses_one_llm_call_and_applies_status(self, _enabled, llm_call):
        llm_call.return_value = (
            {
                "assessments": [
                    {
                        "finding_id": "finding-1",
                        "risk_type": "SQL Injection",
                        "risk_reason": "Input reaches string-built SQL.",
                        "exploit_scenario": "An attacker changes query structure.",
                        "confidence": 0.92,
                        "severity": "high",
                        "status": "confirmed",
                        "review_reason": "No parameter binding is present.",
                    }
                ]
            },
            None,
            321,
        )
        evidence = Evidence(
            evidence_id="evidence-1",
            finding_id="finding-1",
            file_path="app.py",
            start_line=1,
            end_line=5,
            code_context='pass' + 'word = "SensitiveFixtureValue"\nquery = input',
            stage=AuditStageName.INJECTION,
        )

        batch = FindingAssessorTool().run([self._finding()], [evidence])

        self.assertEqual(llm_call.call_count, 1)
        self.assertEqual(batch.findings[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(batch.review_results[0].status, FindingStatus.CONFIRMED)
        self.assertEqual(batch.token_usage, 321)
        self.assertNotIn("SensitiveFixtureValue", str(llm_call.call_args.args[1]))

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_reports_are_sanitized_and_sarif_is_valid(self, _llm, _which):
        diff_text = Path("data/sample_repos/sample.diff").read_text(encoding="utf-8")
        with TemporaryDirectory() as report_dir, patch.dict(os.environ, {"CODEAUDIT_REPORT_DIR": report_dir}):
            report = run_audit({"mode": "diff_scan", "diff_text": diff_text})["final_report"]
            markdown = Path(report.markdown_path).read_text(encoding="utf-8")
            json_text = Path(report.json_path).read_text(encoding="utf-8")
            sarif_text = Path(report.sarif_path).read_text(encoding="utf-8")

        for content in (markdown, json_text, sarif_text):
            self.assertNotIn("ProdPassword123!", content)
        sarif = json.loads(sarif_text)
        report_payload = json.loads(json_text)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(report_payload["report_id"], report.report_id)
        self.assertEqual(len(report.findings), 4)
        self.assertTrue(all(item.evidence_ids for item in report.findings))
        self.assertTrue(all(source.tool_call_id for item in report.findings for source in item.provenance))
        self.assertTrue(all(FindingStatus.REPORTED in item.status_history for item in report.findings))


if __name__ == "__main__":
    unittest.main()
