import json
import os
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.integrations.github import COMMENT_MARKER, render_pr_comment
from app.reporting.sarif import validate_sarif_document
from app.schemas import AuditMetrics, AuditReport, Finding
from app.schemas import AuditBudget, AuditPlan, AuditStageName, AuditStagePlan, ProjectProfile, Severity
from app.schemas.execution import ValidatedToolCall
from app.security_tools.mcp import discover_mcp_security_tools, execute_mcp_tool
from app.security_tools.gateway import execute_tool_plan, select_tool_plan
from app.security_tools.registry import load_security_tools
from app.storage.retention import ReportRetentionPolicy, prune_reports


class EngineeringIntegrationTests(unittest.TestCase):
    def test_mcp_discovery_and_call_use_real_stdio_protocol(self):
        fixture = Path("tests/fixtures/fake_mcp_server.py").resolve()
        with TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "servers": [
                            {
                                "name": "fixture",
                                "command": sys.executable,
                                "args": [str(fixture)],
                                "allowed_tools": ["scan_source", "rewrite_source"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            tools, errors = discover_mcp_security_tools(config)

            self.assertFalse(errors)
            self.assertEqual([tool.mcp_tool_name for tool in tools], ["scan_source"])
            tool = tools[0]
            call = ValidatedToolCall(call_id="call-mcp", tool_name=tool.name, target_files=["app.py"])
            result = execute_mcp_tool(
                tool,
                call,
                [{"path": "app.py", "content": "os.system(command)\n", "source": "repo"}],
                Path(temp_dir),
                "repo_scan",
                config,
            )

        self.assertEqual(result.status, "success")
        self.assertEqual(result.findings[0].category, "Command Execution")
        self.assertEqual(result.findings[0].source, "mcp.fixture.scan_source")
        self.assertNotIn("FixtureSecret123", result.model_dump_json())
        self.assertEqual(result.metadata["arguments"], ["files", "scan_mode"])

    def test_mcp_tool_stays_inside_selector_executor_and_fallback_contract(self):
        fixture = Path("tests/fixtures/fake_mcp_server.py").resolve()
        with TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "servers": [
                            {
                                "name": "fixture-gateway",
                                "command": sys.executable,
                                "args": [str(fixture)],
                                "allowed_tools": ["scan_source"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"CODEAUDIT_MCP_CONFIG": str(config)}):
                registry = [
                    tool
                    for tool in load_security_tools(mcp_path=config)
                    if tool.name in {"custom_rule_scanner", "secret_scanner"} or tool.adapter == "mcp"
                ]
                profile = ProjectProfile(languages=["Python"], risk_surfaces=["Command Execution"])
                audit_plan = AuditPlan(
                    stages=[
                        AuditStagePlan(
                            stage=AuditStageName.COMMAND,
                            priority=Severity.HIGH,
                            risk_types=["Command Execution"],
                            target_files=["app.py"],
                            required_capabilities=["scan_command_execution"],
                        )
                    ]
                )
                files = [{"path": "app.py", "content": "os.system(command)\n", "source": "repo"}]
                plan = select_tool_plan(
                    profile,
                    [],
                    "repo_scan",
                    files,
                    audit_plan,
                    temp_dir,
                    AuditBudget(max_files_per_call=1),
                    registry,
                    True,
                )
                results = execute_tool_plan(plan, files, temp_dir, "repo_scan", registry)

        mcp_calls = [call for call in plan.tool_calls if call.tool_name.startswith("mcp.")]
        self.assertEqual(len(mcp_calls), 1)
        self.assertEqual(mcp_calls[0].target_files, ["app.py"])
        self.assertEqual(mcp_calls[0].fallback_tool, "custom_rule_scanner")
        self.assertTrue(any(result.tool_name.startswith("mcp.") and result.findings for result in results))

    def test_sarif_validator_rejects_unsafe_location(self):
        payload = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeAudit-Agent", "rules": [{"id": "RULE"}]}},
                    "results": [
                        {
                            "ruleId": "RULE",
                            "message": {"text": "risk"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "../outside.py"},
                                        "region": {"startLine": 1, "endLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        self.assertTrue(any("repository-relative" in error for error in validate_sarif_document(payload)))

    def test_invalid_mcp_config_degrades_to_discovery_error(self):
        with TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "invalid.json"
            config.write_text("{invalid", encoding="utf-8")

            tools, errors = discover_mcp_security_tools(config)

        self.assertFalse(tools)
        self.assertTrue(errors)

    def test_pr_comment_contains_metadata_but_no_evidence(self):
        finding = Finding(
            finding_id="finding-1",
            rule_id="SECRET_RULE",
            file_path="app.py",
            line_start=2,
            line_end=2,
            severity="high",
            category="Secrets",
            message="Possible secret",
            evidence_text="password = 'DoNotExposeThisValue'",
            source="secret_scanner",
        )
        report = AuditReport(
            report_id="abcd1234",
            mode="diff_scan",
            summary="Scanned 1 file.",
            findings=[finding],
            metrics=AuditMetrics(confirmed_findings=1),
            fallback_reasons=["tool failed with password = 'DoNotExposeFallbackValue'"],
        )

        comment = render_pr_comment(report)

        self.assertIn(COMMENT_MARKER, comment)
        self.assertIn("app.py:2", comment)
        self.assertNotIn("DoNotExposeThisValue", comment)
        self.assertNotIn("DoNotExposeFallbackValue", comment)
        self.assertNotIn("evidence", comment.lower())

    def test_report_retention_removes_complete_old_report_sets_only(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            now = time.time()
            for report_id, age_days in (("aaaabbbb", 10), ("ccccdddd", 5), ("eeeeffff", 0)):
                for suffix in ("json", "md", "sarif"):
                    path = root / f"{report_id}.{suffix}"
                    path.write_text("{}", encoding="utf-8")
                    timestamp = now - age_days * 86400
                    os.utime(path, (timestamp, timestamp))
            unrelated = root / "latest.json"
            unrelated.write_text("{}", encoding="utf-8")

            result = prune_reports(
                root,
                ReportRetentionPolicy(enabled=True, max_reports=2, max_age_days=30),
                now=now,
            )

            self.assertEqual(result.pruned_reports, 1)
            self.assertFalse((root / "aaaabbbb.json").exists())
            self.assertTrue((root / "eeeeffff.sarif").exists())
            self.assertTrue(unrelated.exists())


if __name__ == "__main__":
    unittest.main()
