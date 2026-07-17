import json
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agent.tools import FindingMergerTool
from app.schemas import AuditBudget, AuditPlan, AuditStageName, AuditStagePlan, ProjectProfile, Severity
from app.schemas.execution import ToolRunResult, ValidatedToolCall
from app.schemas.finding import Finding
from app.schemas.project import SecurityTool
from app.security_tools.adapters import CommandOutput, _semgrep_core_targets, execute_adapter, parse_bandit_json, parse_gitleaks_json, parse_semgrep_json
from app.security_tools.gateway import execute_tool_plan, select_tool_plan
from app.security_tools.registry import load_security_tools, mcp_tool_to_security_tool


class ToolGatewayTests(unittest.TestCase):
    def setUp(self):
        self.files = [
            {
                "path": "app.py",
                "content": "password = 'demo-secret'\nquery = 'SELECT * FROM users WHERE id=' + user_id\n",
                "source": "repo",
            },
            {"path": "routes.py", "content": "def health(): return {}\n", "source": "repo"},
        ]
        self.profile = ProjectProfile(languages=["Python"], risk_surfaces=["Secrets", "SQL Injection"])
        self.audit_plan = AuditPlan(
            stages=[
                AuditStagePlan(
                    stage=AuditStageName.INJECTION,
                    priority=Severity.HIGH,
                    risk_types=["SQL Injection"],
                    target_files=["app.py", "../outside.py"],
                    required_capabilities=["scan_sql_patterns"],
                )
            ]
        )

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    def test_selector_rejects_unsafe_paths_batches_calls_and_falls_back(self, _which):
        plan = select_tool_plan(
            self.profile,
            [],
            "repo_scan",
            self.files,
            self.audit_plan,
            ".",
            AuditBudget(max_files_per_call=1),
        )

        self.assertIn("../outside.py", plan.rejected_targets)
        self.assertIn("custom_rule_scanner", plan.selected_tools)
        self.assertIn("secret_scanner", plan.selected_tools)
        self.assertIn("semgrep", plan.unavailable_tools)
        self.assertTrue(plan.fallback_reasons)
        self.assertTrue(all(len(call.target_files) <= 1 for call in plan.tool_calls))
        self.assertTrue(all(set(call.arguments) == {"mode"} for call in plan.tool_calls))

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    def test_builtin_fallback_executes_without_external_tools(self, _which):
        plan = select_tool_plan(self.profile, [], "repo_scan", self.files, self.audit_plan, ".")
        results = execute_tool_plan(plan, self.files, ".", "repo_scan")
        categories = {finding.category for result in results for finding in result.findings}

        self.assertIn("Secrets", categories)
        self.assertIn("SQL Injection", categories)
        self.assertTrue(any(result.tool_name == "semgrep" and result.status == "skipped" for result in results))

    def test_external_json_parsers_normalize_and_redact(self):
        root = Path(".").resolve()
        bandit = parse_bandit_json(
            json.dumps(
                {
                    "results": [
                        {
                            "filename": "app.py",
                            "line_number": 3,
                            "line_range": [3],
                            "issue_severity": "HIGH",
                            "issue_confidence": "HIGH",
                            "test_id": "B602",
                            "issue_text": "subprocess with shell=True",
                            "code": "subprocess.run(command, shell=True)",
                        }
                    ]
                }
            ),
            root,
        )
        semgrep = parse_semgrep_json(
            ".\r\n" + json.dumps(
                {
                    "results": [
                        {
                            "check_id": "codeaudit.python.os-system",
                            "path": "app.py",
                            "start": {"line": 4},
                            "end": {"line": 4},
                            "extra": {"severity": "ERROR", "message": "unsafe command", "metadata": {"risk_type": "Command Execution"}},
                        }
                    ]
                }
            ),
            root,
        )
        gitleaks = parse_gitleaks_json(
            json.dumps([{"RuleID": "generic-api-key", "File": "app.py", "StartLine": 1, "EndLine": 1, "Secret": "must-not-leak"}]),
            root,
        )

        self.assertEqual(bandit[0].source, "bandit")
        self.assertEqual(semgrep[0].category, "Command Execution")
        self.assertEqual(gitleaks[0].evidence_text, "<redacted secret evidence>")
        self.assertNotIn("must-not-leak", gitleaks[0].model_dump_json())

    def test_semgrep_core_targets_use_absolute_project_paths(self):
        root = Path(".").resolve()
        payload = _semgrep_core_targets(root, ["app/agent/graph.py"])

        target = payload[1][0][1]
        self.assertTrue(Path(target["path"]["fpath"]).is_absolute())
        self.assertEqual(target["path"]["ppath"], "/app/agent/graph.py")
        self.assertEqual(target["analyzer"], "python")

    @patch("app.security_tools.adapters._windows_semgrep_core", return_value=None)
    @patch("app.security_tools.adapters.run_fixed_command")
    def test_semgrep_adapter_uses_fixed_command_and_filters_diff_lines(self, command, _core):
        command.return_value = CommandOutput(
            returncode=0,
            stdout=json.dumps(
                {
                    "results": [
                        {
                            "check_id": "rule.one",
                            "path": "app.py",
                            "start": {"line": 1},
                            "end": {"line": 1},
                            "extra": {"severity": "ERROR", "message": "first", "metadata": {"risk_type": "Command Execution"}},
                        },
                        {
                            "check_id": "rule.two",
                            "path": "app.py",
                            "start": {"line": 2},
                            "end": {"line": 2},
                            "extra": {"severity": "ERROR", "message": "second", "metadata": {"risk_type": "Command Execution"}},
                        },
                    ]
                }
            ),
            stderr="",
            duration_ms=10,
        )
        tool = SecurityTool(name="semgrep", adapter="semgrep_json", executable="semgrep", read_only=True)
        call = ValidatedToolCall(
            call_id="call-1",
            tool_name="semgrep",
            arguments={"command": "powershell -c malicious"},
            target_files=["app.py"],
        )
        files = [{"path": "app.py", "content": "one\ntwo\n", "changed_lines": [2], "source": "diff"}]

        result = execute_adapter(tool, call, files, Path(".").resolve(), "diff_scan")
        argv = command.call_args.args[0]

        self.assertEqual([finding.line_start for finding in result.findings], [2])
        self.assertEqual(argv[0:2], ["semgrep", "scan"])
        self.assertNotIn("powershell -c malicious", argv)

    @patch("app.security_tools.adapters.run_fixed_command")
    def test_gitleaks_adapter_uses_current_directory_command(self, command):
        command.return_value = CommandOutput(returncode=0, stdout="", stderr="", duration_ms=10)
        tool = SecurityTool(name="gitleaks", adapter="gitleaks_json", executable="gitleaks", read_only=True)
        call = ValidatedToolCall(call_id="call-2", tool_name="gitleaks")

        result = execute_adapter(tool, call, self.files, Path(".").resolve(), "repo_scan")
        argv = command.call_args.args[0]

        self.assertEqual(argv[0:2], ["gitleaks", "dir"])
        self.assertNotIn("detect", argv)
        self.assertEqual(result.status, "success")

    def test_merger_retains_multiple_tool_sources(self):
        first = Finding(
            finding_id="one",
            rule_id="RULE_A",
            file_path="app.py",
            line_start=2,
            line_end=2,
            severity="medium",
            category="SQL Injection",
            message="first",
            evidence_text="query",
            source="custom_rule_scanner",
        )
        second = first.model_copy(
            update={
                "finding_id": "two",
                "rule_id": "RULE_B",
                "severity": "high",
                "source": "semgrep",
                "sources": ["semgrep"],
                "source_rule_ids": ["RULE_B"],
            }
        )

        merged = FindingMergerTool().run(
            [
                ToolRunResult(tool_name="custom_rule_scanner", status="success", findings=[first]),
                ToolRunResult(tool_name="semgrep", status="success", findings=[second]),
            ]
        )

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "high")
        self.assertEqual(merged[0].sources, ["custom_rule_scanner", "semgrep"])
        self.assertEqual(merged[0].source_rule_ids, ["RULE_A", "RULE_B"])

    def test_registry_and_mcp_conversion_are_structured(self):
        tools = {tool.name: tool for tool in load_security_tools()}
        mcp_tool = mcp_tool_to_security_tool(
            {
                "name": "remote-sast",
                "description": "Read-only remote scanner",
                "annotations": {"readOnlyHint": True},
                "metadata": {"capabilities": ["scan_sql_patterns"], "supported_languages": ["Python"]},
            }
        )

        self.assertEqual(tools["semgrep"].adapter, "semgrep_json")
        self.assertEqual(tools["gitleaks"].capabilities, ["scan_secrets"])
        self.assertEqual(mcp_tool.adapter, "mcp")
        self.assertTrue(mcp_tool.read_only)


if __name__ == "__main__":
    unittest.main()
