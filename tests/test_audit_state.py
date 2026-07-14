import unittest

from app.agent.state import normalize_audit_state, serialize_audit_state, sync_audit_state
from app.schemas import AuditBudget, ProjectProfile


class AuditStateTests(unittest.TestCase):
    def test_normalize_builds_all_state_sections(self):
        state = normalize_audit_state({"request": {"mode": "repo_scan", "repo_path": "demo"}})

        self.assertEqual(state["mode"], "repo_scan")
        self.assertEqual(state["repo_path"], "demo")
        self.assertIsInstance(state["budget"], AuditBudget)
        self.assertEqual(
            set(serialize_audit_state(state)),
            {"request", "project_context", "planning", "execution", "findings", "runtime"},
        )

    def test_sync_mirrors_legacy_fields_into_sections(self):
        state = normalize_audit_state({"mode": "repo_scan", "repo_path": "demo"})
        state["project_profile"] = ProjectProfile(languages=["Python"])
        state["scanned_files"] = [{"path": "app.py", "content": "print('ok')"}]

        sync_audit_state(state)

        self.assertEqual(state["project_context"]["project_profile"].languages, ["Python"])
        self.assertEqual(state["project_context"]["scanned_files"][0]["path"], "app.py")

    def test_serialized_state_contains_json_safe_models(self):
        state = normalize_audit_state(
            {
                "mode": "diff_scan",
                "diff_text": "diff --git a/a.py b/a.py",
                "scanned_files": [{"path": "a.py", "source": "diff", "content": "secret = 'value'", "changed_lines": [1]}],
            }
        )
        snapshot = serialize_audit_state(state)

        self.assertEqual(snapshot["request"]["mode"], "diff_scan")
        self.assertEqual(snapshot["request"]["diff_text"], "<omitted from report snapshot>")
        self.assertNotIn("content", snapshot["project_context"]["scanned_files"][0])
        self.assertEqual(snapshot["project_context"]["scanned_files"][0]["content_length"], 16)
        self.assertEqual(snapshot["runtime"]["budget"]["max_tool_rounds_per_stage"], 2)
        self.assertNotIn("final_report", snapshot)

    def test_normalize_restores_models_from_structured_snapshot(self):
        snapshot = {
            "request": {"mode": "repo_scan", "repo_path": "demo"},
            "project_context": {
                "project_profile": {"languages": ["Python"], "profile_scope": "full_repo"},
                "scanned_files": [],
                "changed_files": [],
                "retrieved_knowledge": [],
            },
            "planning": {"stage_queue": [], "stage_results": []},
            "execution": {"tool_results": [], "evidence_pool": []},
            "findings": {"candidate_findings": []},
            "runtime": {"budget": {"max_tool_rounds_per_stage": 4}, "metrics": {}},
        }

        state = normalize_audit_state(snapshot)

        self.assertIsInstance(state["project_profile"], ProjectProfile)
        self.assertEqual(state["project_profile"].languages, ["Python"])
        self.assertEqual(state["budget"].max_tool_rounds_per_stage, 4)


if __name__ == "__main__":
    unittest.main()
