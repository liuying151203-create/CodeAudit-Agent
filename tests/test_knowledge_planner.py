import unittest

from app.agent.planner import PLANNER_CAPABILITIES, build_template_audit_plan, parse_llm_audit_plan
from app.knowledge.retriever import retrieve_vulnerability_knowledge
from app.project.reader import build_project_profile
from app.schemas.enums import AuditStageName


class KnowledgePlannerTests(unittest.TestCase):
    def test_retriever_returns_only_relevant_fastapi_knowledge(self):
        profile = build_project_profile("data/sample_repos/fastapi_app", [])

        knowledge = retrieve_vulnerability_knowledge(profile)
        ids = {item.knowledge_id for item in knowledge}

        self.assertEqual(ids, {"broken_access_control", "path_traversal", "secret_leak", "sql_injection"})
        sql = next(item for item in knowledge if item.knowledge_id == "sql_injection")
        self.assertIn("scan_sql_patterns", sql.recommended_capabilities)
        self.assertGreaterEqual(sql.relevance_score, 0.8)
        self.assertTrue(sql.match_reasons)

    def test_template_planner_builds_dynamic_java_stages(self):
        profile = build_project_profile("data/sample_repos/small_java_app", [])
        knowledge = retrieve_vulnerability_knowledge(profile)

        plan = build_template_audit_plan(profile, knowledge)
        stages = [stage.stage for stage in plan.stages]

        self.assertEqual(stages, [AuditStageName.SECRET, AuditStageName.INJECTION, AuditStageName.AUTH])
        injection = next(stage for stage in plan.stages if stage.stage == AuditStageName.INJECTION)
        self.assertIn("scan_sql_patterns", injection.required_capabilities)
        self.assertIn("extract_call_chain", injection.required_capabilities)
        self.assertTrue(injection.target_files)
        self.assertTrue(injection.evidence_goals)

    def test_user_task_can_activate_additional_risk_knowledge(self):
        profile = build_project_profile("data/sample_repos/fastapi_app", [])

        knowledge = retrieve_vulnerability_knowledge(profile, "重点检查 command injection 和 shell 调用")

        self.assertIn("command_injection", {item.knowledge_id for item in knowledge})

    def test_llm_plan_parser_filters_unknown_tools_and_files(self):
        profile = build_project_profile("data/sample_repos/fastapi_app", [])
        fallback = build_template_audit_plan(profile, retrieve_vulnerability_knowledge(profile))
        data = {
            "summary": "Focused plan",
            "stages": [
                {
                    "stage": "injection",
                    "priority": "high",
                    "risk_types": ["SQL Injection"],
                    "target_files": ["db/repository.py", "../../outside.py"],
                    "required_capabilities": ["scan_sql_patterns", "run_shell"],
                    "evidence_goals": ["Trace input to query"],
                    "reason": "Database access exists",
                }
            ],
        }

        plan = parse_llm_audit_plan(data, fallback, profile)

        self.assertIsNotNone(plan)
        self.assertEqual(plan.stages[0].target_files, ["db/repository.py"])
        self.assertEqual(plan.stages[0].required_capabilities, ["scan_sql_patterns"])
        self.assertTrue(set(plan.stages[0].required_capabilities) <= PLANNER_CAPABILITIES)


if __name__ == "__main__":
    unittest.main()
