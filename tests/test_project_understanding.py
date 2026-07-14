import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.project.reader import build_project_profile
from app.schemas.enums import ProfileScope


class ProjectUnderstandingTests(unittest.TestCase):
    def test_fastapi_project_profile(self):
        profile = build_project_profile("data/sample_repos/fastapi_app", [])

        self.assertEqual(profile.languages, ["Python"])
        self.assertIn("FastAPI", profile.frameworks)
        self.assertIn("SQLAlchemy", profile.frameworks)
        self.assertEqual(profile.dependency_files, ["requirements.txt"])
        self.assertIn("main.py", profile.entrypoints)
        self.assertIn("api/users.py", profile.route_files)
        self.assertIn("auth/jwt.py", profile.auth_files)
        self.assertIn("db/repository.py", profile.db_files)
        self.assertIn("api/upload.py", profile.upload_files)
        self.assertIn("SQL Injection", profile.risk_surfaces)
        self.assertIn("Broken Access Control", profile.risk_surfaces)
        self.assertEqual(profile.profile_scope, ProfileScope.FULL_REPO)
        self.assertEqual(profile.profile_confidence, 1.0)

    def test_flask_project_profile(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("flask\nsqlalchemy\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from flask import Flask\napp = Flask(__name__)\n@app.get('/health')\ndef health(): return {}\n",
                encoding="utf-8",
            )

            profile = build_project_profile(str(root), [])

        self.assertEqual(profile.languages, ["Python"])
        self.assertIn("Flask", profile.frameworks)
        self.assertIn("SQLAlchemy", profile.frameworks)
        self.assertIn("app.py", profile.entrypoints)
        self.assertIn("app.py", profile.route_files)

    def test_spring_mybatis_project_profile(self):
        profile = build_project_profile("data/sample_repos/small_java_app", [])

        self.assertEqual(profile.languages, ["Java"])
        self.assertIn("Spring Boot", profile.frameworks)
        self.assertIn("Spring MVC", profile.frameworks)
        self.assertIn("Spring Security", profile.frameworks)
        self.assertIn("MyBatis", profile.frameworks)
        self.assertIn("src/main/java/com/example/Application.java", profile.entrypoints)
        self.assertIn("src/main/java/com/example/controller/UserController.java", profile.route_files)
        self.assertIn("src/main/java/com/example/security/SecurityConfig.java", profile.auth_files)
        self.assertIn("src/main/resources/mapper/UserMapper.xml", profile.db_files)
        self.assertIn("dynamic_sql_construction", profile.security_signals)
        self.assertIn("SQL Injection", profile.risk_surfaces)

    def test_diff_only_profile_does_not_invent_repository_context(self):
        profile = build_project_profile(
            None,
            [
                {
                    "path": "src/UserController.java",
                    "source": "diff",
                    "content": "@RestController class UserController {}",
                    "changed_lines": [1],
                }
            ],
        )

        self.assertEqual(profile.profile_scope, ProfileScope.DIFF_ONLY)
        self.assertEqual(profile.dependency_files, [])
        self.assertNotIn("Spring Boot", profile.frameworks)
        self.assertIn("Spring MVC", profile.frameworks)
        self.assertTrue(profile.missing_context)


if __name__ == "__main__":
    unittest.main()
