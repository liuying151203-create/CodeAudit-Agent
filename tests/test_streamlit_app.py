import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


class StreamlitAppTests(unittest.TestCase):
    def test_initial_page_renders_without_exceptions(self):
        app = AppTest.from_file("frontend/streamlit_app.py", default_timeout=30).run()

        self.assertFalse(app.exception)
        self.assertTrue(any("CodeAudit-Agent" in item.value for item in app.markdown))
        self.assertTrue(app.button)

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_repo_scan_renders_complete_workspace(self, _llm, _which):
        app = AppTest.from_file("frontend/streamlit_app.py", default_timeout=120).run()
        app.button[0].click().run(timeout=120)

        self.assertFalse(app.exception)
        self.assertTrue(app.success)
        self.assertIn("项目概览", [item.label for item in app.tabs])
        self.assertIn("SARIF", [item.label for item in app.tabs])
        self.assertEqual(next(item.value for item in app.metric if item.label == "已确认"), "7")

    @patch("app.security_tools.gateway.shutil.which", return_value=None)
    @patch("app.agent.tools._llm_enabled", return_value=False)
    def test_diff_scan_runs_from_sidebar(self, _llm, _which):
        app = AppTest.from_file("frontend/streamlit_app.py", default_timeout=120).run()
        app.segmented_control[0].set_value("Git Diff").run()
        app.button[0].click().run(timeout=120)

        self.assertFalse(app.exception)
        self.assertEqual(next(item.value for item in app.metric if item.label == "已确认"), "4")
        self.assertTrue(any(item.label == "Diff 来源" for item in app.segmented_control))


if __name__ == "__main__":
    unittest.main()
