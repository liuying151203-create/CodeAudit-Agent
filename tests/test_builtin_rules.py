import unittest

from app.scanners.builtin_rules import scan_text


class BuiltinRulesTests(unittest.TestCase):
    def test_scan_text_finds_core_risks(self):
        text = """
password = "ProdPassword123!"
eval(user_input)
subprocess.run(command, shell=True)
pickle.load(handle)
sql = "SELECT * FROM users WHERE name = '" + name + "'"
"""
        findings = scan_text("app.py", text)
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("PY_SECRET_HARDCODED", rule_ids)
        self.assertIn("PY_DANGEROUS_FUNCTION", rule_ids)
        self.assertIn("PY_SUBPROCESS_SHELL_TRUE", rule_ids)
        self.assertIn("PY_SQL_STRING_BUILD", rule_ids)


if __name__ == "__main__":
    unittest.main()
