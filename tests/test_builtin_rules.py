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

    def test_java_and_mybatis_fallback_rules(self):
        java_findings = scan_text("CommandService.java", 'Runtime.getRuntime().exec(command);\nnew ObjectInputStream(stream);')
        mapper_findings = scan_text("UserMapper.xml", '<select>SELECT * FROM users WHERE name = "${name}"</select>')

        self.assertIn("JAVA_COMMAND_EXECUTION", {finding.rule_id for finding in java_findings})
        self.assertIn("JAVA_UNSAFE_DESERIALIZATION", {finding.rule_id for finding in java_findings})
        self.assertIn("JAVA_MYBATIS_RAW_SUBSTITUTION", {finding.rule_id for finding in mapper_findings})


if __name__ == "__main__":
    unittest.main()
