from app.scanners.builtin_rules import scan_text


def test_scan_text_finds_core_risks():
    text = """
password = "ProdPassword123!"
eval(user_input)
subprocess.run(command, shell=True)
pickle.load(handle)
sql = "SELECT * FROM users WHERE name = '" + name + "'"
"""
    findings = scan_text("app.py", text)
    rule_ids = {finding.rule_id for finding in findings}
    assert "PY_SECRET_HARDCODED" in rule_ids
    assert "PY_DANGEROUS_FUNCTION" in rule_ids
    assert "PY_SUBPROCESS_SHELL_TRUE" in rule_ids
    assert "PY_SQL_STRING_BUILD" in rule_ids
