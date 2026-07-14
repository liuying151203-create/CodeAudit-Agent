import unittest
from pathlib import Path

from app.diff.diff_parser import parse_unified_diff


class DiffParserTests(unittest.TestCase):
    def test_parse_sample_diff(self):
        files = parse_unified_diff(Path("data/sample_repos/sample.diff").read_text(encoding="utf-8"))
        self.assertTrue(files)
        self.assertEqual(files[0]["path"], "app.py")
        self.assertTrue(files[0]["changed_lines"])


if __name__ == "__main__":
    unittest.main()
