import unittest, json, tempfile
from pathlib import Path
from src.deid import audit

class TestAudit(unittest.TestCase):
    def test_entry_records_actions_without_values(self):
        e = audit.build_entry("patient-token-abc", [
            ("name", "removed"),
            ("identifier:ssn", "hashed"),
            ("birthDate", "date_shifted"),
            ("address.postalCode", "generalized:region=M"),
        ])
        self.assertEqual(e["record"], "patient-token-abc")
        blob = json.dumps(e)
        self.assertNotIn("999-00-0000", blob)   # no original PHI ever
        self.assertIn("hashed", blob)

    def test_write_and_count(self):
        with tempfile.TemporaryDirectory() as d:
            audit.write_entry(Path(d), audit.build_entry("t1", [("name", "removed")]))
            audit.write_entry(Path(d), audit.build_entry("t2", [("name", "removed")]))
            self.assertEqual(audit.count(Path(d)), 2)

if __name__ == "__main__":
    unittest.main()
