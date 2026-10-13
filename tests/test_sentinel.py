import unittest, tempfile, os
from pathlib import Path
from src.sentinel import sentinel

class TestSentinel(unittest.TestCase):
    def test_world_readable_key_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "provider.key"; key.write_text("x"); os.chmod(key, 0o644)
            problems = sentinel.check_key_permissions(key)
            self.assertTrue(any("readable" in p for p in problems))

    def test_tight_key_passes(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "provider.key"; key.write_text("x"); os.chmod(key, 0o600)
            self.assertEqual(sentinel.check_key_permissions(key), [])

    def test_unknown_file_in_open_zone_flagged(self):
        known = {"a.json", "b.json"}
        present = {"a.json", "b.json", "MYSTERY.json"}
        problems = sentinel.check_no_unknown_records(present, known)
        self.assertTrue(any("MYSTERY.json" in p for p in problems))

    def test_sealed_quiescent_passes_when_unchanged(self):
        self.assertEqual(sentinel.check_sealed_quiescent(123.0, 123.0), [])

    def test_sealed_quiescent_first_run_has_no_baseline(self):
        self.assertEqual(sentinel.check_sealed_quiescent(123.0, None), [])

    def test_sealed_quiescent_alarms_on_unexplained_write(self):
        # the blind spot that let roast.md into sealed: a write changes the dir mtime
        problems = sentinel.check_sealed_quiescent(200.0, 123.0)
        self.assertTrue(any("wrote INTO the sealed zone" in p for p in problems))

if __name__ == "__main__":
    unittest.main()
