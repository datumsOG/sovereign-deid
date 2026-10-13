import unittest
from src.deid import pseudonymize as ps

SALT = b"test-salt-not-the-real-one"

class TestPseudonymize(unittest.TestCase):
    def test_hash_is_deterministic_and_salted(self):
        a = ps.hash_identifier("MRN-123", SALT)
        b = ps.hash_identifier("MRN-123", SALT)
        c = ps.hash_identifier("MRN-123", b"other-salt")
        self.assertEqual(a, b)            # deterministic
        self.assertNotEqual(a, c)         # salt changes output
        self.assertNotIn("MRN-123", a)    # original not recoverable in the token

    def test_date_shift_is_per_patient_stable(self):
        o1 = ps.date_shift_days("AAAA-1111", SALT)
        o2 = ps.date_shift_days("AAAA-1111", SALT)
        o3 = ps.date_shift_days("BBBB-2222", SALT)
        self.assertEqual(o1, o2)                 # same patient → same offset
        self.assertTrue(-365 <= o1 <= 365)
        self.assertNotEqual(o1, o3)              # different patient → (almost surely) different

    def test_shift_date_preserves_intervals(self):
        # two dates shifted by the SAME offset keep their gap
        off = 30
        d1 = ps.shift_date("2021-06-01", off)
        d2 = ps.shift_date("2021-06-11", off)
        self.assertEqual(d1, "2021-07-01")
        self.assertEqual(d2, "2021-07-11")

    def test_shift_datetime_keeps_time_component(self):
        self.assertTrue(ps.shift_date("2021-06-01T10:00:00Z", 1).startswith("2021-06-02"))

if __name__ == "__main__":
    unittest.main()
