import unittest
from datetime import date
from src.deid import classify
from tests.fixtures._fixtures import load

class TestClassify(unittest.TestCase):
    def test_extract_patient(self):
        pat = classify.extract_patient(load("patient_a"))
        self.assertEqual(pat["id"], "AAAA-1111")

    def test_quasi_identifiers(self):
        qi = classify.quasi_identifiers(load("patient_a"), today=date(2021, 6, 1))
        self.assertEqual(qi["age"], 41)          # born 1980-04-15
        self.assertEqual(qi["gender"], "female")
        self.assertEqual(qi["postal_code"], "M5V 2T6")
        self.assertEqual(qi["marital_status"], "M")

    def test_no_patient_raises_specific_error(self):
        # audit A.4 / PD-003: callers must be able to skip ONLY the no-Patient case,
        # not swallow every ValueError. NoPatientError stays a ValueError for compat.
        with self.assertRaises(classify.NoPatientError):
            classify.extract_patient({"entry": [{"resource": {"resourceType": "Organization"}}]})
        self.assertTrue(issubclass(classify.NoPatientError, ValueError))

if __name__ == "__main__":
    unittest.main()
