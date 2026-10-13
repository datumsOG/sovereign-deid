import unittest
from src.deid import config

class TestConfig(unittest.TestCase):
    def test_release_model_is_non_public(self):
        self.assertEqual(config.RELEASE_MODEL, "non_public_third_party")

    def test_threshold_is_documented_value(self):
        # IPC non-public sharing commonly uses 0.09 max acceptable risk
        self.assertAlmostEqual(config.RISK_THRESHOLD, 0.09)

    def test_quasi_identifier_keys(self):
        self.assertEqual(
            config.QUASI_IDENTIFIERS,
            ["age_band", "gender", "region", "marital_status"],
        )

    def test_ssn_is_a_direct_identifier_system(self):
        self.assertIn("http://hl7.org/fhir/sid/us-ssn", config.DIRECT_IDENTIFIER_SYSTEMS)

if __name__ == "__main__":
    unittest.main()
