import json
import unittest
from datetime import date
from src.deid import pipeline
from tests.fixtures._fixtures import load

SALT = b"test-salt"

class TestPipeline(unittest.TestCase):
    def test_deidentify_record_strips_direct_identifiers(self):
        out, actions, qi = pipeline.deidentify_record(load("patient_a"), SALT, today=date(2021, 6, 1))
        pat = next(e["resource"] for e in out["entry"] if e["resource"]["resourceType"] == "Patient")
        self.assertNotIn("name", pat)                      # names removed
        self.assertNotIn("telecom", pat)                   # contact removed
        blob = str(out)
        self.assertNotIn("999-00-0000", blob)              # SSN not present in clear
        self.assertNotIn("Testfamily", blob)
        self.assertEqual(qi["age"], 41)

    def test_unknown_identifier_system_is_still_hashed(self):
        # audit A.3 (default-hash): an identifier whose system is NOT in any known list
        # must still be tokenized — no allow-list gap leaks an MRN/UUID.
        bundle = {"entry": [{"resource": {
            "resourceType": "Patient", "id": "X-1", "birthDate": "1980-01-01",
            "identifier": [{"system": "urn:some:unknown:system", "value": "SECRET-UUID-XYZ"}],
        }}]}
        out, actions, _ = pipeline.deidentify_record(bundle, SALT, today=date(2021, 6, 1))
        self.assertNotIn("SECRET-UUID-XYZ", str(out))
        self.assertTrue(any(a[1] == "hashed" for a in actions))

    def test_corpus_reaches_k_anonymity(self):
        # 10 records: five identical female/M, five identical male/S, same age & postal.
        # At generalization level 0 each forms a class of 5 -> k-anonymity met, none suppressed.
        base_f = {"age": 41, "gender": "female", "postal_code": "M5V 2T6", "marital_status": "M"}
        base_m = {"age": 39, "gender": "male", "postal_code": "M5V 2T6", "marital_status": "S"}
        qis = [dict(base_f) for _ in range(5)] + [dict(base_m) for _ in range(5)]
        report = pipeline.assess_corpus(qis)
        self.assertTrue(report["meets_threshold"])
        self.assertGreaterEqual(report["k_anonymity"], 5)
        self.assertEqual(report["records_suppressed"], 0)
        self.assertLessEqual(report["overall_risk"], 0.09)

    def test_corpus_suppresses_a_lone_outlier(self):
        # 5 identical + 1 unique outlier that can never join a class of 5 -> suppressed.
        base = {"age": 41, "gender": "female", "postal_code": "M5V 2T6", "marital_status": "M"}
        outlier = {"age": 41, "gender": "male", "postal_code": "K1A 0B1", "marital_status": "W"}
        qis = [dict(base) for _ in range(5)] + [outlier]
        report = pipeline.assess_corpus(qis)
        self.assertTrue(report["meets_threshold"])
        self.assertEqual(report["records_suppressed"], 1)

if __name__ == "__main__":
    unittest.main()


def test_patient_extensions_are_dropped_by_default():
    """Audit 2026-07-23 finding #1: mothersMaidenName and birthPlace leaked into
    released output because Patient.extension was never processed. Deny by default."""
    from src.deid import pipeline, config
    pat = {
        "id": "p1",
        "extension": [
            {"url": "http://hl7.org/fhir/StructureDefinition/patient-mothersMaidenName",
             "valueString": "Claudine313 Ondricka197"},
            {"url": "http://hl7.org/fhir/StructureDefinition/patient-birthPlace",
             "valueAddress": {"city": "Stratford", "country": "CA"}},
        ],
    }
    actions = pipeline._strip_patient(pat, b"salt", 0)
    assert "extension" not in pat, "extensions must not survive de-identification"
    blob = json.dumps(pat)
    assert "Ondricka197" not in blob and "Stratford" not in blob
    assert any(a[0].startswith("extension:") and a[1] == "removed" for a in actions)


def test_safe_listed_extension_is_retained():
    from src.deid import pipeline, config
    safe = "http://example.org/fhir/StructureDefinition/harmless"
    pat = {"id": "p1", "extension": [
        {"url": safe, "valueString": "keep me"},
        {"url": "http://hl7.org/fhir/StructureDefinition/patient-birthPlace",
         "valueAddress": {"city": "Stratford"}},
    ]}
    original = config.SAFE_EXTENSION_URLS
    config.SAFE_EXTENSION_URLS = (safe,)
    try:
        pipeline._strip_patient(pat, b"salt", 0)
    finally:
        config.SAFE_EXTENSION_URLS = original
    urls = [e["url"] for e in pat["extension"]]
    assert urls == [safe]
