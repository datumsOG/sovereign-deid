import unittest
from src.deid import generalize as g

class TestGeneralize(unittest.TestCase):
    def test_age_band_level_0_is_5yr(self):
        self.assertEqual(g.age_to_band(41, level=0), "40-44")
    def test_age_band_level_1_is_10yr(self):
        self.assertEqual(g.age_to_band(41, level=1), "40-49")
    def test_age_band_level_2_suppresses(self):
        self.assertEqual(g.age_to_band(41, level=2), "*")
    def test_postal_to_region_level_0_is_fsa(self):
        self.assertEqual(g.postal_to_region("M5V 2T6", level=0), "M5V")
    def test_postal_to_region_level_1_is_first_char(self):
        self.assertEqual(g.postal_to_region("M5V 2T6", level=1), "M")
    def test_postal_to_region_level_2_suppresses(self):
        self.assertEqual(g.postal_to_region("M5V 2T6", level=2), "*")
    def test_generalize_record_applies_levels(self):
        qi = {"age": 41, "gender": "female", "postal_code": "M5V 2T6", "marital_status": "M"}
        out = g.generalize_record(qi, age_level=1, region_level=1)
        self.assertEqual(out, {"age_band": "40-49", "gender": "female",
                               "region": "M", "marital_status": "M"})

    def test_apply_to_patient_generalizes_and_drops_precise_location(self):
        pat = {
            "birthDate": "1980-04-15",
            "ageBand": None,  # not yet set
            "address": [{
                "line": ["1 Fake St"], "city": "Toronto", "state": "ON",
                "postalCode": "M5V 2T6", "country": "CA",
                "extension": [{"url": "geolocation", "extension": [
                    {"url": "latitude", "valueDecimal": 43.6}, {"url": "longitude", "valueDecimal": -79.3}]}],
            }],
        }
        # ageBand sentinel None should be overwritten; force the birthDate path
        pat.pop("ageBand")
        actions = g.apply_to_patient(pat, age_band="40-49", region="M")
        self.assertNotIn("birthDate", pat)                 # exact DOB gone
        self.assertEqual(pat["ageBand"], "40-49")
        addr = pat["address"][0]
        self.assertNotIn("line", addr)
        self.assertNotIn("city", addr)
        self.assertNotIn("postalCode", addr)               # raw FSA gone
        self.assertNotIn("extension", addr)                # exact GPS gone
        self.assertEqual(addr["region"], "M")
        self.assertEqual(addr["state"], "ON")              # province retained
        blob = str(pat)
        self.assertNotIn("43.6", blob)                     # no GPS leaks
        self.assertNotIn("M5V 2T6", blob)
        self.assertTrue(any("generalized" in a for _, a in actions))

if __name__ == "__main__":
    unittest.main()
