import unittest
from src.deid import risk

# generalized QI rows (equivalence-class keys)
ROWS = [
    {"age_band": "40-49", "gender": "female", "region": "M", "marital_status": "M"},
    {"age_band": "40-49", "gender": "female", "region": "M", "marital_status": "M"},
    {"age_band": "40-49", "gender": "female", "region": "M", "marital_status": "M"},
    {"age_band": "70-79", "gender": "male",   "region": "K", "marital_status": "S"},  # unique
]
KEYS = ["age_band", "gender", "region", "marital_status"]

class TestRisk(unittest.TestCase):
    def test_equivalence_classes(self):
        classes = risk.equivalence_classes(ROWS, KEYS)
        sizes = sorted(classes.values())
        self.assertEqual(sizes, [1, 3])

    def test_max_risk_is_one_over_smallest_class(self):
        classes = risk.equivalence_classes(ROWS, KEYS)
        self.assertAlmostEqual(risk.max_vulnerability(classes), 1.0)  # the unique record

    def test_average_vulnerability(self):
        classes = risk.equivalence_classes(ROWS, KEYS)
        # rows: three at 1/3, one at 1/1  -> mean = (1/3*3 + 1)/4 = 0.5
        self.assertAlmostEqual(risk.average_vulnerability(ROWS, classes, KEYS), 0.5)

    def test_min_class_size(self):
        classes = risk.equivalence_classes(ROWS, KEYS)
        self.assertEqual(risk.min_class_size(classes), 1)

    def test_overall_risk_scales_by_attack_probability(self):
        self.assertAlmostEqual(risk.overall_risk(1.0, 0.05), 0.05)

    def test_meets_threshold(self):
        self.assertTrue(risk.meets_threshold(0.04, threshold=0.09))
        self.assertFalse(risk.meets_threshold(0.5, threshold=0.09))

if __name__ == "__main__":
    unittest.main()
