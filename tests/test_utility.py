import unittest
from src.deid import utility

class TestUtility(unittest.TestCase):
    def test_suppression_rate(self):
        rows = [{"age_band": "*", "region": "M"}, {"age_band": "40-49", "region": "*"}]
        # 2 suppressed cells out of 4 -> 0.5
        self.assertAlmostEqual(utility.suppression_rate(rows, ["age_band", "region"]), 0.5)

    def test_distinct_retained(self):
        rows = [{"region": "M"}, {"region": "M"}, {"region": "K"}]
        self.assertEqual(utility.distinct_retained(rows, "region"), 2)

if __name__ == "__main__":
    unittest.main()
