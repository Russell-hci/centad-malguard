from __future__ import annotations

import importlib.util
import unittest

if importlib.util.find_spec("pandas") is None:
    raise unittest.SkipTest("pandas is required for statistical-analysis tests; install requirements.txt to run them")

import pandas as pd

from binaryshield.evaluation.statistical_analysis import (
    exact_mcnemar_pvalue,
    metric_values,
    paired_flip_counts,
)


class BinaryShieldStatisticalAnalysisTests(unittest.TestCase):
    def test_paired_flip_counts_and_metrics(self) -> None:
        frame = pd.DataFrame(
            {
                "sample_id": ["a", "b", "c", "d"],
                "target": ["malware", "malware", "benign", "benign"],
                "clean_prediction": ["malware", "benign", "benign", "malware"],
                "transformed_prediction": ["benign", "malware", "benign", "malware"],
            }
        )
        counts = paired_flip_counts(frame)
        self.assertEqual(counts["n"], 4)
        self.assertEqual(counts["clean_correct_to_transformed_incorrect"], 1)
        self.assertEqual(counts["clean_incorrect_to_transformed_correct"], 1)
        self.assertEqual(counts["total_prediction_flips"], 2)
        self.assertEqual(counts["total_label_correctness_flips"], 2)

        values = metric_values(frame)
        self.assertEqual(values["row_count"], 4.0)
        self.assertEqual(values["prediction_stability"], 0.5)
        self.assertEqual(values["attack_success_rate"], 0.5)

    def test_exact_mcnemar_pvalue_fallback_shape(self) -> None:
        self.assertEqual(exact_mcnemar_pvalue(0, 0), 1.0)
        self.assertAlmostEqual(exact_mcnemar_pvalue(1, 1), 1.0)
        self.assertLess(exact_mcnemar_pvalue(0, 10), 0.01)


if __name__ == "__main__":
    unittest.main()
