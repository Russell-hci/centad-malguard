from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from binaryshield.evaluation.multi_detector_summary import build_multi_detector_summary


class BinaryShieldMultiDetectorSummaryTests(unittest.TestCase):
    def test_candidate_improvement_is_counted_across_robustness_metrics(self) -> None:
        matrix = {
            "append_overlay": {
                "baseline": {
                    "transformed_accuracy": 0.70,
                    "transformed_macro_f1": 0.60,
                    "robust_min_macro_f1": 0.60,
                    "prediction_stability": 0.75,
                    "attack_success_rate": 0.30,
                    "transformed_worst_class_f1": 0.20,
                    "transformed_classes_below_f1_050": 2.0,
                    "transformed_classes_below_f1_080": 4.0,
                },
                "binaryshield": {
                    "transformed_accuracy": 0.82,
                    "transformed_macro_f1": 0.74,
                    "robust_min_macro_f1": 0.74,
                    "prediction_stability": 0.91,
                    "attack_success_rate": 0.10,
                    "transformed_worst_class_f1": 0.33,
                    "transformed_classes_below_f1_050": 1.0,
                    "transformed_classes_below_f1_080": 3.0,
                },
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "transfer.json"
            path.write_text(json.dumps(matrix), encoding="utf-8")
            summary = build_multi_detector_summary(
                path,
                candidate_detector="binaryshield",
                baseline_detectors=["baseline"],
            )
        self.assertEqual(summary["detector_count"], 2)
        self.assertEqual(summary["candidate_comparison"]["status"], "PASS")
        self.assertGreaterEqual(summary["candidate_comparison"]["metrics_beaten"], 2)


if __name__ == "__main__":
    unittest.main()
