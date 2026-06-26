from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from binaryshield.datasets import BinarySample
from binaryshield.evaluation.evaluate_transformations import (
    TransformationEvaluationConfig,
    evaluate_detector_under_transformation,
)
from binaryshield.evaluation.metrics import classification_summary, robustness_summary
from binaryshield.fixtures import write_minimal_pe_fixture


class StableDetector:
    detector_name = "stable_detector"

    def predict(self, paths: list[str | Path]) -> list[str]:
        return ["benign" for _ in paths]


class MalwareDetector:
    detector_name = "malware_detector"

    def predict(self, paths: list[str | Path]) -> list[str]:
        return ["malware" for _ in paths]


class BinaryShieldEvaluationTests(unittest.TestCase):
    def test_classification_and_robustness_metrics(self) -> None:
        summary = classification_summary(["a", "a", "b"], ["a", "b", "b"])
        self.assertAlmostEqual(summary["accuracy"], 2 / 3)
        self.assertIn("macro_f1", summary)
        robust = robustness_summary(["a", "a"], ["a", "b"], ["a", "a"])
        self.assertAlmostEqual(robust["prediction_stability"], 0.5)
        self.assertAlmostEqual(robust["attack_success_rate"], 0.5)

    def test_evaluate_detector_under_append_transformation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample_path = root / "sample.exe"
            write_minimal_pe_fixture(sample_path)
            sample = BinarySample(sample_id="sample", path=sample_path, label="benign", family="benign", split="test")
            output_dir = root / "eval"
            metrics = evaluate_detector_under_transformation(
                StableDetector(),
                [sample],
                TransformationEvaluationConfig(output_dir=output_dir, transformation="append_overlay", payload_size=32),
            )
            self.assertEqual(metrics["evaluated_samples"], 1.0)
            self.assertEqual(metrics["prediction_stability"], 1.0)
            self.assertTrue((output_dir / "validation" / "append_overlay" / "sample.json").exists())
            self.assertTrue((output_dir / "cards" / "append_overlay" / "sample.md").exists())

    def test_label_target_does_not_use_family_when_family_is_present(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample_path = root / "sample.exe"
            write_minimal_pe_fixture(sample_path)
            sample = BinarySample(sample_id="sample", path=sample_path, label="malware", family="trojan", split="test")
            metrics = evaluate_detector_under_transformation(
                MalwareDetector(),
                [sample],
                TransformationEvaluationConfig(
                    output_dir=root / "label_eval",
                    transformation="append_overlay",
                    payload_size=32,
                    target="label",
                ),
            )
            self.assertEqual(metrics["clean_accuracy"], 1.0)
            self.assertEqual(metrics["transformed_accuracy"], 1.0)


if __name__ == "__main__":
    unittest.main()
