from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from binaryshield.datasets import BinarySample
from binaryshield.evaluation.transfer_attack import TransferAttackConfig, evaluate_transfer_attack
from binaryshield.fixtures import write_minimal_pe_fixture


class SizeSensitiveDetector:
    detector_name = "size_sensitive"

    def predict(self, paths: list[str | Path]) -> list[str]:
        return ["alpha" if Path(path).stat().st_size < 2000 else "beta" for path in paths]


class StableAlphaDetector:
    detector_name = "stable_alpha"

    def predict(self, paths: list[str | Path]) -> list[str]:
        return ["alpha" for _ in paths]


class BinaryShieldTransferAttackTests(unittest.TestCase):
    def test_transfer_attack_reuses_source_selected_transformed_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample_path = write_minimal_pe_fixture(root / "alpha.exe")
            sample = BinarySample(sample_id="alpha", path=sample_path, label="alpha", family="alpha", split="test")
            output_dir = root / "transfer_attack"
            matrix = evaluate_transfer_attack(
                SizeSensitiveDetector(),
                [StableAlphaDetector()],
                [sample],
                TransferAttackConfig(output_dir=output_dir, transformation="append_overlay", n=2, payload_size=1024),
            )

            self.assertIn("size_sensitive", matrix)
            self.assertIn("stable_alpha", matrix)
            self.assertEqual(matrix["size_sensitive"]["attack_success_rate"], 1.0)
            self.assertEqual(matrix["stable_alpha"]["prediction_stability"], 1.0)
            self.assertTrue((output_dir / "selected_transformations.csv").exists())
            self.assertTrue((output_dir / "transfer_attack_matrix.json").exists())
            self.assertTrue((output_dir / "cards" / "stable_alpha" / "append_overlay" / "alpha.md").exists())


if __name__ == "__main__":
    unittest.main()
