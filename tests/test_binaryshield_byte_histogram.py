from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from binaryshield.evaluation.metrics import classification_summary
from binaryshield.models.byte_histogram import CalibratedByteHistogramDetector, ByteHistogramLogisticDetector


class CalibratedByteHistogramTests(unittest.TestCase):
    def test_calibration_improves_imbalanced_macro_f1_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            train_paths = [
                _write_bytes(root / "train_benign.bin", bytes([0]) * 100),
                _write_bytes(root / "train_malware.bin", bytes([10]) * 100),
            ]
            train_labels = ["benign", "malware"]
            val_paths = [
                _write_bytes(root / "val_benign.bin", bytes([0]) * 60 + bytes([10]) * 40),
                _write_bytes(root / "val_malware_1.bin", bytes([0]) * 52 + bytes([10]) * 48),
                _write_bytes(root / "val_malware_2.bin", bytes([0]) * 30 + bytes([10]) * 70),
            ]
            val_labels = ["benign", "malware", "malware"]

            detector = CalibratedByteHistogramDetector.create()
            detector.fit(train_paths, train_labels)
            before = classification_summary(
                val_labels,
                detector.predict(val_paths),
                ["benign", "malware"],
            )
            detector.calibrate(val_paths, val_labels)
            after = classification_summary(
                val_labels,
                detector.predict(val_paths),
                ["benign", "malware"],
            )

            self.assertLess(before["macro_f1"], after["macro_f1"])
            self.assertEqual(after["macro_f1"], 1.0)
            self.assertEqual(detector.validation_macro_f1, 1.0)

            model_path = root / "detector.json"
            detector.save(model_path)
            loaded = CalibratedByteHistogramDetector.load(model_path)
            self.assertEqual(detector.predict(val_paths), loaded.predict(val_paths))

    def test_logistic_detector_learns_binary_histogram_boundary_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            train_paths = [
                _write_bytes(root / "train_benign_1.bin", bytes([0]) * 90 + bytes([10]) * 10),
                _write_bytes(root / "train_benign_2.bin", bytes([0]) * 80 + bytes([10]) * 20),
                _write_bytes(root / "train_malware_1.bin", bytes([0]) * 10 + bytes([10]) * 90),
                _write_bytes(root / "train_malware_2.bin", bytes([0]) * 20 + bytes([10]) * 80),
            ]
            train_labels = ["benign", "benign", "malware", "malware"]
            val_paths = [
                _write_bytes(root / "val_benign.bin", bytes([0]) * 70 + bytes([10]) * 30),
                _write_bytes(root / "val_malware.bin", bytes([0]) * 30 + bytes([10]) * 70),
            ]
            val_labels = ["benign", "malware"]

            detector = ByteHistogramLogisticDetector.create(epochs=100, learning_rate=0.1)
            detector.fit(train_paths, train_labels).calibrate(val_paths, val_labels)
            predictions = detector.predict(val_paths)

            self.assertEqual(predictions, val_labels)
            self.assertEqual(detector.validation_macro_f1, 1.0)

            model_path = root / "logistic_detector.json"
            detector.save(model_path)
            loaded = ByteHistogramLogisticDetector.load(model_path)
            self.assertEqual(detector.predict(val_paths), loaded.predict(val_paths))


def _write_bytes(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


if __name__ == "__main__":
    unittest.main()
