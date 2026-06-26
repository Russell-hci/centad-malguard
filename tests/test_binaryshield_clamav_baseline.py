from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

if importlib.util.find_spec("pandas") is None or importlib.util.find_spec("sklearn") is None:
    raise unittest.SkipTest("pandas and scikit-learn are required for ClamAV baseline tests; install requirements.txt to run them")

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "binaryshield_clamav_baseline.py"
spec = importlib.util.spec_from_file_location("binaryshield_clamav_baseline", SCRIPT)
clamav = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(clamav)


class BinaryShieldClamAVBaselineTests(unittest.TestCase):
    def test_parse_clamscan_output(self) -> None:
        self.assertEqual(clamav.parse_clamscan_output("/tmp/a: Eicar-Test-Signature FOUND\n"), "malware")
        self.assertEqual(clamav.parse_clamscan_output("/tmp/a: OK\n"), "benign")
        self.assertEqual(clamav.parse_clamscan_output("/tmp/a: Access denied ERROR\n"), "error")
        self.assertEqual(clamav.parse_clamscan_output("unexpected output"), "error")

    def test_metrics_treat_errors_as_coverage_failures(self) -> None:
        rows = [
            {"sample_id": "a", "label": "malware", "prediction": "malware"},
            {"sample_id": "b", "label": "benign", "prediction": "error"},
        ]
        metrics = clamav.metrics(rows)
        self.assertEqual(metrics["total"], 2)
        self.assertEqual(metrics["scanned"], 1)
        self.assertEqual(metrics["errors_or_timeouts"], 1)
        self.assertEqual(metrics["coverage"], 0.5)
        self.assertEqual(metrics["malware_recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
