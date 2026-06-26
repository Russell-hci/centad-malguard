from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from binaryshield.evaluation.feature_record_summary import (
    build_feature_record_gate_report,
    write_feature_record_gate_report,
)


class FeatureRecordSummaryTests(unittest.TestCase):
    def test_feature_record_gate_report_passes_clean_track_but_bounds_raw_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            candidate = root / "candidate.json"
            baseline = root / "baseline.json"
            summary = root / "summary.json"
            candidate.write_text(
                json.dumps(
                    {
                        "accuracy": 0.97,
                        "macro_f1": 0.96,
                        "worst_class_f1": 0.95,
                        "benign_f1": 0.94,
                        "malware_f1": 0.98,
                    }
                ),
                encoding="utf-8",
            )
            baseline.write_text(
                json.dumps(
                    {
                        "accuracy": 0.72,
                        "macro_f1": 0.71,
                        "worst_class_f1": 0.70,
                        "benign_f1": 0.73,
                        "malware_f1": 0.69,
                    }
                ),
                encoding="utf-8",
            )
            summary.write_text(json.dumps({"scope": "feature-vector only"}), encoding="utf-8")

            report = build_feature_record_gate_report(
                candidate_metrics_path=candidate,
                baseline_metrics_path=baseline,
                candidate_summary_path=summary,
            )

            self.assertEqual(report["overall_status"], "PARTIAL_PASS")
            statuses = {gate["name"]: gate["status"] for gate in report["gates"]}
            self.assertEqual(statuses["Candidate clean accuracy"], "PASS")
            self.assertEqual(statuses["Candidate beats feature baseline"], "PASS")
            self.assertEqual(statuses["Raw PE transformation robustness"], "NOT_APPLICABLE")
            self.assertEqual(statuses["Behavior preservation"], "NOT_VALIDATED")
            self.assertIn("does not validate raw PE transformation", report["claim_boundary"])

            output_dir = root / "out"
            write_feature_record_gate_report(report, output_dir)
            self.assertTrue((output_dir / "feature_record_gate_report.json").exists())
            self.assertTrue((output_dir / "feature_record_gate_report.md").exists())
            self.assertTrue((output_dir / "feature_record_gate_rows.csv").exists())
            self.assertIn("BODMAS Feature-Record Gate Report", (output_dir / "feature_record_gate_report.md").read_text())


if __name__ == "__main__":
    unittest.main()
