from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class EvidenceTableTests(unittest.TestCase):
    def test_builds_sanitized_tables_from_prediction_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            append_predictions = root / "append_predictions.csv"
            slack_predictions = root / "slack_predictions.csv"
            _write_predictions(append_predictions)
            _write_predictions(slack_predictions)
            append_metrics = root / "append_metrics.json"
            slack_metrics = root / "slack_metrics.json"
            append_metrics.write_text(json.dumps({"transformed_macro_f1": 1.0}), encoding="utf-8")
            slack_metrics.write_text(json.dumps({"transformed_macro_f1": 1.0}), encoding="utf-8")
            append_validation = root / "append_validation.json"
            slack_validation = root / "slack_validation.json"
            validation_payload = {
                "validation_json_count": 2,
                "expected_count": 2,
                "validation_json_generation_rate": 1.0,
                "overall": {
                    "pe_parse_transformed_rate": 1.0,
                    "entry_point_unchanged_rate": 1.0,
                    "executable_sections_unchanged_rate": 1.0,
                    "level_2_or_higher_rate": 1.0,
                },
            }
            append_validation.write_text(json.dumps(validation_payload), encoding="utf-8")
            slack_validation.write_text(json.dumps(validation_payload), encoding="utf-8")
            multi = root / "multi.json"
            multi.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "detector": "byte_histogram_logistic",
                                "transformation": "append_overlay",
                                "clean_macro_f1": 1.0,
                                "transformed_macro_f1": 1.0,
                                "robust_min_macro_f1": 1.0,
                                "prediction_stability": 1.0,
                                "attack_success_rate": 0.0,
                                "transformed_worst_class_f1": 1.0,
                                "evaluated_samples": 2,
                            }
                        ],
                        "candidate_comparison": {
                            "metric_results": [
                                {
                                    "metric": "robust_min_macro_f1",
                                    "status": "BEATS_BASELINE",
                                    "candidate": 1.0,
                                    "strongest_baseline": 0.5,
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            output = root / "out"
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_build_evidence_tables.py",
                    "--append-predictions",
                    str(append_predictions),
                    "--slack-predictions",
                    str(slack_predictions),
                    "--append-metrics",
                    str(append_metrics),
                    "--slack-metrics",
                    str(slack_metrics),
                    "--append-validation",
                    str(append_validation),
                    "--slack-validation",
                    str(slack_validation),
                    "--multi-detector-summary",
                    str(multi),
                    "--output-dir",
                    str(output),
                ],
                check=True,
            )

            payload = json.loads((output / "binaryshield_sanitized_evidence_tables.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["append_confusion_matrix"][0]["support"], 1)
            self.assertEqual(payload["prediction_stability"][0]["prediction_stability"], 1.0)
            self.assertTrue((output / "accepted_vs_baseline_deltas.csv").exists())


def _write_predictions(path: Path) -> None:
    rows = [
        {
            "sample_id": "a",
            "target": "benign",
            "label": "benign",
            "family": "",
            "clean_prediction": "benign",
            "transformed_prediction": "benign",
            "prediction_stable": "True",
            "attack_success": "False",
            "error": "",
        },
        {
            "sample_id": "b",
            "target": "malware",
            "label": "malware",
            "family": "",
            "clean_prediction": "malware",
            "transformed_prediction": "malware",
            "prediction_stable": "True",
            "attack_success": "False",
            "error": "",
        },
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    unittest.main()
