from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from binaryshield.evaluation.acceptance import build_acceptance_report


class BinaryShieldAcceptanceTests(unittest.TestCase):
    def test_acceptance_report_marks_missing_real_evidence_not_validated(self) -> None:
        report = build_acceptance_report()
        self.assertEqual(report.overall_status, "NOT_VALIDATED")
        self.assertTrue(any(gate.status == "NOT_VALIDATED" for gate in report.gates))

    def test_acceptance_report_passes_with_sufficient_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            validation = root / "validation.json"
            append = root / "append.json"
            slack = root / "slack.json"
            append_validation = root / "append_validation.json"
            slack_validation = root / "slack_validation.json"
            append_cards = root / "append_cards.json"
            slack_cards = root / "slack_cards.json"
            transfer = root / "transfer.json"
            multi = root / "multi.json"
            validation.write_text(
                json.dumps({"pe_parse_success_rate": 0.99, "feature_extraction_success_rate": 0.98}),
                encoding="utf-8",
            )
            append.write_text(
                json.dumps(
                    {
                        "prediction_stability": 0.90,
                        "transformed_macro_f1": 0.86,
                        "attack_success_rate": 0.20,
                    }
                ),
                encoding="utf-8",
            )
            slack.write_text(json.dumps({"transformed_macro_f1": 0.75}), encoding="utf-8")
            validation_payload = {
                "validation_json_generation_rate": 1.0,
                "overall": {
                    "pe_parse_transformed_rate": 1.0,
                    "entry_point_unchanged_rate": 1.0,
                    "executable_sections_unchanged_rate": 1.0,
                },
            }
            append_validation.write_text(json.dumps(validation_payload), encoding="utf-8")
            slack_validation.write_text(json.dumps(validation_payload), encoding="utf-8")
            card_payload = {"card_generation_rate": 1.0, "card_count": 2, "expected_count": 2}
            append_cards.write_text(json.dumps(card_payload), encoding="utf-8")
            slack_cards.write_text(json.dumps(card_payload), encoding="utf-8")
            transfer.write_text(json.dumps({"append_overlay": {"a": {}, "b": {}}}), encoding="utf-8")
            multi.write_text(
                json.dumps(
                    {
                        "detector_count": 2,
                        "candidate_comparison": {
                            "status": "PASS",
                            "metrics_beaten": 2,
                        },
                    }
                ),
                encoding="utf-8",
            )
            report = build_acceptance_report(
                validation,
                append,
                slack,
                append_validation,
                slack_validation,
                append_cards,
                slack_cards,
                transfer,
                multi,
            )
            self.assertEqual(report.overall_status, "PASS")
            self.assertIn("BinaryShield Acceptance Report", report.to_markdown())


if __name__ == "__main__":
    unittest.main()
