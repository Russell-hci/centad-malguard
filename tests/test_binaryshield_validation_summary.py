from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from binaryshield.evaluation.validation_summary import summarize_validation_records, to_markdown


class BinaryShieldValidationSummaryTests(unittest.TestCase):
    def test_validation_summary_computes_measurable_goal_rates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            validation = root / "validation" / "append_overlay"
            validation.mkdir(parents=True)
            (validation / "a.json").write_text(
                json.dumps(
                    {
                        "transformation_type": "append_overlay",
                        "pe_parse_original": True,
                        "pe_parse_transformed": True,
                        "entry_point_unchanged": True,
                        "section_count_valid": True,
                        "executable_sections_unchanged": True,
                        "allowed_for_evaluation": True,
                        "validation_level": 2,
                    }
                ),
                encoding="utf-8",
            )
            summary = summarize_validation_records(root / "validation", expected_count=1)
        self.assertEqual(summary["validation_json_generation_rate"], 1.0)
        self.assertEqual(summary["overall"]["pe_parse_transformed_rate"], 1.0)
        self.assertEqual(summary["overall"]["entry_point_unchanged_rate"], 1.0)
        self.assertIn("Transformation Validation Summary", to_markdown(summary))

    def test_validation_summary_can_use_existing_records_for_optional_transforms(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            validation = root / "validation" / "section_slack"
            validation.mkdir(parents=True)
            (validation / "a.json").write_text(
                json.dumps(
                    {
                        "transformation_type": "section_slack",
                        "pe_parse_original": True,
                        "pe_parse_transformed": True,
                        "entry_point_unchanged": True,
                        "section_count_valid": True,
                        "executable_sections_unchanged": True,
                        "allowed_for_evaluation": True,
                        "validation_level": 2,
                    }
                ),
                encoding="utf-8",
            )
            existing_count = len(list(validation.rglob("*.json")))
            summary = summarize_validation_records(validation, expected_count=existing_count)
        self.assertEqual(summary["expected_count"], 1)
        self.assertEqual(summary["validation_json_generation_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
