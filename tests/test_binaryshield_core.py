from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from binaryshield.byte_loader import chunk_bytes, load_bytes
from binaryshield.fixtures import write_minimal_pe_fixture
from binaryshield.mutation_regions import find_mutation_regions
from binaryshield.pe_features import parse_pe
from binaryshield.robustness_card import card_from_validation
from binaryshield.transformations import append_overlay, mutate_slack_space
from binaryshield.validation import validate_transformation


class BinaryShieldCoreTests(unittest.TestCase):
    def test_parse_regions_transform_validate_and_card(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            original = root / "minimal.exe"
            write_minimal_pe_fixture(original)

            record = parse_pe(original)
            self.assertEqual(record.number_of_sections, 2)
            self.assertEqual(record.address_of_entry_point, 0x1000)

            byte_result = load_bytes(original, max_bytes=128)
            self.assertTrue(byte_result.truncated)
            self.assertEqual(len(chunk_bytes(byte_result.byte_values, chunk_size=64)), 2)

            regions = find_mutation_regions(record)
            self.assertTrue(any(region.region_type == "append_overlay" for region in regions))
            self.assertTrue(any(region.region_type == "section_slack" and region.validation_level == 2 for region in regions))

            appended = append_overlay(original, root / "appended.exe", payload_size=64, seed=1)
            appended_validation = validate_transformation(appended, root / "appended_validation.json")
            self.assertTrue(appended_validation.allowed_for_evaluation)
            self.assertEqual(appended_validation.validation_level, 2)
            self.assertTrue((root / "appended_validation.json").exists())

            slack = mutate_slack_space(original, root / "slack.exe", max_bytes=32, seed=2)
            slack_validation = validate_transformation(slack)
            self.assertTrue(slack_validation.allowed_for_evaluation)
            self.assertEqual(slack_validation.validation_level, 2)

            card = card_from_validation(
                sample_id="fixture",
                validation=appended_validation,
                detector_name="unit_test_detector",
                clean_prediction="malware",
                transformed_prediction="malware",
                clean_confidence=0.91,
                transformed_confidence=0.88,
            )
            self.assertEqual(card.verdict, "detector_stable")
            self.assertIn("Claim Boundary", card.to_markdown())

    def test_append_overlay_rejects_truncated_section_raw_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            original = root / "minimal.exe"
            truncated = root / "truncated.exe"
            write_minimal_pe_fixture(original)
            data = original.read_bytes()
            truncated.write_bytes(data[:-1])

            regions = find_mutation_regions(truncated)
            append_region = next(region for region in regions if region.region_type == "append_overlay")
            self.assertEqual(append_region.validation_level, 1)
            self.assertIn("file ends inside declared section raw data", append_region.reason)

            with self.assertRaisesRegex(ValueError, "append overlay is not Level-2 safe"):
                append_overlay(truncated, root / "unsafe_append.exe", payload_size=64, seed=1)

    def test_executable_section_validation_handles_duplicate_section_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            original = root / "duplicate_names.exe"
            write_minimal_pe_fixture(original)
            data = bytearray(original.read_bytes())
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            coff = pe_offset + 4
            optional_header_size = int.from_bytes(data[coff + 16 : coff + 18], "little")
            section_table = coff + 20 + optional_header_size
            second_section = section_table + 40
            data[second_section : second_section + 8] = b".text\x00\x00\x00"
            original.write_bytes(data)

            appended = append_overlay(original, root / "appended_duplicate_names.exe", payload_size=64, seed=3)
            validation = validate_transformation(appended)
            self.assertTrue(validation.executable_sections_unchanged)
            self.assertEqual(validation.validation_level, 2)


if __name__ == "__main__":
    unittest.main()
