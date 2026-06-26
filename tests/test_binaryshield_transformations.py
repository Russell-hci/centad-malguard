from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from binaryshield.mutation_regions import MutationRegion
from binaryshield.transformations import mutate_slack_space


class BinaryShieldTransformationTests(unittest.TestCase):
    def test_mutate_slack_space_skips_out_of_file_regions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "sample.bin"
            output = root / "out.bin"
            source.write_bytes(b"A" * 16)

            fake_region = MutationRegion(
                region_type="section_slack",
                start=64,
                end=80,
                size=16,
                section_name=".reloc",
                validation_level=2,
                reason="declared slack past EOF",
            )

            with patch("binaryshield.transformations.find_mutation_regions", return_value=[fake_region]):
                with self.assertRaisesRegex(ValueError, "no suitable slack-space mutation region found"):
                    mutate_slack_space(source, output, max_bytes=8, seed=1)

            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
