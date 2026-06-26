from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

from binaryshield.sorel import maybe_decompress_sorel_binary


class BinaryShieldSORELTests(unittest.TestCase):
    def test_maybe_decompress_sorel_binary_handles_zlib_and_plain_pe(self) -> None:
        plain = b"MZ" + b"\x00" * 16
        compressed = zlib.compress(plain)

        decoded, was_compressed = maybe_decompress_sorel_binary(compressed)
        self.assertTrue(was_compressed)
        self.assertEqual(decoded, plain)

        decoded_plain, was_plain_compressed = maybe_decompress_sorel_binary(plain)
        self.assertFalse(was_plain_compressed)
        self.assertEqual(decoded_plain, plain)

    def test_prepare_sorel_workspace_creates_external_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "sorel"
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_prepare_sorel_workspace.py",
                    "--workspace",
                    str(workspace),
                    "--allow-low-space",
                ],
                check=True,
            )
            metadata = json.loads((workspace / "binaryshield_sorel_workspace.json").read_text(encoding="utf-8"))

            self.assertEqual(metadata["workspace"], str(workspace.resolve()))
            self.assertTrue((workspace / "binaries").exists())
            self.assertTrue((workspace / "compressed_binaries").exists())
            self.assertIn("sorel_binary_prefix", metadata)
            self.assertIn("Do not claim full behavior preservation", " ".join(metadata["safety_rules"]))

    def test_sorel_readiness_marks_empty_raw_track_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            workspace = root / "sorel"
            output_dir = root / "report"
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_prepare_sorel_workspace.py",
                    "--workspace",
                    str(workspace),
                    "--allow-low-space",
                ],
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_sorel_readiness.py",
                    "--workspace",
                    str(workspace),
                    "--output-dir",
                    str(output_dir),
                    "--min-free-gb",
                    "0",
                ],
                check=True,
            )
            report = json.loads((output_dir / "sorel_readiness.json").read_text(encoding="utf-8"))

            self.assertFalse(report["tracks"]["raw_disarmed_pe_track_ready"])
            self.assertIn("directory is empty", report["tracks"]["raw_disarmed_pe_blocker"])
            self.assertIsNone(report["commands"]["raw_multidetector_pipeline"])
            self.assertIn("not full behavior preservation", report["claim_boundary"])


if __name__ == "__main__":
    unittest.main()
