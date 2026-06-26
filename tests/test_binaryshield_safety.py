from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from binaryshield.datasets import BinarySample
from binaryshield.safety import assert_safe_transformation_output, is_relative_to


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BinaryShieldSafetyTests(unittest.TestCase):
    def test_external_samples_cannot_write_transformed_outputs_inside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = BinarySample(sample_id="external", path=Path(temp_dir) / "sample.exe", label="malware")
            with self.assertRaisesRegex(ValueError, "refusing to write transformed artifacts"):
                assert_safe_transformation_output(
                    samples=[sample],
                    output_dir=PROJECT_ROOT / "results" / "binaryshield" / "unsafe",
                    project_root=PROJECT_ROOT,
                )

    def test_repo_local_fixture_output_is_allowed(self) -> None:
        sample = BinarySample(
            sample_id="fixture",
            path=PROJECT_ROOT / "binaryshield_outputs" / "demo_dataset" / "alpha_0.bin",
            label="malware",
        )
        assert_safe_transformation_output(
            samples=[sample],
            output_dir=PROJECT_ROOT / "results" / "binaryshield" / "fixture",
            project_root=PROJECT_ROOT,
        )

    def test_readiness_script_reports_raw_blocker_and_feature_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "bodmas"
            (workspace / "metadata").mkdir(parents=True)
            (workspace / "features").mkdir()
            (workspace / "binaries").mkdir()
            (workspace / "metadata" / "bodmas_metadata.csv").write_text("sha256,first_seen,family\n", encoding="utf-8")
            (workspace / "features" / "bodmas.npz").write_bytes(b"placeholder")
            output_dir = Path(temp_dir) / "readiness"
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_realdata_readiness.py",
                    "--workspace",
                    str(workspace),
                    "--output-dir",
                    str(output_dir),
                    "--min-free-gb",
                    "0",
                ],
                cwd=PROJECT_ROOT,
                check=True,
            )
            report = json.loads((output_dir / "realdata_readiness.json").read_text(encoding="utf-8"))
        self.assertTrue(report["tracks"]["public_feature_vector_track_ready"])
        self.assertFalse(report["tracks"]["raw_pe_track_ready"])
        self.assertIn("raw binaries directory is empty", report["tracks"]["raw_pe_blocker"])
        self.assertFalse(is_relative_to(report["workspace"], PROJECT_ROOT))


if __name__ == "__main__":
    unittest.main()
