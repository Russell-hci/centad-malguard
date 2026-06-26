from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from binaryshield.artifact_export import export_sanitized_artifacts


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BinaryShieldArtifactExportTests(unittest.TestCase):
    def test_export_copies_safe_artifacts_and_blocks_unsafe_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "external_run"
            destination = root / "sanitized"
            source.mkdir()
            (source / "metrics.json").write_text(json.dumps({"accuracy": 0.9}), encoding="utf-8")
            (source / "card.md").write_text("# Robustness Card\n", encoding="utf-8")
            (source / "predictions.csv").write_text("sample_id,prediction\nx,malware\n", encoding="utf-8")
            (source / "malware.bin").write_bytes(b"MZ")
            (source / "model.joblib").write_bytes(b"model")
            (source / "pe_feature_detector.json").write_text(json.dumps({"centroids": {}}), encoding="utf-8")
            (source / "secret.txt").write_text("access_token = 'abcdefghijklmnopqrstuvwxyz123456'", encoding="utf-8")

            summary = export_sanitized_artifacts(source, destination)

            copied = {record["relative_path"] for record in summary["records"] if record["status"] == "COPIED"}
            blocked = {record["relative_path"] for record in summary["records"] if record["status"] == "BLOCKED"}
            self.assertEqual(summary["status"], "REVIEW_REQUIRED")
            self.assertEqual(copied, {"card.md", "metrics.json", "predictions.csv"})
            self.assertEqual(blocked, {"malware.bin", "model.joblib", "pe_feature_detector.json", "secret.txt"})
            self.assertTrue((destination / "sanitized_artifact_export_summary.json").exists())
            self.assertFalse((destination / "malware.bin").exists())

    def test_cli_refuses_source_inside_repo_by_default(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as source_dir, tempfile.TemporaryDirectory() as output_dir:
            source = Path(source_dir)
            (source / "metrics.json").write_text("{}", encoding="utf-8")
            destination = Path(output_dir) / "dest"
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_export_sanitized_artifacts.py",
                    "--source-dir",
                    str(source),
                    "--destination-dir",
                    str(destination),
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source-dir is inside the repository", result.stderr)

    def test_cli_allows_fixture_source_inside_repo_when_explicit(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as source_dir:
            source = Path(source_dir)
            destination = PROJECT_ROOT / "tmp" / "binaryshield_artifact_export_test"
            if destination.exists():
                for path in sorted(destination.rglob("*"), reverse=True):
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
            source.joinpath("metrics.json").write_text("{}", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_export_sanitized_artifacts.py",
                    "--source-dir",
                    str(source),
                    "--destination-dir",
                    str(destination),
                    "--allow-source-inside-repo",
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((destination / "metrics.json").exists())


if __name__ == "__main__":
    unittest.main()
