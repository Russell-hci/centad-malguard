from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from binaryshield.fixtures import write_minimal_pe_fixture


class PemmlManifestTests(unittest.TestCase):
    def test_balanced_subset_manifest_from_samples_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            samples_dir = root / "samples"
            samples_dir.mkdir()
            rows = []
            for label in ["malware", "malware", "benign", "benign"]:
                sample = samples_dir / f"{label}_{len(rows)}.exe"
                write_minimal_pe_fixture(sample)
                rows.append({"path": str(sample.relative_to(root)), "label": label})
            samples_csv = root / "samples.csv"
            with samples_csv.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["path", "label"])
                writer.writeheader()
                writer.writerows(rows)

            manifest = root / "manifest.csv"
            summary = root / "summary.json"
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_build_pemml_manifest.py",
                    "--samples-csv",
                    str(samples_csv),
                    "--dataset-root",
                    str(root),
                    "--output",
                    str(manifest),
                    "--summary-output",
                    str(summary),
                    "--mode",
                    "balanced-subset",
                    "--malware-count",
                    "1",
                    "--benign-count",
                    "1",
                    "--seed",
                    "7",
                ],
                check=True,
            )

            with manifest.open(encoding="utf-8", newline="") as handle:
                manifest_rows = list(csv.DictReader(handle))
            payload = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(len(manifest_rows), 2)
            self.assertEqual(payload["label_counts"], {"benign": 1, "malware": 1})
            self.assertEqual(sorted(row["label"] for row in manifest_rows), ["benign", "malware"])
            self.assertTrue(all(row["sha256"] for row in manifest_rows))

    def test_official_pemml_id_and_list_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            samples_dir = root / "samples"
            samples_dir.mkdir()
            rows = []
            for sample_id, label in [("101", "Blacklist"), ("102", "Whitelist")]:
                sample = samples_dir / sample_id
                write_minimal_pe_fixture(sample)
                rows.append({"id": sample_id, "sha256": "", "list": label, "filetype": "exe"})
            samples_csv = root / "samples.csv"
            with samples_csv.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["id", "sha256", "list", "filetype"])
                writer.writeheader()
                writer.writerows(rows)

            manifest = root / "manifest.csv"
            summary = root / "summary.json"
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_build_pemml_manifest.py",
                    "--samples-csv",
                    str(samples_csv),
                    "--dataset-root",
                    str(root),
                    "--output",
                    str(manifest),
                    "--summary-output",
                    str(summary),
                    "--mode",
                    "balanced-subset",
                    "--malware-count",
                    "1",
                    "--benign-count",
                    "1",
                    "--seed",
                    "7",
                ],
                check=True,
            )

            with manifest.open(encoding="utf-8", newline="") as handle:
                manifest_rows = list(csv.DictReader(handle))
            payload = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(len(manifest_rows), 2)
            self.assertEqual(payload["label_counts"], {"benign": 1, "malware": 1})
            self.assertEqual(sorted(row["path"] for row in manifest_rows), ["samples/101", "samples/102"])


if __name__ == "__main__":
    unittest.main()
