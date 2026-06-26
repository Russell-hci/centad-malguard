from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from binaryshield.fixtures import write_minimal_pe_fixture
from binaryshield.metadata_manifest import build_metadata_manifest_rows


class BinaryShieldMetadataManifestTests(unittest.TestCase):
    def test_path_based_metadata_manifest_preserves_labels_family_and_split(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binaries = root / "binaries"
            sample = write_minimal_pe_fixture(binaries / "malware" / "family_a" / "sample.exe")
            metadata = root / "metadata.csv"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text(
                "rel_path,verdict,family,split,sample_name\n"
                f"{sample.relative_to(binaries)},malware,family_a,test,sample_a\n",
                encoding="utf-8",
            )

            rows, summary = build_metadata_manifest_rows(
                metadata,
                binaries,
                path_column="rel_path",
                label_column="verdict",
                family_column="family",
                split_column="split",
                sample_id_column="sample_name",
                require_pe_parse=True,
                relative_to=binaries,
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].sample_id, "sample_a")
        self.assertEqual(rows[0].path, Path("malware/family_a/sample.exe"))
        self.assertEqual(rows[0].label, "malware")
        self.assertEqual(rows[0].family, "family_a")
        self.assertEqual(rows[0].split, "test")
        self.assertEqual(summary["manifest_rows"], 1)

    def test_sha_based_cli_manifest_skips_non_pe_and_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binaries = root / "binaries"
            binaries.mkdir()
            sample = write_minimal_pe_fixture(root / "sample.exe")
            sample_sha = _sha256(sample)
            (binaries / sample_sha).write_bytes(sample.read_bytes())
            bad_sha = "0" * 64
            (binaries / bad_sha).write_text("not a pe", encoding="utf-8")
            metadata = root / "metadata.csv"
            metadata.write_text(
                "sha256,label,family\n"
                f"{sample_sha},benign,fixture\n"
                f"{bad_sha},malware,bad_fixture\n",
                encoding="utf-8",
            )
            output = root / "manifest.csv"
            summary = root / "summary.json"

            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_build_metadata_manifest.py",
                    "--metadata",
                    str(metadata),
                    "--binaries-dir",
                    str(binaries),
                    "--output",
                    str(output),
                    "--summary-output",
                    str(summary),
                    "--sha256-column",
                    "sha256",
                    "--label-column",
                    "label",
                    "--family-column",
                    "family",
                    "--require-pe-parse",
                ],
                check=True,
            )

            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            payload = json.loads(summary.read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sha256"], sample_sha)
        self.assertEqual(rows[0]["label"], "benign")
        self.assertEqual(payload["skipped"]["pe_parse_failed"], 1)
        self.assertEqual(payload["label_counts"]["benign"], 1)


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
