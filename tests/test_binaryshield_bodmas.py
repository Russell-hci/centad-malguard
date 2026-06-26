from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from binaryshield.bodmas import build_raw_bodmas_matches, inspect_bodmas_npz, load_bodmas_metadata
from binaryshield.fixtures import write_minimal_pe_fixture


class BinaryShieldBODMASTests(unittest.TestCase):
    def test_metadata_loader_accepts_headerless_rows_and_raw_sha_matching(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample = write_minimal_pe_fixture(root / "sample.exe")
            sha = _sha256(sample)
            metadata = root / "metadata.csv"
            metadata.write_text(f"{sha},2020-01-01,family_a\n", encoding="utf-8")
            renamed = root / "raw" / sha
            renamed.parent.mkdir()
            renamed.write_bytes(sample.read_bytes())

            rows = load_bodmas_metadata(metadata)
            matches = build_raw_bodmas_matches(rows, renamed.parent)

        self.assertEqual(rows[0].family, "family_a")
        self.assertEqual(rows[0].label, "malware")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].sha256, sha)

    def test_bodmas_manifest_builder_writes_sanitized_feature_and_raw_manifests(self) -> None:
        try:
            import numpy as np
        except ImportError:
            self.skipTest("numpy unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            raw_root = root / "raw"
            raw_root.mkdir()
            sample = write_minimal_pe_fixture(root / "fixture.exe")
            sha = _sha256(sample)
            (raw_root / sha).write_bytes(sample.read_bytes())
            metadata = root / "metadata.csv"
            metadata.write_text(f"sha256,first_seen,family\n{sha},2020-01-01,family_a\n", encoding="utf-8")
            features = root / "bodmas.npz"
            np.savez(features, X=np.asarray([[1.0, 2.0, 3.0]], dtype=float), y=np.asarray([1], dtype=int))
            raw_manifest = root / "raw_manifest.csv"
            feature_manifest = root / "feature_manifest.csv"
            summary = root / "summary.json"

            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_build_bodmas_manifest.py",
                    "--metadata",
                    str(metadata),
                    "--raw-binaries-dir",
                    str(raw_root),
                    "--features-npz",
                    str(features),
                    "--raw-output",
                    str(raw_manifest),
                    "--feature-output",
                    str(feature_manifest),
                    "--summary-output",
                    str(summary),
                    "--relative-to",
                    str(raw_root),
                    "--require-pe-parse",
                ],
                check=True,
            )

            with raw_manifest.open(encoding="utf-8") as handle:
                raw_rows = list(csv.DictReader(handle))
            with feature_manifest.open(encoding="utf-8") as handle:
                feature_rows = list(csv.DictReader(handle))
            summary_payload = json.loads(summary.read_text(encoding="utf-8"))

        self.assertEqual(len(raw_rows), 1)
        self.assertEqual(raw_rows[0]["path"], sha)
        self.assertEqual(len(feature_rows), 1)
        self.assertEqual(feature_rows[0]["record_index"], "0")
        self.assertEqual(summary_payload["raw_matches"], 1)
        self.assertEqual(summary_payload["feature_rows_written"], 1)

    def test_npz_inspection_is_git_safe(self) -> None:
        try:
            import numpy as np
        except ImportError:
            self.skipTest("numpy unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            npz = Path(temp_dir) / "bodmas.npz"
            np.savez(npz, X=np.zeros((2, 4), dtype=float), y=np.asarray([0, 1], dtype=int))
            summary = inspect_bodmas_npz(npz)
        self.assertEqual(summary["feature_rows"], 2)
        self.assertEqual(summary["feature_dim"], 4)
        self.assertEqual(summary["label_counts"]["0"], 1)


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
