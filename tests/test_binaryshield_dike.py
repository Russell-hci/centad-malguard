from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from binaryshield.dike import build_dike_manifest_rows
from binaryshield.fixtures import write_minimal_pe_fixture


class BinaryShieldDikeTests(unittest.TestCase):
    def test_dike_builder_filters_non_pe_and_extracts_binary_and_family_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            files = root / "files"
            labels = root / "labels"
            benign = write_minimal_pe_fixture(files / "benign" / ("a" * 64 + ".exe"))
            malware = write_minimal_pe_fixture(files / "malware" / ("b" * 64 + ".exe"))
            bad = files / "malware" / ("c" * 64 + ".ole")
            bad.parent.mkdir(parents=True, exist_ok=True)
            bad.write_text("not a pe", encoding="utf-8")
            labels.mkdir()
            _write_label_csv(labels / "benign.csv", [(benign.stem, 0.0, {"generic": 0.0, "trojan": 0.0})])
            _write_label_csv(
                labels / "malware.csv",
                [
                    (malware.stem, 0.9, {"generic": 0.2, "trojan": 0.7}),
                    (bad.stem, 0.9, {"generic": 0.8, "trojan": 0.1}),
                ],
            )

            rows, summary = build_dike_manifest_rows(
                [labels / "benign.csv", labels / "malware.csv"],
                files,
                malice_threshold=0.4,
                min_family_score=0.05,
                require_pe_parse=True,
                relative_to=files,
            )

        self.assertEqual(len(rows), 2)
        by_label = {row.label: row for row in rows}
        self.assertEqual(by_label["benign"].family, "benign")
        self.assertEqual(by_label["malware"].family, "trojan")
        self.assertEqual(summary["skipped"]["pe_parse_failed"], 1)

    def test_dike_cli_writes_manifest_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            files = root / "files"
            labels = root / "labels"
            sample = write_minimal_pe_fixture(files / "benign" / ("d" * 64 + ".exe"))
            labels.mkdir()
            _write_label_csv(labels / "benign.csv", [(sample.stem, 0.0, {"generic": 0.0})])
            _write_label_csv(labels / "malware.csv", [])
            output = root / "manifest.csv"
            summary = root / "summary.json"

            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_build_dike_manifest.py",
                    "--dike-root",
                    str(root),
                    "--output",
                    str(output),
                    "--summary-output",
                    str(summary),
                ],
                check=True,
            )

            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            payload = json.loads(summary.read_text(encoding="utf-8"))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "benign")
        self.assertEqual(payload["manifest_rows"], 1)


def _write_label_csv(path: Path, rows: list[tuple[str, float, dict[str, float]]]) -> None:
    fieldnames = [
        "type",
        "hash",
        "malice",
        "generic",
        "trojan",
        "ransomware",
        "worm",
        "backdoor",
        "spyware",
        "rootkit",
        "encrypter",
        "downloader",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for sha, malice, scores in rows:
            row = {name: 0 for name in fieldnames}
            row["hash"] = sha
            row["malice"] = malice
            for key, value in scores.items():
                row[key] = value
            writer.writerow(row)


if __name__ == "__main__":
    unittest.main()
