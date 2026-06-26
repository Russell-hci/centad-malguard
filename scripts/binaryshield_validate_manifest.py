from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import load_manifest
from binaryshield.mutation_regions import find_mutation_regions
from binaryshield.pe_features import PEParseError, parse_pe


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run BinaryShield parse/feature validation over a manifest.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/binaryshield/manifest_validation"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    samples = load_manifest(args.manifest, args.root_dir)
    rows: list[dict[str, object]] = []
    parse_success = 0
    feature_success = 0
    append_available = 0
    slack_available = 0
    for sample in samples:
        row: dict[str, object] = {
            "sample_id": sample.sample_id,
            "label": sample.label,
            "family": sample.family or "",
            "split": sample.split or "",
            "path": str(sample.path),
        }
        try:
            record = parse_pe(sample.path)
            parse_success += 1
            vector = record.to_vector()
            feature_success += 1
            regions = find_mutation_regions(record)
            level2_append_available = any(
                region.region_type == "append_overlay" and region.validation_level >= 2 for region in regions
            )
            level2_slack_available = any(
                region.region_type == "section_slack" and region.validation_level >= 2 for region in regions
            )
            append_available += int(level2_append_available)
            slack_available += int(level2_slack_available)
            row.update(
                {
                    "parse_success": True,
                    "feature_success": True,
                    "sha256": record.sha256,
                    "file_size": record.file_size,
                    "number_of_sections": record.number_of_sections,
                    "overlay_size": record.overlay_size,
                    "feature_count": len(vector),
                    "append_available": level2_append_available,
                    "level2_append_available": level2_append_available,
                    "level2_slack_available": level2_slack_available,
                    "error": "",
                }
            )
        except (PEParseError, OSError, ValueError) as exc:
            row.update({"parse_success": False, "feature_success": False, "error": str(exc)})
        rows.append(row)

    total = max(len(samples), 1)
    summary = {
        "sample_count": len(samples),
        "pe_parse_success_rate": parse_success / total,
        "feature_extraction_success_rate": feature_success / total,
        "append_region_available_rate": append_available / total,
        "level2_slack_region_available_rate": slack_available / total,
        "meets_parse_goal_095": parse_success / total >= 0.95,
        "meets_feature_goal_095": feature_success / total >= 0.95,
    }
    with (args.output_dir / "validation_rows.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = sorted({key for row in rows for key in row.keys()}) if rows else ["sample_id"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    (args.output_dir / "validation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
