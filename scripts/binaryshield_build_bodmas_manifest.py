from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.bodmas import (  # noqa: E402
    build_raw_bodmas_matches,
    inspect_bodmas_npz,
    load_bodmas_metadata,
    split_by_time_or_hash,
)
from binaryshield.pe_features import PEParseError, parse_pe  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build sanitized BODMAS manifests for BinaryShield.")
    parser.add_argument("--metadata", type=Path, required=True, help="BODMAS metadata CSV.")
    parser.add_argument("--raw-binaries-dir", type=Path, default=None, help="External raw malware binary directory.")
    parser.add_argument("--features-npz", type=Path, default=None, help="Optional BODMAS bodmas.npz feature-vector file.")
    parser.add_argument("--raw-output", type=Path, default=None, help="Output raw-PE manifest CSV.")
    parser.add_argument("--feature-output", type=Path, default=None, help="Output PE-derived feature-record manifest CSV.")
    parser.add_argument("--summary-output", type=Path, required=True, help="Output JSON summary.")
    parser.add_argument("--relative-to", type=Path, default=None, help="Store raw paths relative to this directory.")
    parser.add_argument("--compute-hash", action="store_true", help="Hash raw files if filenames are not SHA-256.")
    parser.add_argument("--require-pe-parse", action="store_true", help="Skip raw files that do not parse as PE.")
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metadata_rows = load_bodmas_metadata(args.metadata)
    summary: dict[str, object] = {
        "metadata_rows": len(metadata_rows),
        "metadata_path": str(args.metadata),
        "claim_boundary": (
            "This script writes sanitized manifests only. It does not copy raw malware "
            "or validate behavioral preservation."
        ),
    }
    if args.features_npz:
        feature_summary = inspect_bodmas_npz(args.features_npz)
        summary["features_npz"] = str(args.features_npz)
        summary["feature_summary"] = feature_summary
        if args.feature_output:
            feature_rows_written = _write_feature_manifest(
                args.feature_output,
                metadata_rows,
                feature_row_count=int(feature_summary.get("feature_rows", len(metadata_rows))),
                val_ratio=args.val_ratio,
                test_ratio=args.test_ratio,
            )
            summary["feature_manifest"] = str(args.feature_output)
            summary["feature_rows_written"] = feature_rows_written
    if args.raw_binaries_dir:
        matches = build_raw_bodmas_matches(metadata_rows, args.raw_binaries_dir, compute_hash=args.compute_hash)
        parse_failures = 0
        if args.require_pe_parse:
            kept = []
            for match in matches:
                try:
                    parse_pe(match.path)
                    kept.append(match)
                except (PEParseError, OSError, ValueError):
                    parse_failures += 1
            matches = kept
        if args.raw_output:
            _write_raw_manifest(args.raw_output, matches, args.relative_to, args.val_ratio, args.test_ratio)
        summary.update(
            {
                "raw_binaries_dir": str(args.raw_binaries_dir),
                "raw_matches": len(matches),
                "raw_parse_failures": parse_failures,
                "raw_manifest": str(args.raw_output) if args.raw_output else None,
                "raw_paths_are_relative_to": str(args.relative_to) if args.relative_to else None,
            }
        )
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


def _write_feature_manifest(
    output: Path,
    metadata_rows,
    *,
    feature_row_count: int,
    val_ratio: float,
    test_ratio: float,
) -> int:
    count = min(len(metadata_rows), feature_row_count)
    rows = metadata_rows[:count]
    splits = split_by_time_or_hash(rows, val_ratio=val_ratio, test_ratio=test_ratio)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["sample_id", "record_index", "label", "family", "split", "sha256", "first_seen"],
        )
        writer.writeheader()
        for index, (row, split) in enumerate(zip(rows, splits, strict=False)):
            writer.writerow(
                {
                    "sample_id": row.sha256,
                    "record_index": index,
                    "label": row.label,
                    "family": row.family,
                    "split": split,
                    "sha256": row.sha256,
                    "first_seen": row.first_seen,
                }
            )
    return count


def _write_raw_manifest(output: Path, matches, relative_to: Path | None, val_ratio: float, test_ratio: float) -> None:
    splits = split_by_time_or_hash(matches, val_ratio=val_ratio, test_ratio=test_ratio)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_id", "path", "label", "family", "split", "sha256"])
        writer.writeheader()
        for match, split in zip(matches, splits, strict=False):
            stored_path = match.path
            if relative_to is not None:
                stored_path = match.path.relative_to(relative_to)
            writer.writerow(
                {
                    "sample_id": match.sample_id,
                    "path": str(stored_path),
                    "label": match.label,
                    "family": match.family,
                    "split": split,
                    "sha256": match.sha256,
                }
            )


if __name__ == "__main__":
    main()
