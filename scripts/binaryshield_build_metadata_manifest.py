from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.metadata_manifest import build_metadata_manifest_rows, write_metadata_manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a Git-safe BinaryShield manifest from an approved metadata CSV "
            "and external raw PE directory. Supports path-based or SHA-based joins."
        )
    )
    parser.add_argument("--metadata", type=Path, required=True, help="Headered metadata CSV.")
    parser.add_argument("--binaries-dir", type=Path, required=True, help="External directory containing approved PE files.")
    parser.add_argument("--output", type=Path, required=True, help="Output BinaryShield manifest CSV.")
    parser.add_argument("--summary-output", type=Path, default=None, help="Optional JSON summary path.")
    parser.add_argument("--path-column", default=None, help="Metadata column containing absolute or binaries-dir-relative paths.")
    parser.add_argument("--sha256-column", default=None, help="Metadata column containing SHA-256 hashes.")
    parser.add_argument("--label-column", required=True, help="Metadata column containing the classification label.")
    parser.add_argument("--family-column", default=None, help="Optional metadata column containing malware family/type.")
    parser.add_argument("--split-column", default=None, help="Optional metadata column containing train/val/test split.")
    parser.add_argument("--sample-id-column", default=None, help="Optional metadata column containing sample IDs.")
    parser.add_argument("--default-label", default=None, help="Fallback label when label column value is empty.")
    parser.add_argument("--default-family", default="", help="Fallback family when no family column is supplied.")
    parser.add_argument("--relative-to", type=Path, default=None, help="Store paths relative to this external directory.")
    parser.add_argument("--compute-hash", action="store_true", help="Hash files when filenames are not SHA-256 values.")
    parser.add_argument("--require-pe-parse", action="store_true", help="Skip files that fail PE parsing.")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows, summary = build_metadata_manifest_rows(
        args.metadata,
        args.binaries_dir,
        path_column=args.path_column,
        sha256_column=args.sha256_column,
        label_column=args.label_column,
        family_column=args.family_column,
        split_column=args.split_column,
        sample_id_column=args.sample_id_column,
        default_label=args.default_label,
        default_family=args.default_family,
        compute_hash=args.compute_hash,
        require_pe_parse=args.require_pe_parse,
        relative_to=args.relative_to or args.binaries_dir,
        seed=args.seed,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
    )
    write_metadata_manifest(rows, args.output)
    if args.summary_output is not None:
        args.summary_output.parent.mkdir(parents=True, exist_ok=True)
        args.summary_output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"manifest": str(args.output), **summary}, indent=2))


if __name__ == "__main__":
    main()
