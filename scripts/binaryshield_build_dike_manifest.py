from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.dike import build_dike_manifest_rows
from binaryshield.metadata_manifest import write_metadata_manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a BinaryShield manifest from an external DikeDataset checkout.")
    parser.add_argument("--dike-root", type=Path, required=True, help="External DikeDataset root directory.")
    parser.add_argument("--output", type=Path, required=True, help="Output BinaryShield manifest CSV.")
    parser.add_argument("--summary-output", type=Path, default=None, help="Optional JSON summary path.")
    parser.add_argument("--malice-threshold", type=float, default=0.4)
    parser.add_argument("--min-family-score", type=float, default=0.05)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    parser.add_argument("--allow-non-pe", action="store_true", help="Include files even if PE parsing fails. Not recommended.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    label_paths = [args.dike_root / "labels" / "benign.csv", args.dike_root / "labels" / "malware.csv"]
    files_dir = args.dike_root / "files"
    rows, summary = build_dike_manifest_rows(
        label_paths,
        files_dir,
        malice_threshold=args.malice_threshold,
        min_family_score=args.min_family_score,
        require_pe_parse=not args.allow_non_pe,
        relative_to=files_dir,
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
