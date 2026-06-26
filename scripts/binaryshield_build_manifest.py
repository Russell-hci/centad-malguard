from __future__ import annotations

import argparse
import csv
import hashlib
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.pe_features import PEParseError, parse_pe


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Git-safe manifest for external PE files.")
    parser.add_argument("--input-dir", type=Path, required=True, help="Directory containing approved external PE files.")
    parser.add_argument("--output", type=Path, required=True, help="Output CSV manifest path.")
    parser.add_argument("--label", default=None, help="Constant label for all files, e.g. benign or malware.")
    parser.add_argument("--label-from-parent", action="store_true", help="Use parent folder name as label.")
    parser.add_argument("--family-from-parent", action="store_true", help="Use parent folder name as family.")
    parser.add_argument("--relative-to", type=Path, default=None, help="Store paths relative to this directory.")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    parser.add_argument("--require-pe-parse", action="store_true", help="Skip files that do not parse as PE.")
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _split(index: int, total: int, val_ratio: float, test_ratio: float) -> str:
    test_start = int(total * (1.0 - test_ratio))
    val_start = int(total * (1.0 - test_ratio - val_ratio))
    if index >= test_start:
        return "test"
    if index >= val_start:
        return "val"
    return "train"


def main() -> None:
    args = parse_args()
    files = [path for path in args.input_dir.rglob("*") if path.is_file()]
    rng = random.Random(args.seed)
    rng.shuffle(files)
    rows: list[dict[str, str]] = []
    for index, path in enumerate(files):
        if args.require_pe_parse:
            try:
                parse_pe(path)
            except PEParseError:
                continue
        if args.label_from_parent:
            label = path.parent.name
        elif args.label is not None:
            label = args.label
        else:
            label = "unknown"
        family = path.parent.name if args.family_from_parent else ""
        stored_path = path
        if args.relative_to is not None:
            stored_path = path.relative_to(args.relative_to)
        rows.append(
            {
                "sample_id": path.stem,
                "path": str(stored_path),
                "label": label,
                "family": family,
                "split": _split(index, len(files), args.val_ratio, args.test_ratio),
                "sha256": _sha256(path),
            }
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_id", "path", "label", "family", "split", "sha256"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
