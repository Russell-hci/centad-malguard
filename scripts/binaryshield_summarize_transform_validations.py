from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import iter_split, load_manifest  # noqa: E402
from binaryshield.evaluation.validation_summary import (  # noqa: E402
    summarize_validation_records,
    write_validation_summary,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize BinaryShield transformation validation JSON records.")
    parser.add_argument("--validation-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-count", type=int, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--split", default="test")
    parser.add_argument(
        "--expected-existing-records",
        action="store_true",
        help="Use existing validation JSON count as the expected count. Use for optional transformations such as slack.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    expected_count = args.expected_count
    if expected_count is None and args.expected_existing_records:
        expected_count = len(list(args.validation_dir.rglob("*.json"))) if args.validation_dir.exists() else 0
    if expected_count is None and args.manifest is not None:
        expected_count = len(list(iter_split(load_manifest(args.manifest, args.root_dir), args.split)))
    summary = summarize_validation_records(args.validation_dir, expected_count=expected_count)
    write_validation_summary(summary, args.output_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
