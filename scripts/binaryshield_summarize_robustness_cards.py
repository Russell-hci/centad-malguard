from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import iter_split, load_manifest  # noqa: E402
from binaryshield.evaluation.card_summary import summarize_robustness_cards, write_card_summary  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize BinaryShield Malware Robustness Card coverage.")
    parser.add_argument("--cards-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-count", type=int, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--split", default="test")
    parser.add_argument(
        "--expected-existing-records",
        action="store_true",
        help="Use existing card count as the expected count. Use for optional transformations such as slack.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    expected_count = args.expected_count
    if expected_count is None and args.expected_existing_records:
        expected_count = len(list(args.cards_dir.rglob("*.md"))) if args.cards_dir.exists() else 0
    if expected_count is None and args.manifest is not None:
        expected_count = len(list(iter_split(load_manifest(args.manifest, args.root_dir), args.split)))
    summary = summarize_robustness_cards(args.cards_dir, expected_count=expected_count)
    write_card_summary(summary, args.output_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
