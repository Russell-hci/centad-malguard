from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.evaluation.card_deck import build_card_deck, write_card_deck  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a consolidated BinaryShield Malware Robustness Card deck.")
    parser.add_argument("--cards-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--title", default="BinaryShield Malware Robustness Card Deck")
    parser.add_argument("--max-cards", type=int, default=25)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    deck = build_card_deck(args.cards_root, title=args.title, max_cards=args.max_cards)
    write_card_deck(deck, args.output_dir)
    print(json.dumps(deck, indent=2))


if __name__ == "__main__":
    main()
