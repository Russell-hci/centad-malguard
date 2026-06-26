from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.mutation_regions import find_mutation_regions
from binaryshield.pe_features import parse_pe
from binaryshield.robustness_card import card_from_validation, write_robustness_card
from binaryshield.transformations import append_overlay, mutate_slack_space
from binaryshield.validation import validate_transformation


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a BinaryShield PE audit on one file.")
    parser.add_argument("--input", type=Path, required=True, help="Input PE file.")
    parser.add_argument("--output-dir", type=Path, default=Path("binaryshield_outputs/audit"))
    parser.add_argument("--sample-id", default=None)
    parser.add_argument("--transformation", choices=["append_overlay", "section_slack"], default="append_overlay")
    parser.add_argument("--payload-size", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=1337)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sample_id = args.sample_id or args.input.stem
    args.output_dir.mkdir(parents=True, exist_ok=True)

    feature_record = parse_pe(args.input)
    regions = find_mutation_regions(feature_record)
    transformed_path = args.output_dir / "transformed" / f"{sample_id}_{args.transformation}.bin"
    if args.transformation == "append_overlay":
        result = append_overlay(args.input, transformed_path, payload_size=args.payload_size, seed=args.seed)
    else:
        result = mutate_slack_space(args.input, transformed_path, max_bytes=args.payload_size, seed=args.seed)

    validation = validate_transformation(result, args.output_dir / "validation" / f"{sample_id}.json")
    card = card_from_validation(
        sample_id=sample_id,
        validation=validation,
        detector_name="not_attached",
        notes=[
            "Single-file audit validates PE structure and transformation safety.",
            "No detector was attached in this CLI run.",
        ],
    )
    write_robustness_card(card, args.output_dir / "cards" / f"{sample_id}.md")
    (args.output_dir / "features.json").write_text(
        json.dumps(feature_record.to_dict(), indent=2),
        encoding="utf-8",
    )
    (args.output_dir / "mutation_regions.json").write_text(
        json.dumps([region.to_dict() for region in regions], indent=2),
        encoding="utf-8",
    )
    print(json.dumps({"sample_id": sample_id, "validation": validation.to_dict()}, indent=2))


if __name__ == "__main__":
    main()
