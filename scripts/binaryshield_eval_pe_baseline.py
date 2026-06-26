from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import iter_split, load_manifest
from binaryshield.evaluation.evaluate_transformations import (
    TransformationEvaluationConfig,
    evaluate_detector_under_transformation,
)
from binaryshield.models.loaders import load_any_detector
from binaryshield.safety import assert_safe_transformation_output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a PE-feature baseline under BinaryShield transformations.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--split", default="test")
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument("--transformation", choices=["append_overlay", "section_slack"], default="append_overlay")
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/pe_feature_eval"))
    parser.add_argument("--device", default="auto", help="Device for torch checkpoints.")
    parser.add_argument(
        "--allow-repo-output",
        action="store_true",
        help="Allow transformed outputs under the repository. Use only for controlled non-malware fixtures.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    detector = load_any_detector(args.model, device=args.device)
    samples = list(iter_split(load_manifest(args.manifest, args.root_dir), args.split))
    assert_safe_transformation_output(
        samples=samples,
        output_dir=args.output_dir,
        project_root=PROJECT_ROOT,
        allow_repo_output=args.allow_repo_output,
    )
    config = TransformationEvaluationConfig(output_dir=args.output_dir, transformation=args.transformation, target=args.target)
    metrics = evaluate_detector_under_transformation(detector, samples, config)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
