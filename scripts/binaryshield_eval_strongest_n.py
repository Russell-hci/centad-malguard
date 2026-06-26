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
    parser = argparse.ArgumentParser(description="Run strongest-of-N BinaryShield transformation evaluation.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--split", default="test")
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument("--transformation", choices=["append_overlay", "section_slack"], default="append_overlay")
    parser.add_argument("--n", type=int, default=5)
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/strongest_n"))
    parser.add_argument("--device", default="auto", help="Device for torch checkpoints.")
    parser.add_argument(
        "--allow-repo-output",
        action="store_true",
        help="Allow transformed outputs under the repository. Use only for controlled non-malware fixtures.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.n <= 0:
        raise ValueError("--n must be positive")
    detector = load_any_detector(args.model, device=args.device)
    samples = list(iter_split(load_manifest(args.manifest, args.root_dir), args.split))
    assert_safe_transformation_output(
        samples=samples,
        output_dir=args.output_dir,
        project_root=PROJECT_ROOT,
        allow_repo_output=args.allow_repo_output,
    )
    all_metrics: list[dict[str, float]] = []
    for seed in range(args.n):
        metrics = evaluate_detector_under_transformation(
            detector,
            samples,
            TransformationEvaluationConfig(
                output_dir=args.output_dir / f"seed_{seed}",
                transformation=args.transformation,
                seed=seed,
                target=args.target,
            ),
        )
        metrics["seed"] = float(seed)
        all_metrics.append(metrics)
    strongest = max(
        all_metrics,
        key=lambda item: (item.get("attack_success_rate", 0.0), -item.get("robust_min_macro_f1", 0.0)),
    )
    summary = {
        "detector": detector.detector_name,
        "transformation": args.transformation,
        "n": args.n,
        "strongest_seed": int(strongest["seed"]),
        "strongest_metrics": strongest,
        "all_metrics": all_metrics,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "strongest_of_n_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
