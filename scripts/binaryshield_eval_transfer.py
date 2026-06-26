from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import iter_split, load_manifest
from binaryshield.evaluation.evaluate_transfer import evaluate_transfer_matrix
from binaryshield.models.loaders import load_any_detector
from binaryshield.safety import assert_safe_transformation_output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate validated PE transformations across multiple detectors.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--models", type=Path, nargs="+", required=True)
    parser.add_argument("--split", default="test")
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument("--transformations", nargs="+", default=["append_overlay", "section_slack"])
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/transfer_eval"))
    parser.add_argument("--device", default="auto", help="Device for torch checkpoints.")
    parser.add_argument(
        "--allow-repo-output",
        action="store_true",
        help="Allow transformed outputs under the repository. Use only for controlled non-malware fixtures.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    detectors = [load_any_detector(path, device=args.device) for path in args.models]
    samples = list(iter_split(load_manifest(args.manifest, args.root_dir), args.split))
    assert_safe_transformation_output(
        samples=samples,
        output_dir=args.output_dir,
        project_root=PROJECT_ROOT,
        allow_repo_output=args.allow_repo_output,
    )
    matrix = evaluate_transfer_matrix(detectors, samples, args.output_dir, transformations=list(args.transformations), target=args.target)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "transfer_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    print(json.dumps(matrix, indent=2))


if __name__ == "__main__":
    main()
