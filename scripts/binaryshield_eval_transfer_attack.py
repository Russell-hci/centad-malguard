from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import iter_split, load_manifest  # noqa: E402
from binaryshield.evaluation.transfer_attack import TransferAttackConfig, evaluate_transfer_attack  # noqa: E402
from binaryshield.models.loaders import load_any_detector  # noqa: E402
from binaryshield.safety import assert_safe_transformation_output  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate transformations selected against one detector on other detectors.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--source-model", type=Path, required=True)
    parser.add_argument("--target-models", type=Path, nargs="+", required=True)
    parser.add_argument("--split", default="test")
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument("--transformation", choices=["append_overlay", "section_slack"], default="append_overlay")
    parser.add_argument("--n", type=int, default=5)
    parser.add_argument("--payload-size", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/transfer_attack"))
    parser.add_argument("--device", default="auto", help="Device for torch checkpoints.")
    parser.add_argument(
        "--allow-repo-output",
        action="store_true",
        help="Allow transformed outputs under the repository. Use only for controlled non-malware fixtures.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source = load_any_detector(args.source_model, device=args.device)
    targets = [load_any_detector(path, device=args.device) for path in args.target_models]
    samples = list(iter_split(load_manifest(args.manifest, args.root_dir), args.split))
    assert_safe_transformation_output(
        samples=samples,
        output_dir=args.output_dir,
        project_root=PROJECT_ROOT,
        allow_repo_output=args.allow_repo_output,
    )
    matrix = evaluate_transfer_attack(
        source,
        targets,
        samples,
        TransferAttackConfig(
            output_dir=args.output_dir,
            transformation=args.transformation,
            n=args.n,
            payload_size=args.payload_size,
            seed=args.seed,
            target=args.target,
        ),
    )
    print(json.dumps(matrix, indent=2))


if __name__ == "__main__":
    main()
