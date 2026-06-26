from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.pemml import PemmlManifestConfig, build_pemml_manifest  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a BinaryShield manifest from a local PEMML dataset checkout.")
    parser.add_argument("--samples-csv", type=Path, required=True, help="Path to PEMML samples.csv.")
    parser.add_argument("--dataset-root", type=Path, required=True, help="Root containing PEMML sample files.")
    parser.add_argument("--output", type=Path, required=True, help="Output BinaryShield-compatible manifest CSV.")
    parser.add_argument("--summary-output", type=Path, default=None, help="Optional JSON summary path.")
    parser.add_argument("--mode", choices=["full", "balanced-subset"], default="full")
    parser.add_argument("--malware-count", type=int, default=None)
    parser.add_argument("--benign-count", type=int, default=None)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = build_pemml_manifest(
        PemmlManifestConfig(
            samples_csv=args.samples_csv,
            dataset_root=args.dataset_root,
            output=args.output,
            summary_output=args.summary_output,
            mode=args.mode,
            malware_count=args.malware_count,
            benign_count=args.benign_count,
            seed=args.seed,
            val_ratio=args.val_ratio,
            test_ratio=args.test_ratio,
        )
    )
    print(json.dumps({"manifest": str(args.output), **summary}, indent=2))


if __name__ == "__main__":
    main()
