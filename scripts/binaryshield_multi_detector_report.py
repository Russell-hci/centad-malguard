from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.evaluation.multi_detector_summary import (  # noqa: E402
    build_multi_detector_summary,
    write_multi_detector_summary,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize BinaryShield robustness across detector families.")
    parser.add_argument("--transfer-matrix", type=Path, required=True)
    parser.add_argument("--candidate-detector", default=None)
    parser.add_argument("--baseline-detectors", nargs="*", default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/binaryshield/multi_detector"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = build_multi_detector_summary(
        transfer_matrix_path=args.transfer_matrix,
        candidate_detector=args.candidate_detector,
        baseline_detectors=args.baseline_detectors,
    )
    write_multi_detector_summary(summary, args.output_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
