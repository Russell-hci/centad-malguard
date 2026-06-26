from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.evaluation.feature_record_summary import (  # noqa: E402
    build_feature_record_gate_report,
    write_feature_record_gate_report,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a gate report for BODMAS PE-derived feature-record evaluation.")
    parser.add_argument("--candidate-metrics", type=Path, required=True)
    parser.add_argument("--baseline-metrics", type=Path, default=None)
    parser.add_argument("--candidate-summary", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--min-accuracy", type=float, default=0.90)
    parser.add_argument("--min-macro-f1", type=float, default=0.90)
    parser.add_argument("--min-worst-class-f1", type=float, default=0.85)
    parser.add_argument("--min-benign-f1", type=float, default=0.90)
    parser.add_argument("--min-malware-f1", type=float, default=0.90)
    parser.add_argument("--min-baseline-metrics-beaten", type=int, default=3)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_feature_record_gate_report(
        candidate_metrics_path=args.candidate_metrics,
        baseline_metrics_path=args.baseline_metrics,
        candidate_summary_path=args.candidate_summary,
        min_accuracy=args.min_accuracy,
        min_macro_f1=args.min_macro_f1,
        min_worst_class_f1=args.min_worst_class_f1,
        min_benign_f1=args.min_benign_f1,
        min_malware_f1=args.min_malware_f1,
        min_baseline_metrics_beaten=args.min_baseline_metrics_beaten,
    )
    write_feature_record_gate_report(report, args.output_dir)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
