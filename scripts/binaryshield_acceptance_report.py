from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.evaluation.acceptance import build_acceptance_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a BinaryShield measurable-goal acceptance report.")
    parser.add_argument("--validation-summary", type=Path, default=None)
    parser.add_argument("--append-metrics", type=Path, default=None)
    parser.add_argument("--slack-metrics", type=Path, default=None)
    parser.add_argument("--append-validation-summary", type=Path, default=None)
    parser.add_argument("--slack-validation-summary", type=Path, default=None)
    parser.add_argument("--append-card-summary", type=Path, default=None)
    parser.add_argument("--slack-card-summary", type=Path, default=None)
    parser.add_argument("--transfer-matrix", type=Path, default=None)
    parser.add_argument("--multi-detector-summary", type=Path, default=None)
    parser.add_argument("--detector-count", type=int, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("reports/binaryshield/acceptance"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_acceptance_report(
        validation_summary_path=args.validation_summary,
        append_metrics_path=args.append_metrics,
        slack_metrics_path=args.slack_metrics,
        append_validation_summary_path=args.append_validation_summary,
        slack_validation_summary_path=args.slack_validation_summary,
        append_card_summary_path=args.append_card_summary,
        slack_card_summary_path=args.slack_card_summary,
        transfer_matrix_path=args.transfer_matrix,
        multi_detector_summary_path=args.multi_detector_summary,
        detector_count=args.detector_count,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "acceptance_report.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    (args.output_dir / "acceptance_report.md").write_text(report.to_markdown(), encoding="utf-8")
    print(json.dumps(report.to_dict(), indent=2))


if __name__ == "__main__":
    main()
