from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.evaluation.evidence_tables import EvidenceInputs, build_evidence_tables  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build sanitized BinaryShield judge-facing evidence tables.")
    parser.add_argument(
        "--append-predictions",
        type=Path,
        default=Path("reports/binaryshield/dike_logistic_candidate_import/append_eval/predictions_byte_histogram_logistic_append_overlay.csv"),
    )
    parser.add_argument(
        "--slack-predictions",
        type=Path,
        default=Path("reports/binaryshield/dike_logistic_candidate_import/slack_eval/predictions_byte_histogram_logistic_section_slack.csv"),
    )
    parser.add_argument(
        "--append-metrics",
        type=Path,
        default=Path("reports/binaryshield/dike_logistic_candidate_import/append_eval/metrics_byte_histogram_logistic_append_overlay.json"),
    )
    parser.add_argument(
        "--slack-metrics",
        type=Path,
        default=Path("reports/binaryshield/dike_logistic_candidate_import/slack_eval/metrics_byte_histogram_logistic_section_slack.json"),
    )
    parser.add_argument(
        "--append-validation",
        type=Path,
        default=Path("reports/binaryshield/dike_logistic_candidate_import/append_eval/validation_summary/transformation_validation_summary.json"),
    )
    parser.add_argument(
        "--slack-validation",
        type=Path,
        default=Path("reports/binaryshield/dike_logistic_candidate_import/slack_eval/validation_summary/transformation_validation_summary.json"),
    )
    parser.add_argument(
        "--multi-detector-summary",
        type=Path,
        default=Path("reports/binaryshield/dike_logistic_candidate_reports_import/multi_detector/multi_detector_summary.json"),
    )
    parser.add_argument("--logistic-model", type=Path, default=None, help="Optional saved byte_histogram_logistic_detector.json.")
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/sanitized_metrics"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = build_evidence_tables(
        EvidenceInputs(
            append_predictions=args.append_predictions,
            slack_predictions=args.slack_predictions,
            append_metrics=args.append_metrics,
            slack_metrics=args.slack_metrics,
            append_validation=args.append_validation,
            slack_validation=args.slack_validation,
            multi_detector_summary=args.multi_detector_summary,
            logistic_model=args.logistic_model,
            output_dir=args.output_dir,
        )
    )
    print(json.dumps({"output_dir": str(args.output_dir), "tables": sorted(summary.keys())}, indent=2))


if __name__ == "__main__":
    main()
