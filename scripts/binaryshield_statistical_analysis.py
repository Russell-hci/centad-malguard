#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.evaluation.statistical_analysis import (
    load_prediction_csv,
    metric_ci_rows,
    mcnemar_clean_vs_transformed,
    mcnemar_model_vs_model,
    paired_delta_rows,
    paired_flip_counts,
)


def dataframe_to_markdown(df: pd.DataFrame) -> str:
    if df.empty:
        return "_(no rows)_"
    text_df = df.copy()
    for col in text_df.columns:
        text_df[col] = text_df[col].map(lambda value: f"{value:.6g}" if isinstance(value, float) else str(value))
    headers = list(text_df.columns)
    rows = text_df.values.tolist()
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compute BinaryShield paired statistical evidence from prediction CSVs.")
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--report-output", type=Path, required=True)
    p.add_argument("--bootstrap-samples", type=int, default=2000)
    p.add_argument("--seed", type=int, default=1337)
    return p.parse_args()


def pred(run_dir: Path, rel: str) -> Path:
    path = run_dir / rel
    if not path.exists():
        raise FileNotFoundError(path)
    return path


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    logistic = {
        "append": pred(args.run_dir, "results/byte_histogram_logistic_append_eval/predictions_byte_histogram_logistic_append_overlay.csv"),
        "slack": pred(args.run_dir, "results/byte_histogram_logistic_slack_eval/predictions_byte_histogram_logistic_section_slack.csv"),
    }
    detector_paths = {
        "byte_histogram_centroid": {
            "append": pred(args.run_dir, "results/byte_histogram_centroid_append_eval/predictions_byte_histogram_centroid_append_overlay.csv"),
            "slack": pred(args.run_dir, "results/byte_histogram_centroid_slack_eval/predictions_byte_histogram_centroid_section_slack.csv"),
        },
        "hybrid_centroid": {
            "append": pred(args.run_dir, "results/hybrid_centroid_append_eval/predictions_hybrid_centroid_append_overlay.csv"),
            "slack": pred(args.run_dir, "results/hybrid_centroid_slack_eval/predictions_hybrid_centroid_section_slack.csv"),
        },
        "pe_feature_centroid": {
            "append": pred(args.run_dir, "results/centroid_append_eval/predictions_pe_feature_centroid_append_overlay.csv"),
            "slack": pred(args.run_dir, "results/centroid_slack_eval/predictions_pe_feature_centroid_section_slack.csv"),
        },
    }
    ci = pd.DataFrame(metric_ci_rows(logistic, args.bootstrap_samples, args.seed))
    deltas = pd.DataFrame(paired_delta_rows(logistic, args.bootstrap_samples, args.seed))

    # Detector transformed-prediction McNemar tests against logistic on the same transformation rows.
    mc_rows = []
    for condition, path in logistic.items():
        df = load_prediction_csv(path)
        mc_rows.append(mcnemar_clean_vs_transformed(df, f"clean_vs_{condition}"))
        for detector, paths in detector_paths.items():
            mc_rows.append(mcnemar_model_vs_model(df, load_prediction_csv(paths[condition]), f"byte_histogram_logistic_vs_{detector}_{condition}"))
    mcnemar = pd.DataFrame(mc_rows)

    flips = []
    for condition, path in logistic.items():
        row = {"condition": condition, **paired_flip_counts(load_prediction_csv(path))}
        flips.append(row)
    flips_df = pd.DataFrame(flips)

    ci.to_csv(args.output_dir / "statistical_confidence_intervals.csv", index=False)
    deltas.to_csv(args.output_dir / "paired_deltas.csv", index=False)
    mcnemar.to_csv(args.output_dir / "mcnemar_tests.csv", index=False)
    flips_df.to_csv(args.output_dir / "prediction_flip_analysis.csv", index=False)

    report = [
        "# BinaryShield PEMML Statistical Analysis",
        "",
        f"Run directory: `{args.run_dir}`",
        f"Bootstrap samples: `{args.bootstrap_samples}`",
        f"Seed: `{args.seed}`",
        "",
        "Important scope note: the run artifacts provide paired clean/transformed predictions for transformation-evaluable rows. Full-test clean macro F1 remains the point estimate reported in the main PEMML evidence; paired confidence intervals below are computed on the rows where both clean and transformed predictions are available.",
        "",
        "## Confidence Intervals",
        "",
        dataframe_to_markdown(ci),
        "",
        "## Paired Deltas",
        "",
        dataframe_to_markdown(deltas),
        "",
        "## Prediction Flip Analysis",
        "",
        dataframe_to_markdown(flips_df),
        "",
        "## McNemar Tests",
        "",
        dataframe_to_markdown(mcnemar),
        "",
        "## Interpretation",
        "",
        "The append and slack drops are small in point-estimate terms. The paired intervals and McNemar tests should be interpreted within the transformation-evaluable subsets, not as full-test clean-performance intervals. Detector-vs-detector tests compare transformed correctness on shared sample IDs and do not imply commercial antivirus superiority.",
    ]
    args.report_output.write_text("\n".join(report) + "\n")
    print({
        "confidence_intervals": str(args.output_dir / "statistical_confidence_intervals.csv"),
        "paired_deltas": str(args.output_dir / "paired_deltas.csv"),
        "mcnemar_tests": str(args.output_dir / "mcnemar_tests.csv"),
        "prediction_flip_analysis": str(args.output_dir / "prediction_flip_analysis.csv"),
        "report": str(args.report_output),
    })


if __name__ == "__main__":
    main()
