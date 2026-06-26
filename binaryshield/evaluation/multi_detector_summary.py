from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


HIGHER_IS_BETTER = {
    "clean_accuracy",
    "clean_macro_f1",
    "transformed_accuracy",
    "transformed_macro_f1",
    "robust_min_macro_f1",
    "prediction_stability",
    "transformed_worst_class_f1",
}

LOWER_IS_BETTER = {
    "attack_success_rate",
    "transformed_classes_below_f1_050",
    "transformed_classes_below_f1_080",
}

COMPARISON_METRICS = [
    "robust_min_macro_f1",
    "transformed_accuracy",
    "transformed_macro_f1",
    "prediction_stability",
    "attack_success_rate",
    "transformed_worst_class_f1",
    "transformed_classes_below_f1_050",
    "transformed_classes_below_f1_080",
]


@dataclass(frozen=True)
class DetectorAggregate:
    detector: str
    transformation_count: int
    metric_count: int
    robust_min_macro_f1: float | None
    transformed_accuracy_min: float | None
    transformed_macro_f1_min: float | None
    prediction_stability_min: float | None
    attack_success_rate_max: float | None
    transformed_worst_class_f1_min: float | None
    transformed_classes_below_f1_050_max: float | None
    transformed_classes_below_f1_080_max: float | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_multi_detector_summary(
    transfer_matrix_path: str | Path,
    candidate_detector: str | None = None,
    baseline_detectors: list[str] | None = None,
) -> dict[str, Any]:
    matrix = json.loads(Path(transfer_matrix_path).read_text(encoding="utf-8"))
    rows = flatten_transfer_matrix(matrix)
    detector_names = sorted({row["detector"] for row in rows})
    aggregates = [aggregate_detector(name, rows) for name in detector_names]
    aggregate_by_name = {item.detector: item for item in aggregates}
    candidate = candidate_detector or _default_candidate(detector_names)
    baselines = baseline_detectors or [name for name in detector_names if name != candidate]
    comparison = compare_candidate_to_baselines(aggregate_by_name, candidate, baselines)
    return {
        "detector_count": len(detector_names),
        "transformation_count": len(matrix),
        "candidate_detector": candidate,
        "baseline_detectors": baselines,
        "detector_aggregates": [item.to_dict() for item in aggregates],
        "rows": rows,
        "candidate_comparison": comparison,
        "claim_boundary": (
            "This summary compares detectors only on the supplied transfer matrix. "
            "It does not validate malware behavior preservation beyond the validation records used during evaluation."
        ),
    }


def flatten_transfer_matrix(matrix: dict[str, dict[str, dict[str, object]]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for transformation, detectors in matrix.items():
        for detector, metrics in detectors.items():
            row: dict[str, object] = {"transformation": transformation, "detector": detector}
            if "error" in metrics:
                row["error"] = metrics["error"]
            else:
                for key, value in metrics.items():
                    if isinstance(value, (int, float)):
                        row[key] = float(value)
            rows.append(row)
    return rows


def aggregate_detector(detector: str, rows: list[dict[str, object]]) -> DetectorAggregate:
    detector_rows = [row for row in rows if row["detector"] == detector and "error" not in row]
    return DetectorAggregate(
        detector=detector,
        transformation_count=len({str(row["transformation"]) for row in detector_rows}),
        metric_count=len(detector_rows),
        robust_min_macro_f1=_min_metric(detector_rows, "robust_min_macro_f1"),
        transformed_accuracy_min=_min_metric(detector_rows, "transformed_accuracy"),
        transformed_macro_f1_min=_min_metric(detector_rows, "transformed_macro_f1"),
        prediction_stability_min=_min_metric(detector_rows, "prediction_stability"),
        attack_success_rate_max=_max_metric(detector_rows, "attack_success_rate"),
        transformed_worst_class_f1_min=_min_metric(detector_rows, "transformed_worst_class_f1"),
        transformed_classes_below_f1_050_max=_max_metric(detector_rows, "transformed_classes_below_f1_050"),
        transformed_classes_below_f1_080_max=_max_metric(detector_rows, "transformed_classes_below_f1_080"),
    )


def compare_candidate_to_baselines(
    aggregates: dict[str, DetectorAggregate],
    candidate: str | None,
    baselines: list[str],
) -> dict[str, object]:
    if not candidate or candidate not in aggregates or not baselines:
        return {
            "status": "NOT_VALIDATED",
            "metrics_beaten": 0,
            "target": "candidate beats strongest baseline on >= 2 robustness metrics",
            "note": "Missing candidate or baseline detector.",
        }
    candidate_metrics = aggregates[candidate].to_dict()
    metric_results: list[dict[str, object]] = []
    metrics_beaten = 0
    for metric in COMPARISON_METRICS:
        candidate_value = candidate_metrics.get(_aggregate_key(metric))
        baseline_values = [
            aggregates[name].to_dict().get(_aggregate_key(metric))
            for name in baselines
            if name in aggregates and aggregates[name].to_dict().get(_aggregate_key(metric)) is not None
        ]
        if candidate_value is None or not baseline_values:
            metric_results.append(
                {
                    "metric": metric,
                    "status": "NOT_VALIDATED",
                    "candidate": candidate_value,
                    "strongest_baseline": None,
                }
            )
            continue
        candidate_float = float(candidate_value)
        if metric in LOWER_IS_BETTER:
            strongest_baseline = min(float(value) for value in baseline_values)
            beaten = candidate_float < strongest_baseline
        else:
            strongest_baseline = max(float(value) for value in baseline_values)
            beaten = candidate_float > strongest_baseline
        metrics_beaten += int(beaten)
        metric_results.append(
            {
                "metric": metric,
                "status": "BEATS_BASELINE" if beaten else "DOES_NOT_BEAT_BASELINE",
                "candidate": candidate_float,
                "strongest_baseline": strongest_baseline,
            }
        )
    return {
        "status": "PASS" if metrics_beaten >= 2 else "FAIL",
        "metrics_beaten": metrics_beaten,
        "target": "candidate beats strongest baseline on >= 2 robustness metrics",
        "metric_results": metric_results,
    }


def write_multi_detector_summary(summary: dict[str, Any], output_dir: str | Path) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "multi_detector_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (root / "multi_detector_summary.md").write_text(to_markdown(summary), encoding="utf-8")
    with (root / "multi_detector_rows.csv").open("w", encoding="utf-8", newline="") as handle:
        rows = list(summary.get("rows", []))
        fieldnames = sorted({key for row in rows for key in row}) if rows else ["detector", "transformation"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(summary: dict[str, Any]) -> str:
    aggregate_rows = "\n".join(
        "| {detector} | {transformation_count} | {robust_min_macro_f1} | {transformed_macro_f1_min} | {prediction_stability_min} | {attack_success_rate_max} |".format(
            **aggregate
        )
        for aggregate in summary.get("detector_aggregates", [])
    )
    comparison = summary.get("candidate_comparison", {})
    metric_rows = "\n".join(
        f"| {row.get('metric')} | {row.get('status')} | {row.get('candidate')} | {row.get('strongest_baseline')} |"
        for row in comparison.get("metric_results", [])
    )
    return (
        "# BinaryShield Multi-Detector Summary\n\n"
        f"**Candidate detector:** {summary.get('candidate_detector')}\n\n"
        f"**Baseline detectors:** {', '.join(summary.get('baseline_detectors', []))}\n\n"
        f"**Detector count:** {summary.get('detector_count')}\n\n"
        f"**Transformation count:** {summary.get('transformation_count')}\n\n"
        "## Detector Aggregates\n\n"
        "| Detector | Transformations | Robust-Min Macro F1 | Transformed Macro F1 Min | Prediction Stability Min | Attack Success Rate Max |\n"
        "|---|---:|---:|---:|---:|---:|\n"
        f"{aggregate_rows}\n\n"
        "## Candidate Comparison\n\n"
        f"**Status:** {comparison.get('status')}\n\n"
        f"**Metrics beaten:** {comparison.get('metrics_beaten')} / 2 required\n\n"
        "| Metric | Status | Candidate | Strongest Baseline |\n"
        "|---|---|---:|---:|\n"
        f"{metric_rows}\n\n"
        "## Claim Boundary\n\n"
        f"{summary.get('claim_boundary')}\n"
    )


def _default_candidate(detector_names: list[str]) -> str | None:
    for preferred in ["torch_hybrid_binaryshield", "hybrid_centroid", "byte_histogram_centroid"]:
        if preferred in detector_names:
            return preferred
    return detector_names[-1] if detector_names else None


def _aggregate_key(metric: str) -> str:
    if metric == "transformed_accuracy":
        return "transformed_accuracy_min"
    if metric == "transformed_macro_f1":
        return "transformed_macro_f1_min"
    if metric == "prediction_stability":
        return "prediction_stability_min"
    if metric == "attack_success_rate":
        return "attack_success_rate_max"
    if metric == "transformed_worst_class_f1":
        return "transformed_worst_class_f1_min"
    if metric == "transformed_classes_below_f1_050":
        return "transformed_classes_below_f1_050_max"
    if metric == "transformed_classes_below_f1_080":
        return "transformed_classes_below_f1_080_max"
    return metric


def _min_metric(rows: list[dict[str, object]], metric: str) -> float | None:
    values = [float(row[metric]) for row in rows if metric in row]
    return min(values) if values else None


def _max_metric(rows: list[dict[str, object]], metric: str) -> float | None:
    values = [float(row[metric]) for row in rows if metric in row]
    return max(values) if values else None
