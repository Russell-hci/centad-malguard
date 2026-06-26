from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LABELS = ["benign", "malware"]


@dataclass(frozen=True)
class EvidenceInputs:
    append_predictions: Path
    slack_predictions: Path
    append_metrics: Path
    slack_metrics: Path
    append_validation: Path
    slack_validation: Path
    multi_detector_summary: Path
    output_dir: Path
    logistic_model: Path | None = None


def build_evidence_tables(inputs: EvidenceInputs) -> dict[str, Any]:
    inputs.output_dir.mkdir(parents=True, exist_ok=True)
    append_rows = _read_csv(inputs.append_predictions)
    slack_rows = _read_csv(inputs.slack_predictions)
    clean_rows = _valid_prediction_rows(append_rows)

    tables: dict[str, Any] = {
        "clean_confusion_matrix": _confusion_matrix(clean_rows, "target", "clean_prediction"),
        "append_confusion_matrix": _confusion_matrix(_valid_prediction_rows(append_rows), "target", "transformed_prediction"),
        "slack_confusion_matrix": _confusion_matrix(_valid_prediction_rows(slack_rows), "target", "transformed_prediction"),
        "clean_per_class_metrics": _per_class_metrics(clean_rows, "target", "clean_prediction"),
        "append_per_class_metrics": _per_class_metrics(_valid_prediction_rows(append_rows), "target", "transformed_prediction"),
        "slack_per_class_metrics": _per_class_metrics(_valid_prediction_rows(slack_rows), "target", "transformed_prediction"),
        "prediction_stability": [
            _prediction_stability("append_overlay", append_rows),
            _prediction_stability("section_slack", slack_rows),
        ],
        "attack_success_rate": [
            _attack_success_rate("append_overlay", append_rows),
            _attack_success_rate("section_slack", slack_rows),
        ],
        "validation_coverage": [
            _validation_coverage("append_overlay", inputs.append_validation),
            _validation_coverage("section_slack", inputs.slack_validation),
        ],
        "detector_comparison": _detector_comparison(inputs.multi_detector_summary),
        "accepted_vs_baseline_deltas": _accepted_vs_baseline_deltas(inputs.multi_detector_summary),
        "logistic_coefficients": _logistic_coefficients(inputs.logistic_model),
        "claim_boundary": (
            "These tables are generated only from sanitized metrics and prediction reports. "
            "They do not include raw malware bytes, transformed binaries, or unsafe paths."
        ),
    }
    _write_outputs(inputs.output_dir, tables)
    return tables


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _valid_prediction_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if not row.get("error")
        and row.get("target")
        and row.get("clean_prediction")
        and row.get("transformed_prediction")
    ]


def _confusion_matrix(rows: list[dict[str, str]], target_key: str, prediction_key: str) -> list[dict[str, object]]:
    labels = sorted(set(LABELS) | {row[target_key] for row in rows} | {row[prediction_key] for row in rows})
    counts = Counter((row[target_key], row[prediction_key]) for row in rows)
    return [
        {
            "target": target,
            **{f"predicted_{prediction}": counts[(target, prediction)] for prediction in labels},
            "support": sum(counts[(target, prediction)] for prediction in labels),
        }
        for target in labels
    ]


def _per_class_metrics(rows: list[dict[str, str]], target_key: str, prediction_key: str) -> list[dict[str, object]]:
    labels = sorted(set(LABELS) | {row[target_key] for row in rows} | {row[prediction_key] for row in rows})
    true_counts = Counter(row[target_key] for row in rows)
    predicted_counts = Counter(row[prediction_key] for row in rows)
    tp = Counter(row[target_key] for row in rows if row[target_key] == row[prediction_key])
    output = []
    for label in labels:
        precision = tp[label] / predicted_counts[label] if predicted_counts[label] else 0.0
        recall = tp[label] / true_counts[label] if true_counts[label] else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        output.append(
            {
                "label": label,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "support": true_counts[label],
            }
        )
    return output


def _prediction_stability(transformation: str, rows: list[dict[str, str]]) -> dict[str, object]:
    valid = _valid_prediction_rows(rows)
    stable = sum(row["clean_prediction"] == row["transformed_prediction"] for row in valid)
    return {
        "transformation": transformation,
        "evaluated_samples": len(valid),
        "stable_predictions": stable,
        "prediction_stability": stable / len(valid) if valid else 0.0,
        "failed_transformations": sum(1 for row in rows if row.get("error")),
    }


def _attack_success_rate(transformation: str, rows: list[dict[str, str]]) -> dict[str, object]:
    valid = _valid_prediction_rows(rows)
    clean_correct = sum(row["clean_prediction"] == row["target"] for row in valid)
    attack_success = sum(
        row["clean_prediction"] == row["target"] and row["transformed_prediction"] != row["target"]
        for row in valid
    )
    return {
        "transformation": transformation,
        "clean_correct_samples": clean_correct,
        "attack_successes": attack_success,
        "attack_success_rate": attack_success / clean_correct if clean_correct else 0.0,
    }


def _validation_coverage(transformation: str, path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    overall = data.get("overall", {})
    return {
        "transformation": transformation,
        "validation_json_count": data.get("validation_json_count", 0),
        "expected_count": data.get("expected_count", 0),
        "validation_json_generation_rate": data.get("validation_json_generation_rate", 0.0),
        "pe_parse_transformed_rate": overall.get("pe_parse_transformed_rate", overall.get("transformed_pe_parse_success_rate", 0.0)),
        "entry_point_unchanged_rate": overall.get("entry_point_unchanged_rate", 0.0),
        "executable_sections_unchanged_rate": overall.get("executable_sections_unchanged_rate", 0.0),
        "level_2_or_higher_rate": overall.get("level2_or_higher_rate", overall.get("level_2_or_higher_rate", 0.0)),
    }


def _detector_comparison(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for row in data.get("rows", []):
        rows.append(
            {
                "detector": row.get("detector"),
                "transformation": row.get("transformation"),
                "clean_macro_f1": _float(row.get("clean_macro_f1")),
                "transformed_macro_f1": _float(row.get("transformed_macro_f1")),
                "robust_min_macro_f1": _float(row.get("robust_min_macro_f1")),
                "prediction_stability": _float(row.get("prediction_stability")),
                "attack_success_rate": _float(row.get("attack_success_rate")),
                "transformed_worst_class_f1": _float(row.get("transformed_worst_class_f1")),
                "evaluated_samples": _float(row.get("evaluated_samples")),
            }
        )
    return rows


def _accepted_vs_baseline_deltas(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    comparison = data.get("candidate_comparison", {})
    rows = []
    for row in comparison.get("metric_results", []):
        candidate = _float(row.get("candidate"))
        baseline = _float(row.get("strongest_baseline"))
        rows.append(
            {
                "metric": row.get("metric"),
                "status": row.get("status"),
                "candidate": candidate,
                "strongest_baseline": baseline,
                "delta_candidate_minus_baseline": candidate - baseline if candidate is not None and baseline is not None else None,
            }
        )
    return rows


def _logistic_coefficients(path: Path | None) -> dict[str, object]:
    if path is None or not path.exists():
        return {
            "status": "NOT_AVAILABLE",
            "reason": "The sanitized Dike evidence package does not include the blocked detector JSON artifact.",
            "interpretation_caveat": (
                "Coefficient tables require the saved detector JSON. Even with that file, weights are on standardized "
                "byte-frequency features, so direction is interpretable but magnitude depends on train-set scaling."
            ),
        }
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = [float(value) for value in payload.get("weights", [])]
    mean = [float(value) for value in payload.get("mean", [])]
    scale = [float(value) for value in payload.get("scale", [])]
    if len(weights) != 256:
        return {"status": "UNSUPPORTED", "reason": f"expected 256 weights, found {len(weights)}"}
    ordered = sorted(enumerate(weights), key=lambda item: item[1])
    return {
        "status": "PASS",
        "feature_count": len(weights),
        "top_benign_weighted_bins": [
            _coefficient_row(index, value, mean, scale) for index, value in ordered[:20]
        ],
        "top_malware_weighted_bins": [
            _coefficient_row(index, value, mean, scale) for index, value in reversed(ordered[-20:])
        ],
        "interpretation_caveat": (
            "Weights apply to standardized normalized byte-frequency bins. Positive weights move the logit toward "
            "the positive label stored in the detector; negative weights move it toward the negative label."
        ),
    }


def _coefficient_row(index: int, value: float, mean: list[float], scale: list[float]) -> dict[str, object]:
    return {
        "byte_bin": index,
        "hex": f"0x{index:02x}",
        "coefficient": value,
        "train_mean_frequency": mean[index] if index < len(mean) else None,
        "train_scale": scale[index] if index < len(scale) else None,
    }


def _write_outputs(output_dir: Path, tables: dict[str, Any]) -> None:
    (output_dir / "binaryshield_sanitized_evidence_tables.json").write_text(json.dumps(tables, indent=2), encoding="utf-8")
    for name, value in tables.items():
        if isinstance(value, list) and (not value or isinstance(value[0], dict)):
            _write_csv(output_dir / f"{name}.csv", value)
    (output_dir / "binaryshield_sanitized_evidence_tables.md").write_text(_to_markdown(tables), encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fieldnames = sorted({key for row in rows for key in row.keys()}) if rows else ["empty"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _to_markdown(tables: dict[str, Any]) -> str:
    lines = [
        "# BinaryShield Sanitized Evidence Tables",
        "",
        tables["claim_boundary"],
        "",
        "## Prediction Stability",
        "",
        _markdown_table(tables["prediction_stability"]),
        "",
        "## Attack Success Rate",
        "",
        _markdown_table(tables["attack_success_rate"]),
        "",
        "## Validation Coverage",
        "",
        _markdown_table(tables["validation_coverage"]),
        "",
        "## Accepted-vs-Baseline Deltas",
        "",
        _markdown_table(tables["accepted_vs_baseline_deltas"]),
        "",
        "## Logistic Coefficients",
        "",
        f"Status: `{tables['logistic_coefficients'].get('status')}`",
        "",
        tables["logistic_coefficients"].get("interpretation_caveat", ""),
        "",
    ]
    return "\n".join(lines)


def _markdown_table(rows: list[dict[str, object]]) -> str:
    if not rows:
        return "_No rows._"
    fieldnames = list(rows[0].keys())
    header = "| " + " | ".join(fieldnames) + " |"
    sep = "| " + " | ".join("---" for _ in fieldnames) + " |"
    body = ["| " + " | ".join(str(row.get(name, "")) for name in fieldnames) + " |" for row in rows]
    return "\n".join([header, sep, *body])


def _float(value: object) -> float | None:
    if value in (None, ""):
        return None
    return float(value)
