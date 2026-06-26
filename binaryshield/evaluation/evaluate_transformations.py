from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from binaryshield.datasets import BinarySample
from binaryshield.evaluation.metrics import robustness_summary
from binaryshield.robustness_card import card_from_validation, write_robustness_card
from binaryshield.transformations import append_overlay, mutate_slack_space
from binaryshield.validation import validate_transformation


class Detector(Protocol):
    detector_name: str

    def predict(self, paths: list[str | Path]) -> list[str]:
        ...


@dataclass(frozen=True)
class TransformationEvaluationConfig:
    output_dir: Path
    transformation: str = "append_overlay"
    payload_size: int = 1024
    seed: int = 1337
    target: str = "label"


@dataclass(frozen=True)
class _EvaluatedArtifact:
    sample: BinarySample
    clean_path: Path
    transformed_path: Path
    target: str
    validation_json_path: Path


def _apply_transformation(sample: BinarySample, config: TransformationEvaluationConfig):
    output_path = config.output_dir / "transformed" / config.transformation / f"{sample.sample_id}.bin"
    if config.transformation == "append_overlay":
        return append_overlay(sample.path, output_path, payload_size=config.payload_size, seed=config.seed)
    if config.transformation == "section_slack":
        return mutate_slack_space(sample.path, output_path, max_bytes=config.payload_size, seed=config.seed)
    raise ValueError(f"unsupported transformation: {config.transformation}")


def evaluate_detector_under_transformation(
    detector: Detector,
    samples: list[BinarySample],
    config: TransformationEvaluationConfig,
) -> dict[str, float]:
    config.output_dir.mkdir(parents=True, exist_ok=True)
    predictions_rows: list[dict[str, object]] = []
    artifacts: list[_EvaluatedArtifact] = []

    for sample in samples:
        try:
            result = _apply_transformation(sample, config)
            validation_path = config.output_dir / "validation" / config.transformation / f"{sample.sample_id}.json"
            validation = validate_transformation(result, validation_path)
            if not validation.allowed_for_evaluation:
                continue
            artifacts.append(
                _EvaluatedArtifact(
                    sample=sample,
                    clean_path=sample.path,
                    transformed_path=Path(result.transformed_path),
                    target=_sample_target(sample, config.target),
                    validation_json_path=validation_path,
                )
            )
        except Exception as exc:  # noqa: BLE001 - record failed samples for audit traceability
            predictions_rows.append(
                {
                    "sample_id": sample.sample_id,
                    "label": sample.label,
                    "family": sample.family or "",
                    "error": str(exc),
                }
            )

    clean_paths = [artifact.clean_path for artifact in artifacts]
    transformed_paths = [artifact.transformed_path for artifact in artifacts]
    targets = [artifact.target for artifact in artifacts]
    clean_predictions = detector.predict(clean_paths) if clean_paths else []
    transformed_predictions = detector.predict(transformed_paths) if transformed_paths else []
    labels = sorted(set(targets) | set(clean_predictions) | set(transformed_predictions))
    metrics = robustness_summary(clean_predictions, transformed_predictions, targets, labels)
    metrics["evaluated_samples"] = float(len(targets))

    for artifact, clean_pred, transformed_pred in zip(
        artifacts,
        clean_predictions,
        transformed_predictions,
        strict=False,
    ):
        validation = json.loads(artifact.validation_json_path.read_text(encoding="utf-8"))
        card = card_from_validation(
            sample_id=artifact.sample.sample_id,
            validation=_validation_from_dict(validation),
            detector_name=detector.detector_name,
            clean_prediction=clean_pred,
            transformed_prediction=transformed_pred,
            notes=["Generated during BinaryShield transformation robustness evaluation."],
        )
        write_robustness_card(card, config.output_dir / "cards" / config.transformation / f"{artifact.sample.sample_id}.md")
        predictions_rows.append(
            {
                "sample_id": artifact.sample.sample_id,
                "label": artifact.sample.label,
                "family": artifact.sample.family or "",
                "target": artifact.target,
                "clean_path": str(artifact.clean_path),
                "transformed_path": str(artifact.transformed_path),
                "clean_prediction": clean_pred,
                "transformed_prediction": transformed_pred,
                "prediction_stable": clean_pred == transformed_pred,
                "attack_success": clean_pred == artifact.target and transformed_pred != artifact.target,
                "error": "",
            }
        )

    metrics_path = config.output_dir / f"metrics_{detector.detector_name}_{config.transformation}.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    predictions_path = config.output_dir / f"predictions_{detector.detector_name}_{config.transformation}.csv"
    with predictions_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = sorted({key for row in predictions_rows for key in row.keys()}) if predictions_rows else ["sample_id"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(predictions_rows)
    return metrics


def _sample_target(sample: BinarySample, target: str) -> str:
    if target == "label":
        return sample.label
    if target == "family":
        return sample.family or sample.label
    raise ValueError(f"unsupported target: {target}")


def _validation_from_dict(data: dict[str, object]):
    from binaryshield.validation import ValidationRecord

    return ValidationRecord(
        original_sha256=data.get("original_sha256"),  # type: ignore[arg-type]
        transformed_sha256=data.get("transformed_sha256"),  # type: ignore[arg-type]
        hash_changed=bool(data.get("hash_changed")),
        pe_parse_original=bool(data.get("pe_parse_original")),
        pe_parse_transformed=bool(data.get("pe_parse_transformed")),
        entry_point_unchanged=bool(data.get("entry_point_unchanged")),
        section_count_valid=bool(data.get("section_count_valid")),
        executable_sections_unchanged=bool(data.get("executable_sections_unchanged")),
        transformation_type=str(data.get("transformation_type")),
        bytes_added_or_modified=int(data.get("bytes_added_or_modified", 0)),
        modified_ranges=[tuple(item) for item in data.get("modified_ranges", [])],  # type: ignore[arg-type]
        validation_level=int(data.get("validation_level", 0)),
        label_preservation_assumption=str(data.get("label_preservation_assumption", "")),
        sandbox_execution_status=str(data.get("sandbox_execution_status", "not_attempted")),
        allowed_for_evaluation=bool(data.get("allowed_for_evaluation")),
        errors=[str(item) for item in data.get("errors", [])],  # type: ignore[arg-type]
    )
