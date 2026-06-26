from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

from binaryshield.datasets import BinarySample
from binaryshield.evaluation.evaluate_transformations import Detector
from binaryshield.evaluation.metrics import robustness_summary
from binaryshield.robustness_card import card_from_validation, write_robustness_card
from binaryshield.transformations import append_overlay, mutate_slack_space
from binaryshield.validation import ValidationRecord, validate_transformation


@dataclass(frozen=True)
class TransferAttackConfig:
    output_dir: Path
    transformation: str = "append_overlay"
    n: int = 5
    payload_size: int = 1024
    seed: int = 1337
    target: str = "label"


@dataclass(frozen=True)
class _SelectedTransformation:
    sample: BinarySample
    clean_path: Path
    transformed_path: Path
    target: str
    validation: ValidationRecord
    seed: int
    source_clean_prediction: str
    source_transformed_prediction: str
    selection_reason: str


def evaluate_transfer_attack(
    source_detector: Detector,
    target_detectors: list[Detector],
    samples: list[BinarySample],
    config: TransferAttackConfig,
) -> dict[str, dict[str, float]]:
    """Select transformations against one detector and test them on all detectors.

    This is the transferability evidence requested by the BinaryShield plan:
    the transformed file is generated once using the source detector's response,
    then reused for the target detectors.
    """

    if config.n <= 0:
        raise ValueError("config.n must be positive")
    config.output_dir.mkdir(parents=True, exist_ok=True)
    selected = [
        item
        for sample in samples
        if (item := _select_for_sample(source_detector, sample, config)) is not None
    ]
    _write_selection_rows(selected, config.output_dir / "selected_transformations.csv")
    detectors = _dedupe_detectors([source_detector, *target_detectors])
    matrix: dict[str, dict[str, float]] = {}
    for detector in detectors:
        metrics = _evaluate_detector(detector, selected, config)
        matrix[detector.detector_name] = metrics
    (config.output_dir / "transfer_attack_matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    return matrix


def _select_for_sample(
    source_detector: Detector,
    sample: BinarySample,
    config: TransferAttackConfig,
) -> _SelectedTransformation | None:
    target = _sample_target(sample, config.target)
    clean_prediction = source_detector.predict([sample.path])[0]
    candidates: list[_SelectedTransformation] = []
    for offset in range(config.n):
        seed = config.seed + offset
        try:
            transformed_path = (
                config.output_dir
                / "selected_by_source"
                / source_detector.detector_name
                / config.transformation
                / f"{sample.sample_id}_seed{seed}.bin"
            )
            result = _apply(sample.path, transformed_path, config.transformation, config.payload_size, seed)
            validation_path = (
                config.output_dir
                / "validation"
                / source_detector.detector_name
                / config.transformation
                / f"{sample.sample_id}_seed{seed}.json"
            )
            validation = validate_transformation(result, validation_path)
            if not validation.allowed_for_evaluation:
                continue
            transformed_prediction = source_detector.predict([transformed_path])[0]
            reason = _selection_reason(clean_prediction, transformed_prediction, target)
            candidates.append(
                _SelectedTransformation(
                    sample=sample,
                    clean_path=sample.path,
                    transformed_path=transformed_path,
                    target=target,
                    validation=validation,
                    seed=seed,
                    source_clean_prediction=clean_prediction,
                    source_transformed_prediction=transformed_prediction,
                    selection_reason=reason,
                )
            )
            if reason == "source_attack_success":
                break
        except Exception:
            continue
    if not candidates:
        return None
    return min(candidates, key=lambda item: _selection_rank(item.selection_reason))


def _evaluate_detector(
    detector: Detector,
    selected: list[_SelectedTransformation],
    config: TransferAttackConfig,
) -> dict[str, float]:
    clean_paths = [item.clean_path for item in selected]
    transformed_paths = [item.transformed_path for item in selected]
    targets = [item.target for item in selected]
    clean_predictions = detector.predict(clean_paths) if clean_paths else []
    transformed_predictions = detector.predict(transformed_paths) if transformed_paths else []
    labels = sorted(set(targets) | set(clean_predictions) | set(transformed_predictions))
    metrics = robustness_summary(clean_predictions, transformed_predictions, targets, labels)
    metrics["evaluated_samples"] = float(len(selected))
    metrics_path = config.output_dir / f"metrics_{detector.detector_name}_{config.transformation}_transfer_attack.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _write_prediction_rows(
        detector,
        selected,
        clean_predictions,
        transformed_predictions,
        config.output_dir / f"predictions_{detector.detector_name}_{config.transformation}_transfer_attack.csv",
    )
    for item, clean_prediction, transformed_prediction in zip(
        selected,
        clean_predictions,
        transformed_predictions,
        strict=False,
    ):
        card = card_from_validation(
            sample_id=item.sample.sample_id,
            validation=item.validation,
            detector_name=detector.detector_name,
            clean_prediction=clean_prediction,
            transformed_prediction=transformed_prediction,
            notes=[
                f"Transformation selected against source detector: {item.source_clean_prediction} -> {item.source_transformed_prediction}.",
                f"Selection reason: {item.selection_reason}.",
            ],
        )
        write_robustness_card(
            card,
            config.output_dir / "cards" / detector.detector_name / config.transformation / f"{item.sample.sample_id}.md",
        )
    return metrics


def _apply(input_path: Path, output_path: Path, transformation: str, payload_size: int, seed: int):
    if transformation == "append_overlay":
        return append_overlay(input_path, output_path, payload_size=payload_size, seed=seed)
    if transformation == "section_slack":
        return mutate_slack_space(input_path, output_path, max_bytes=payload_size, seed=seed)
    raise ValueError(f"unsupported transformation: {transformation}")


def _selection_reason(clean_prediction: str, transformed_prediction: str, target: str) -> str:
    if clean_prediction == target and transformed_prediction != target:
        return "source_attack_success"
    if transformed_prediction != clean_prediction:
        return "source_prediction_changed"
    return "source_prediction_stable"


def _selection_rank(reason: str) -> int:
    return {
        "source_attack_success": 0,
        "source_prediction_changed": 1,
        "source_prediction_stable": 2,
    }.get(reason, 99)


def _sample_target(sample: BinarySample, target: str) -> str:
    if target == "label":
        return sample.label
    if target == "family":
        return sample.family or sample.label
    raise ValueError(f"unsupported target: {target}")


def _dedupe_detectors(detectors: list[Detector]) -> list[Detector]:
    seen = set()
    result = []
    for detector in detectors:
        if detector.detector_name in seen:
            continue
        seen.add(detector.detector_name)
        result.append(detector)
    return result


def _write_selection_rows(selected: list[_SelectedTransformation], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "sample_id": item.sample.sample_id,
            "target": item.target,
            "clean_path": str(item.clean_path),
            "transformed_path": str(item.transformed_path),
            "seed": item.seed,
            "source_clean_prediction": item.source_clean_prediction,
            "source_transformed_prediction": item.source_transformed_prediction,
            "selection_reason": item.selection_reason,
            "validation_level": item.validation.validation_level,
            "allowed_for_evaluation": item.validation.allowed_for_evaluation,
        }
        for item in selected
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = rows[0].keys() if rows else ["sample_id"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_prediction_rows(
    detector: Detector,
    selected: list[_SelectedTransformation],
    clean_predictions: list[str],
    transformed_predictions: list[str],
    output_path: Path,
) -> None:
    rows = [
        {
            "sample_id": item.sample.sample_id,
            "detector": detector.detector_name,
            "target": item.target,
            "clean_prediction": clean_prediction,
            "transformed_prediction": transformed_prediction,
            "prediction_stable": clean_prediction == transformed_prediction,
            "attack_success": clean_prediction == item.target and transformed_prediction != item.target,
            "source_selection_reason": item.selection_reason,
        }
        for item, clean_prediction, transformed_prediction in zip(
            selected,
            clean_predictions,
            transformed_predictions,
            strict=False,
        )
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = rows[0].keys() if rows else ["sample_id"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
