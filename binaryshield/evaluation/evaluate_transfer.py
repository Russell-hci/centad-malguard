from __future__ import annotations

from pathlib import Path

from binaryshield.datasets import BinarySample
from binaryshield.evaluation.evaluate_transformations import (
    Detector,
    TransformationEvaluationConfig,
    evaluate_detector_under_transformation,
)


def evaluate_transfer_matrix(
    detectors: list[Detector],
    samples: list[BinarySample],
    output_dir: str | Path,
    transformations: list[str] | None = None,
    target: str = "label",
) -> dict[str, dict[str, dict[str, float]]]:
    """Evaluate all detectors under each transformation family.

    This provides the framework-level generalizability evidence: the same validated
    PE transformations are tested against multiple detector families.
    """

    transformations = transformations or ["append_overlay", "section_slack"]
    root = Path(output_dir)
    matrix: dict[str, dict[str, dict[str, float]]] = {}
    for transformation in transformations:
        matrix[transformation] = {}
        for detector in detectors:
            config = TransformationEvaluationConfig(
                output_dir=root / detector.detector_name,
                transformation=transformation,
                target=target,
            )
            try:
                matrix[transformation][detector.detector_name] = evaluate_detector_under_transformation(
                    detector, samples, config
                )
            except ValueError as exc:
                matrix[transformation][detector.detector_name] = {"error": str(exc)}  # type: ignore[dict-item]
    return matrix
