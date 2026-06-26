from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from binaryshield.validation import ValidationRecord


@dataclass(frozen=True)
class RobustnessCard:
    sample_id: str
    original_sha256: str | None
    transformed_sha256: str | None
    transformation_type: str
    validation_level: int
    allowed_for_evaluation: bool
    clean_prediction: str | None = None
    transformed_prediction: str | None = None
    clean_confidence: float | None = None
    transformed_confidence: float | None = None
    detector_name: str | None = None
    verdict: str = "not_evaluated"
    claim_boundary: str = (
        "Validated PE-preserving transformation; full behavior preservation is not claimed "
        "unless sandbox_execution_status is passed."
    )
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_markdown(self) -> str:
        rows = [
            ("Sample", self.sample_id),
            ("Detector", self.detector_name or "not evaluated"),
            ("Transformation", self.transformation_type),
            ("Validation level", str(self.validation_level)),
            ("Allowed for evaluation", str(self.allowed_for_evaluation)),
            ("Original SHA-256", self.original_sha256 or "unavailable"),
            ("Transformed SHA-256", self.transformed_sha256 or "unavailable"),
            ("Clean prediction", self.clean_prediction or "not evaluated"),
            ("Transformed prediction", self.transformed_prediction or "not evaluated"),
            ("Clean confidence", _fmt_confidence(self.clean_confidence)),
            ("Transformed confidence", _fmt_confidence(self.transformed_confidence)),
            ("Verdict", self.verdict),
        ]
        table = "\n".join(f"| {key} | {value} |" for key, value in rows)
        notes = "\n".join(f"- {note}" for note in self.notes) if self.notes else "- No additional notes."
        return (
            f"# Malware Robustness Card: {self.sample_id}\n\n"
            "| Field | Value |\n"
            "|---|---|\n"
            f"{table}\n\n"
            "## Claim Boundary\n\n"
            f"{self.claim_boundary}\n\n"
            "## Notes\n\n"
            f"{notes}\n"
        )


def _fmt_confidence(value: float | None) -> str:
    return "not evaluated" if value is None else f"{value:.4f}"


def card_from_validation(
    sample_id: str,
    validation: ValidationRecord,
    detector_name: str | None = None,
    clean_prediction: str | None = None,
    transformed_prediction: str | None = None,
    clean_confidence: float | None = None,
    transformed_confidence: float | None = None,
    notes: list[str] | None = None,
) -> RobustnessCard:
    if clean_prediction is None or transformed_prediction is None:
        verdict = "not_evaluated"
    elif clean_prediction == transformed_prediction and validation.allowed_for_evaluation:
        verdict = "detector_stable"
    elif validation.allowed_for_evaluation:
        verdict = "prediction_changed"
    else:
        verdict = "invalid_transformation"
    return RobustnessCard(
        sample_id=sample_id,
        original_sha256=validation.original_sha256,
        transformed_sha256=validation.transformed_sha256,
        transformation_type=validation.transformation_type,
        validation_level=validation.validation_level,
        allowed_for_evaluation=validation.allowed_for_evaluation,
        clean_prediction=clean_prediction,
        transformed_prediction=transformed_prediction,
        clean_confidence=clean_confidence,
        transformed_confidence=transformed_confidence,
        detector_name=detector_name,
        verdict=verdict,
        notes=notes or [],
    )


def write_robustness_card(card: RobustnessCard, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(card.to_dict(), indent=2), encoding="utf-8")
    else:
        path.write_text(card.to_markdown(), encoding="utf-8")
