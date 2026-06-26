from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class GateResult:
    name: str
    status: str
    observed: float | str | None
    target: str
    evidence: str | None
    note: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AcceptanceReport:
    overall_status: str
    gates: list[GateResult]
    claim_boundary: str

    def to_dict(self) -> dict[str, object]:
        return {
            "overall_status": self.overall_status,
            "gates": [gate.to_dict() for gate in self.gates],
            "claim_boundary": self.claim_boundary,
        }

    def to_markdown(self) -> str:
        rows = "\n".join(
            f"| {gate.name} | {gate.status} | {gate.observed} | {gate.target} | {gate.evidence or ''} |"
            for gate in self.gates
        )
        return (
            "# BinaryShield Acceptance Report\n\n"
            f"**Overall status:** {self.overall_status}\n\n"
            "| Gate | Status | Observed | Target | Evidence |\n"
            "|---|---|---:|---:|---|\n"
            f"{rows}\n\n"
            "## Claim Boundary\n\n"
            f"{self.claim_boundary}\n"
        )


def build_acceptance_report(
    validation_summary_path: str | Path | None = None,
    append_metrics_path: str | Path | None = None,
    slack_metrics_path: str | Path | None = None,
    append_validation_summary_path: str | Path | None = None,
    slack_validation_summary_path: str | Path | None = None,
    append_card_summary_path: str | Path | None = None,
    slack_card_summary_path: str | Path | None = None,
    transfer_matrix_path: str | Path | None = None,
    multi_detector_summary_path: str | Path | None = None,
    detector_count: int | None = None,
) -> AcceptanceReport:
    gates: list[GateResult] = []
    validation = _load_json(validation_summary_path)
    append_metrics = _load_json(append_metrics_path)
    slack_metrics = _load_json(slack_metrics_path)
    append_validation = _load_json(append_validation_summary_path)
    slack_validation = _load_json(slack_validation_summary_path)
    append_cards = _load_json(append_card_summary_path)
    slack_cards = _load_json(slack_card_summary_path)
    transfer_matrix = _load_json(transfer_matrix_path)
    multi_detector_summary = _load_json(multi_detector_summary_path)

    gates.append(_threshold_gate("PE parse success", validation, "pe_parse_success_rate", 0.95, validation_summary_path))
    gates.append(
        _threshold_gate(
            "Feature extraction success",
            validation,
            "feature_extraction_success_rate",
            0.95,
            validation_summary_path,
        )
    )
    gates.append(_threshold_gate("Append prediction stability", append_metrics, "prediction_stability", 0.85, append_metrics_path))
    gates.append(_threshold_gate("Append transformed F1", append_metrics, "transformed_macro_f1", 0.85, append_metrics_path))
    gates.append(_max_gate("Append attack success rate", append_metrics, "attack_success_rate", 0.70, append_metrics_path))
    gates.extend(_transformation_validation_gates("Append", append_validation, append_validation_summary_path, parse_threshold=0.98))
    gates.append(_card_coverage_gate("Append Robustness Card coverage", append_cards, append_card_summary_path))
    gates.append(_threshold_gate("Slack transformed F1", slack_metrics, "transformed_macro_f1", 0.70, slack_metrics_path))
    gates.extend(_transformation_validation_gates("Slack", slack_validation, slack_validation_summary_path, parse_threshold=0.90))
    gates.append(_card_coverage_gate("Slack Robustness Card coverage", slack_cards, slack_card_summary_path))
    gates.append(_detector_gate(detector_count, transfer_matrix, transfer_matrix_path, multi_detector_summary))
    gates.append(_transfer_gate(transfer_matrix, transfer_matrix_path))
    gates.append(_candidate_improvement_gate(multi_detector_summary, multi_detector_summary_path))

    if any(gate.status == "FAIL" for gate in gates):
        overall = "FAIL"
    elif any(gate.status == "NOT_VALIDATED" for gate in gates):
        overall = "NOT_VALIDATED"
    else:
        overall = "PASS"
    return AcceptanceReport(
        overall_status=overall,
        gates=gates,
        claim_boundary=(
            "PASS means the supplied artifacts satisfy BinaryShield's configured gates. "
            "It does not imply full malware behavior preservation without Level 3 sandbox evidence."
        ),
    )


def _load_json(path: str | Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    file_path = Path(path)
    if not file_path.exists():
        return None
    return json.loads(file_path.read_text(encoding="utf-8"))


def _threshold_gate(
    name: str,
    data: dict[str, object] | None,
    key: str,
    threshold: float,
    evidence: str | Path | None,
) -> GateResult:
    if data is None or key not in data:
        return GateResult(name, "NOT_VALIDATED", None, f">= {threshold:.2f}", str(evidence) if evidence else None, "Missing artifact or metric.")
    observed = float(data[key])
    return GateResult(
        name,
        "PASS" if observed >= threshold else "FAIL",
        observed,
        f">= {threshold:.2f}",
        str(evidence) if evidence else None,
        "",
    )


def _max_gate(
    name: str,
    data: dict[str, object] | None,
    key: str,
    maximum: float,
    evidence: str | Path | None,
) -> GateResult:
    if data is None or key not in data:
        return GateResult(name, "NOT_VALIDATED", None, f"<= {maximum:.2f}", str(evidence) if evidence else None, "Missing artifact or metric.")
    observed = float(data[key])
    return GateResult(
        name,
        "PASS" if observed <= maximum else "FAIL",
        observed,
        f"<= {maximum:.2f}",
        str(evidence) if evidence else None,
        "",
    )


def _detector_gate(
    detector_count: int | None,
    transfer_matrix: dict[str, object] | None,
    evidence: str | Path | None,
    multi_detector_summary: dict[str, object] | None = None,
) -> GateResult:
    observed = detector_count
    if observed is None and multi_detector_summary and "detector_count" in multi_detector_summary:
        observed = int(multi_detector_summary["detector_count"])
    if observed is None and transfer_matrix:
        names: set[str] = set()
        for value in transfer_matrix.values():
            if isinstance(value, dict):
                names.update(str(name) for name in value)
        observed = len(names)
    if observed is None:
        return GateResult("Multiple detector families", "NOT_VALIDATED", None, ">= 2", str(evidence) if evidence else None, "Missing detector count.")
    return GateResult(
        "Multiple detector families",
        "PASS" if observed >= 2 else "FAIL",
        float(observed),
        ">= 2",
        str(evidence) if evidence else None,
        "",
    )


def _transfer_gate(transfer_matrix: dict[str, object] | None, evidence: str | Path | None) -> GateResult:
    if not transfer_matrix:
        return GateResult("Transfer-style evaluation", "NOT_VALIDATED", None, "matrix present", str(evidence) if evidence else None, "Missing transfer matrix.")
    transformation_count = len(transfer_matrix)
    return GateResult(
        "Transfer-style evaluation",
        "PASS" if transformation_count >= 1 else "FAIL",
        float(transformation_count),
        ">= 1 transformation",
        str(evidence) if evidence else None,
        "",
    )


def _candidate_improvement_gate(
    multi_detector_summary: dict[str, object] | None,
    evidence: str | Path | None,
) -> GateResult:
    if not multi_detector_summary:
        return GateResult(
            "Candidate beats strongest baseline",
            "NOT_VALIDATED",
            None,
            ">= 2 robustness metrics",
            str(evidence) if evidence else None,
            "Missing multi-detector summary.",
        )
    comparison = multi_detector_summary.get("candidate_comparison")
    if not isinstance(comparison, dict):
        return GateResult(
            "Candidate beats strongest baseline",
            "NOT_VALIDATED",
            None,
            ">= 2 robustness metrics",
            str(evidence) if evidence else None,
            "Missing candidate comparison.",
        )
    observed = float(comparison.get("metrics_beaten", 0))
    status = str(comparison.get("status", "FAIL"))
    return GateResult(
        "Candidate beats strongest baseline",
        "PASS" if status == "PASS" and observed >= 2 else "FAIL",
        observed,
        ">= 2 robustness metrics",
        str(evidence) if evidence else None,
        "",
    )


def _transformation_validation_gates(
    prefix: str,
    summary: dict[str, object] | None,
    evidence: str | Path | None,
    *,
    parse_threshold: float,
) -> list[GateResult]:
    if not summary:
        return [
            GateResult(
                f"{prefix} validation JSON generation",
                "NOT_VALIDATED",
                None,
                ">= 1.00",
                str(evidence) if evidence else None,
                "Missing transformation validation summary.",
            ),
            GateResult(
                f"{prefix} transformed PE parse success",
                "NOT_VALIDATED",
                None,
                f">= {parse_threshold:.2f}",
                str(evidence) if evidence else None,
                "Missing transformation validation summary.",
            ),
            GateResult(
                f"{prefix} entry point unchanged",
                "NOT_VALIDATED",
                None,
                ">= 1.00",
                str(evidence) if evidence else None,
                "Missing transformation validation summary.",
            ),
            GateResult(
                f"{prefix} executable sections unchanged",
                "NOT_VALIDATED",
                None,
                ">= 1.00",
                str(evidence) if evidence else None,
                "Missing transformation validation summary.",
            ),
        ]
    overall = summary.get("overall")
    if not isinstance(overall, dict):
        overall = {}
    return [
        _summary_threshold_gate(
            f"{prefix} validation JSON generation",
            summary,
            "validation_json_generation_rate",
            1.0,
            evidence,
        ),
        _summary_threshold_gate(
            f"{prefix} transformed PE parse success",
            overall,
            "pe_parse_transformed_rate",
            parse_threshold,
            evidence,
        ),
        _summary_threshold_gate(
            f"{prefix} entry point unchanged",
            overall,
            "entry_point_unchanged_rate",
            1.0,
            evidence,
        ),
        _summary_threshold_gate(
            f"{prefix} executable sections unchanged",
            overall,
            "executable_sections_unchanged_rate",
            1.0,
            evidence,
        ),
    ]


def _summary_threshold_gate(
    name: str,
    data: dict[str, object],
    key: str,
    threshold: float,
    evidence: str | Path | None,
) -> GateResult:
    if key not in data or data[key] is None:
        return GateResult(
            name,
            "NOT_VALIDATED",
            None,
            f">= {threshold:.2f}",
            str(evidence) if evidence else None,
            "Missing summary metric.",
        )
    observed = float(data[key])
    return GateResult(
        name,
        "PASS" if observed >= threshold else "FAIL",
        observed,
        f">= {threshold:.2f}",
        str(evidence) if evidence else None,
        "",
    )


def _card_coverage_gate(
    name: str,
    summary: dict[str, object] | None,
    evidence: str | Path | None,
) -> GateResult:
    if not summary:
        return GateResult(
            name,
            "NOT_VALIDATED",
            None,
            ">= 1.00",
            str(evidence) if evidence else None,
            "Missing Robustness Card summary.",
        )
    if summary.get("card_generation_rate") is None:
        return GateResult(
            name,
            "NOT_VALIDATED",
            None,
            ">= 1.00",
            str(evidence) if evidence else None,
            "Missing expected card count.",
        )
    observed = float(summary["card_generation_rate"])
    return GateResult(
        name,
        "PASS" if observed >= 1.0 else "FAIL",
        observed,
        ">= 1.00",
        str(evidence) if evidence else None,
        "",
    )
