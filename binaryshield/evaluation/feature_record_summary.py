from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FeatureRecordGate:
    name: str
    status: str
    observed: float | str | None
    target: str
    evidence: str | None
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_feature_record_gate_report(
    *,
    candidate_metrics_path: str | Path,
    baseline_metrics_path: str | Path | None = None,
    candidate_summary_path: str | Path | None = None,
    min_accuracy: float = 0.90,
    min_macro_f1: float = 0.90,
    min_worst_class_f1: float = 0.85,
    min_benign_f1: float = 0.90,
    min_malware_f1: float = 0.90,
    min_baseline_metrics_beaten: int = 3,
) -> dict[str, Any]:
    candidate_metrics = _load_json(candidate_metrics_path)
    baseline_metrics = _load_json(baseline_metrics_path) if baseline_metrics_path else None
    candidate_summary = _load_json(candidate_summary_path) if candidate_summary_path else None

    gates = [
        _threshold_gate(
            "Candidate clean accuracy",
            candidate_metrics,
            "accuracy",
            min_accuracy,
            candidate_metrics_path,
        ),
        _threshold_gate(
            "Candidate clean macro F1",
            candidate_metrics,
            "macro_f1",
            min_macro_f1,
            candidate_metrics_path,
        ),
        _threshold_gate(
            "Candidate worst-class F1",
            candidate_metrics,
            "worst_class_f1",
            min_worst_class_f1,
            candidate_metrics_path,
        ),
        _threshold_gate(
            "Candidate benign F1",
            candidate_metrics,
            "benign_f1",
            min_benign_f1,
            candidate_metrics_path,
        ),
        _threshold_gate(
            "Candidate malware F1",
            candidate_metrics,
            "malware_f1",
            min_malware_f1,
            candidate_metrics_path,
        ),
        _baseline_improvement_gate(
            candidate_metrics,
            baseline_metrics,
            baseline_metrics_path,
            min_baseline_metrics_beaten,
        ),
        FeatureRecordGate(
            "Raw PE transformation robustness",
            "NOT_APPLICABLE",
            "feature-vector track",
            "raw PE binaries required",
            str(candidate_summary_path) if candidate_summary_path else None,
            "The public BODMAS feature-vector release does not contain original PE binaries.",
        ),
        FeatureRecordGate(
            "Behavior preservation",
            "NOT_VALIDATED",
            None,
            "Level 3 sandbox evidence required",
            None,
            "Feature-vector classification cannot validate executable behavior preservation.",
        ),
    ]

    hard_gates = [gate for gate in gates if gate.status != "NOT_APPLICABLE"]
    if any(gate.status == "FAIL" for gate in hard_gates):
        overall_status = "FAIL"
    elif any(gate.status == "NOT_VALIDATED" for gate in hard_gates):
        overall_status = "PARTIAL_PASS"
    else:
        overall_status = "PASS"

    return {
        "overall_status": overall_status,
        "scope": "Public BODMAS PE-derived feature-vector clean classification.",
        "candidate_metrics": candidate_metrics,
        "baseline_metrics": baseline_metrics,
        "candidate_summary": candidate_summary,
        "gates": [gate.to_dict() for gate in gates],
        "claim_boundary": (
            "This report validates clean malware/benign classification on public BODMAS "
            "PE-derived feature vectors only. It does not validate raw PE transformation "
            "robustness, transfer robustness, CAR-FP-MalAT effectiveness, or malware "
            "behavior preservation."
        ),
    }


def write_feature_record_gate_report(report: dict[str, Any], output_dir: str | Path) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "feature_record_gate_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (root / "feature_record_gate_report.md").write_text(feature_record_report_to_markdown(report), encoding="utf-8")
    with (root / "feature_record_gate_rows.csv").open("w", encoding="utf-8", newline="") as handle:
        rows = list(report.get("gates", []))
        fieldnames = ["name", "status", "observed", "target", "evidence", "note"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def feature_record_report_to_markdown(report: dict[str, Any]) -> str:
    gates = list(report.get("gates", []))
    rows = "\n".join(
        "| {name} | {status} | {observed} | {target} | {note} |".format(
            name=_cell(gate.get("name")),
            status=_cell(gate.get("status")),
            observed=_format_observed(gate.get("observed")),
            target=_cell(gate.get("target")),
            note=_cell(gate.get("note")),
        )
        for gate in gates
    )
    candidate = report.get("candidate_metrics") or {}
    baseline = report.get("baseline_metrics") or {}
    return (
        "# BODMAS Feature-Record Gate Report\n\n"
        f"**Overall status:** `{report.get('overall_status')}`\n\n"
        f"**Scope:** {report.get('scope')}\n\n"
        "## Candidate Test Metrics\n\n"
        "| Metric | Candidate | Baseline |\n"
        "|---|---:|---:|\n"
        f"| Accuracy | {_pct(candidate.get('accuracy'))} | {_pct(baseline.get('accuracy'))} |\n"
        f"| Macro F1 | {_pct(candidate.get('macro_f1'))} | {_pct(baseline.get('macro_f1'))} |\n"
        f"| Worst-class F1 | {_pct(candidate.get('worst_class_f1'))} | {_pct(baseline.get('worst_class_f1'))} |\n"
        f"| Benign F1 | {_pct(candidate.get('benign_f1'))} | {_pct(baseline.get('benign_f1'))} |\n"
        f"| Malware F1 | {_pct(candidate.get('malware_f1'))} | {_pct(baseline.get('malware_f1'))} |\n\n"
        "## Gates\n\n"
        "| Gate | Status | Observed | Target | Note |\n"
        "|---|---|---:|---|---|\n"
        f"{rows}\n\n"
        "## Claim Boundary\n\n"
        f"{report.get('claim_boundary')}\n"
    )


def _load_json(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _threshold_gate(
    name: str,
    metrics: dict[str, Any],
    key: str,
    threshold: float,
    evidence: str | Path,
) -> FeatureRecordGate:
    if key not in metrics:
        return FeatureRecordGate(name, "NOT_VALIDATED", None, f">= {threshold:.2f}", str(evidence), f"Missing `{key}`.")
    observed = float(metrics[key])
    return FeatureRecordGate(
        name,
        "PASS" if observed >= threshold else "FAIL",
        observed,
        f">= {threshold:.2f}",
        str(evidence),
    )


def _baseline_improvement_gate(
    candidate: dict[str, Any],
    baseline: dict[str, Any] | None,
    evidence: str | Path | None,
    min_metrics_beaten: int,
) -> FeatureRecordGate:
    if not baseline:
        return FeatureRecordGate(
            "Candidate beats feature baseline",
            "NOT_VALIDATED",
            None,
            f">= {min_metrics_beaten} metrics",
            str(evidence) if evidence else None,
            "Missing baseline metrics.",
        )
    metric_names = ["accuracy", "macro_f1", "worst_class_f1", "benign_f1", "malware_f1"]
    beaten = sum(float(candidate.get(name, 0.0)) > float(baseline.get(name, 0.0)) for name in metric_names)
    return FeatureRecordGate(
        "Candidate beats feature baseline",
        "PASS" if beaten >= min_metrics_beaten else "FAIL",
        float(beaten),
        f">= {min_metrics_beaten} metrics",
        str(evidence) if evidence else None,
        "Compared accuracy, macro F1, worst-class F1, benign F1, and malware F1.",
    )


def _pct(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value) * 100:.2f}%"


def _format_observed(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    if value is None:
        return ""
    return _cell(value)


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|")
