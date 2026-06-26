from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


BOOLEAN_FIELDS = [
    "pe_parse_original",
    "pe_parse_transformed",
    "entry_point_unchanged",
    "section_count_valid",
    "executable_sections_unchanged",
    "allowed_for_evaluation",
]


def summarize_validation_records(
    validation_dir: str | Path,
    *,
    expected_count: int | None = None,
) -> dict[str, Any]:
    root = Path(validation_dir)
    records = []
    for path in sorted(root.rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        data["_path"] = str(path)
        records.append(data)
    transformation_types = sorted({str(record.get("transformation_type", "")) for record in records if record})
    summary: dict[str, Any] = {
        "validation_dir": str(root),
        "validation_json_count": len(records),
        "expected_count": expected_count,
        "validation_json_generation_rate": (
            len(records) / expected_count if expected_count and expected_count > 0 else None
        ),
        "transformation_types": transformation_types,
        "overall": _summarize_records(records),
        "by_transformation": {},
        "claim_boundary": (
            "Validation summary covers structural PE-preservation records only. "
            "It does not prove runtime behavior preservation without sandbox evidence."
        ),
    }
    for transformation_type in transformation_types:
        subset = [record for record in records if record.get("transformation_type") == transformation_type]
        summary["by_transformation"][transformation_type] = _summarize_records(subset)
    return summary


def write_validation_summary(summary: dict[str, Any], output_dir: str | Path) -> None:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "transformation_validation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (root / "transformation_validation_summary.md").write_text(to_markdown(summary), encoding="utf-8")
    rows = []
    for transformation_type, metrics in summary.get("by_transformation", {}).items():
        rows.append({"scope": transformation_type, **metrics})
    rows.append({"scope": "overall", **summary.get("overall", {})})
    with (root / "transformation_validation_summary.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = sorted({key for row in rows for key in row}) if rows else ["scope"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(summary: dict[str, Any]) -> str:
    rows = []
    for transformation_type, metrics in summary.get("by_transformation", {}).items():
        rows.append(_markdown_row(transformation_type, metrics))
    rows.append(_markdown_row("overall", summary.get("overall", {})))
    return (
        "# BinaryShield Transformation Validation Summary\n\n"
        f"**Validation JSON count:** {summary.get('validation_json_count')}\n\n"
        f"**Expected count:** {summary.get('expected_count')}\n\n"
        f"**Validation JSON generation rate:** {summary.get('validation_json_generation_rate')}\n\n"
        "| Scope | Records | Transformed PE Parse | Entry Point Unchanged | Executable Sections Unchanged | Allowed For Evaluation |\n"
        "|---|---:|---:|---:|---:|---:|\n"
        + "\n".join(rows)
        + "\n\n## Claim Boundary\n\n"
        + str(summary.get("claim_boundary", ""))
        + "\n"
    )


def _summarize_records(records: list[dict[str, Any]]) -> dict[str, float]:
    total = max(len(records), 1)
    metrics: dict[str, float] = {"record_count": float(len(records))}
    for field in BOOLEAN_FIELDS:
        metrics[f"{field}_rate"] = sum(bool(record.get(field)) for record in records) / total
    levels = [int(record.get("validation_level", 0)) for record in records]
    metrics["level2_or_higher_rate"] = sum(level >= 2 for level in levels) / total
    metrics["level3_rate"] = sum(level >= 3 for level in levels) / total
    return metrics


def _markdown_row(scope: str, metrics: dict[str, Any]) -> str:
    return (
        f"| {scope} | {metrics.get('record_count')} | "
        f"{metrics.get('pe_parse_transformed_rate')} | "
        f"{metrics.get('entry_point_unchanged_rate')} | "
        f"{metrics.get('executable_sections_unchanged_rate')} | "
        f"{metrics.get('allowed_for_evaluation_rate')} |"
    )
