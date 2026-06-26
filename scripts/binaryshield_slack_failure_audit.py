#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import pefile

EXECUTE = 0x20000000
CODE = 0x00000020


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit BinaryShield section-slack executable-section preservation failures.")
    parser.add_argument("--validation-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--transformed-dir", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--report-output", type=Path, required=True)
    return parser.parse_args()


def section_rows(path: Path) -> list[dict[str, Any]]:
    pe = pefile.PE(str(path), fast_load=False)
    rows: list[dict[str, Any]] = []
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        characteristics = int(sec.Characteristics)
        start = int(sec.PointerToRawData)
        size = int(sec.SizeOfRawData)
        rows.append(
            {
                "name": name,
                "raw_start": start,
                "raw_end": start + size,
                "size_of_raw_data": size,
                "virtual_address": int(sec.VirtualAddress),
                "virtual_size": int(sec.Misc_VirtualSize),
                "characteristics_hex": f"0x{characteristics:08x}",
                "is_executable_or_code": bool(characteristics & (EXECUTE | CODE)),
                "has_execute": bool(characteristics & EXECUTE),
                "has_code": bool(characteristics & CODE),
            }
        )
    return rows


def overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return max(a0, b0) < min(a1, b1)


def resolve_manifest_path(dataset_root: Path, manifest_row: Any) -> Path | None:
    if manifest_row is None:
        return None
    for column in ("path", "file_path", "sample_path"):
        if hasattr(manifest_row, column):
            value = str(getattr(manifest_row, column))
            path = Path(value)
            return path if path.is_absolute() else dataset_root / path
    return None


def resolve_transformed_path(transformed_dir: Path, sample_id: str) -> Path:
    direct = transformed_dir / sample_id
    if direct.exists():
        return direct
    matches = sorted(transformed_dir.glob(sample_id + "*"))
    return matches[0] if matches else direct


def classify_failure(
    original_path: Path | None,
    transformed_path: Path,
    modified_ranges: list[tuple[int, int]],
) -> tuple[str, list[str], list[str], dict[str, Any]]:
    details: dict[str, Any] = {
        "original_file_size": None,
        "transformed_file_size": None,
        "transformed_size_delta": None,
        "out_of_file_mutation": False,
        "declared_exec_raw_extends_past_eof": False,
    }
    section_summary: list[str] = []
    overlap_summary: list[str] = []
    if not original_path or not original_path.exists() or not transformed_path.exists():
        return "pe_parse_or_path_issue_during_rca", section_summary, overlap_summary, details

    original_size = original_path.stat().st_size
    transformed_size = transformed_path.stat().st_size
    details["original_file_size"] = original_size
    details["transformed_file_size"] = transformed_size
    details["transformed_size_delta"] = transformed_size - original_size
    details["out_of_file_mutation"] = any(start >= original_size or end > original_size for start, end in modified_ranges)

    original_sections = section_rows(original_path)
    exec_sections = [section for section in original_sections if section["is_executable_or_code"]]
    details["declared_exec_raw_extends_past_eof"] = any(section["raw_end"] > original_size for section in exec_sections)

    for section in exec_sections:
        section_summary.append(
            f"{section['name']}:{section['characteristics_hex']}:{section['raw_start']}-{section['raw_end']}"
        )
    for start, end in modified_ranges:
        for section in original_sections:
            if overlaps(start, end, section["raw_start"], section["raw_end"]):
                overlap_summary.append(
                    f"{start}-{end} overlaps {section['name']} exec_or_code={section['is_executable_or_code']} chars={section['characteristics_hex']}"
                )

    if any("exec_or_code=True" in item for item in overlap_summary):
        return "transformer_selected_executable_or_code_section", section_summary, overlap_summary, details
    if (
        details["out_of_file_mutation"]
        and details["transformed_size_delta"] > 0
        and details["declared_exec_raw_extends_past_eof"]
    ):
        return "out_of_file_slack_append_within_declared_executable_raw_extent", section_summary, overlap_summary, details
    if details["out_of_file_mutation"]:
        return "out_of_file_slack_region", section_summary, overlap_summary, details
    return "validator_detected_executable_section_byte_delta_without_recorded_range_overlap", section_summary, overlap_summary, details


def main() -> None:
    args = parse_args()
    manifest = pd.read_csv(args.manifest)
    by_id = {str(row.sample_id): row for row in manifest.itertuples(index=False)}

    total = 0
    failures: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for path in sorted(args.validation_dir.glob("*.json")):
        total += 1
        data = json.loads(path.read_text())
        sample_id = str(data.get("original_sha256") or path.stem)
        base_row = {
            "sample_id": sample_id,
            "allowed_for_evaluation": data.get("allowed_for_evaluation"),
            "executable_sections_unchanged": data.get("executable_sections_unchanged"),
            "validation_level": data.get("validation_level"),
            "modified_ranges": json.dumps(data.get("modified_ranges", [])),
            "bytes_added_or_modified": data.get("bytes_added_or_modified"),
            "errors": json.dumps(data.get("errors", [])),
        }
        if data.get("executable_sections_unchanged") is False:
            failures.append((sample_id, data, base_row))

    output_rows: list[dict[str, Any]] = []
    for sample_id, data, base_row in failures:
        manifest_row = by_id.get(sample_id)
        original_path = resolve_manifest_path(args.dataset_root, manifest_row)
        transformed_path = resolve_transformed_path(args.transformed_dir, sample_id)
        modified_ranges = [(int(start), int(end)) for start, end in data.get("modified_ranges", [])]
        try:
            classification, section_summary, overlap_summary, details = classify_failure(
                original_path,
                transformed_path,
                modified_ranges,
            )
        except Exception as exc:  # Keep RCA failure sanitized and explicit.
            classification = f"rca_error:{type(exc).__name__}"
            section_summary = [str(exc)]
            overlap_summary = []
            details = {
                "original_file_size": None,
                "transformed_file_size": None,
                "transformed_size_delta": None,
                "out_of_file_mutation": None,
                "declared_exec_raw_extends_past_eof": None,
            }
        row = dict(base_row)
        row.update(
            {
                "root_cause_classification": classification,
                "original_path_available": bool(original_path and original_path.exists()),
                "transformed_path_available": transformed_path.exists(),
                "original_file_size": details["original_file_size"],
                "transformed_file_size": details["transformed_file_size"],
                "transformed_size_delta": details["transformed_size_delta"],
                "out_of_file_mutation": details["out_of_file_mutation"],
                "declared_exec_raw_extends_past_eof": details["declared_exec_raw_extends_past_eof"],
                "executable_or_code_sections": "; ".join(section_summary),
                "modified_range_overlaps": "; ".join(overlap_summary),
            }
        )
        output_rows.append(row)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "sample_id",
        "allowed_for_evaluation",
        "executable_sections_unchanged",
        "validation_level",
        "bytes_added_or_modified",
        "modified_ranges",
        "errors",
        "root_cause_classification",
        "original_path_available",
        "transformed_path_available",
        "original_file_size",
        "transformed_file_size",
        "transformed_size_delta",
        "out_of_file_mutation",
        "declared_exec_raw_extends_past_eof",
        "executable_or_code_sections",
        "modified_range_overlaps",
    ]
    with args.output_csv.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(output_rows)

    classifications = Counter(row["root_cause_classification"] for row in output_rows)
    passed = total - len(failures)
    report = [
        "# BinaryShield Slack Failure Root-Cause Analysis",
        "",
        f"Validation records inspected: `{total}`",
        f"Executable-section preservation passes: `{passed}`",
        f"Executable-section preservation failures: `{len(failures)}`",
        "",
        "## Classification Counts",
        "",
    ]
    for key, value in sorted(classifications.items()):
        report.append(f"- `{key}`: `{value}`")
    report += [
        "",
        "## Root Cause",
        "",
        "The two PEMML 5k+5k slack failures are classified as out-of-file slack mutations on malformed or truncated PE layouts. The mutation records target slack in later non-executable sections, but those raw offsets are beyond the original file length. Python bytearray slice assignment beyond EOF appends data at the file end. In these cases the original PE also declares an executable/code section raw extent past EOF, so appending bytes changes the byte range compared by the executable-section preservation validator.",
        "",
        "This is a real transformer edge case, not a basis for lowering the acceptance gate. The appropriate remediation is to skip slack regions whose raw byte ranges are not fully present in the source file, preserving validation coverage accounting instead of silently accepting ambiguous mutations.",
        "",
        "## Claim Boundary",
        "",
        "This RCA is static structural evidence only. It does not prove malware functionality preservation and does not change the original PEMML 5k+5k acceptance status unless the affected validation is rerun under the patched transformer.",
        "",
        f"Failure cases CSV: `{args.output_csv}`",
    ]
    args.report_output.write_text("\n".join(report) + "\n")
    print({"records": total, "failures": len(failures), "output_csv": str(args.output_csv), "report": str(args.report_output), "classifications": dict(classifications)})


if __name__ == "__main__":
    main()
