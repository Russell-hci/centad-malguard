from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from binaryshield.pe_features import PEFeatureRecord, PEParseError, PESection, parse_pe
from binaryshield.transformations import TransformationResult


@dataclass(frozen=True)
class ValidationRecord:
    original_sha256: str | None
    transformed_sha256: str | None
    hash_changed: bool
    pe_parse_original: bool
    pe_parse_transformed: bool
    entry_point_unchanged: bool
    section_count_valid: bool
    executable_sections_unchanged: bool
    transformation_type: str
    bytes_added_or_modified: int
    modified_ranges: list[tuple[int, int]]
    validation_level: int
    label_preservation_assumption: str
    sandbox_execution_status: str
    allowed_for_evaluation: bool
    errors: list[str]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["modified_ranges"] = [list(item) for item in self.modified_ranges]
        return data


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _section_bytes(path: Path, section: PESection) -> bytes:
    data = path.read_bytes()
    return data[section.raw_pointer : min(section.raw_end, len(data))]


def _executable_sections_unchanged(
    original_path: Path,
    transformed_path: Path,
    original_record: PEFeatureRecord,
    transformed_record: PEFeatureRecord,
) -> bool:
    if len(original_record.sections) != len(transformed_record.sections):
        return False
    for section, transformed_section in zip(original_record.sections, transformed_record.sections, strict=True):
        if not section.is_executable:
            continue
        if (
            section.name,
            section.raw_pointer,
            section.raw_size,
            section.virtual_address,
            section.virtual_size,
            section.characteristics,
        ) != (
            transformed_section.name,
            transformed_section.raw_pointer,
            transformed_section.raw_size,
            transformed_section.virtual_address,
            transformed_section.virtual_size,
            transformed_section.characteristics,
        ):
            return False
        if _section_bytes(original_path, section) != _section_bytes(transformed_path, transformed_section):
            return False
    return True


def validate_transformation(
    result: TransformationResult,
    output_json_path: str | Path | None = None,
    sandbox_execution_status: str = "not_attempted",
) -> ValidationRecord:
    original_path = Path(result.original_path)
    transformed_path = Path(result.transformed_path)
    errors: list[str] = []
    original_record: PEFeatureRecord | None = None
    transformed_record: PEFeatureRecord | None = None

    try:
        original_record = parse_pe(original_path)
    except PEParseError as exc:
        errors.append(f"original_parse_error: {exc}")

    try:
        transformed_record = parse_pe(transformed_path)
    except PEParseError as exc:
        errors.append(f"transformed_parse_error: {exc}")

    original_sha = _sha256(original_path) if original_path.exists() else None
    transformed_sha = _sha256(transformed_path) if transformed_path.exists() else None
    pe_parse_original = original_record is not None
    pe_parse_transformed = transformed_record is not None
    entry_point_unchanged = bool(
        original_record
        and transformed_record
        and original_record.address_of_entry_point == transformed_record.address_of_entry_point
    )
    section_count_valid = bool(
        original_record
        and transformed_record
        and original_record.number_of_sections == transformed_record.number_of_sections
    )
    executable_sections_unchanged = bool(
        original_record
        and transformed_record
        and _executable_sections_unchanged(original_path, transformed_path, original_record, transformed_record)
    )
    hash_changed = bool(original_sha and transformed_sha and original_sha != transformed_sha)
    validation_level = 0
    if pe_parse_original and pe_parse_transformed and hash_changed and entry_point_unchanged and section_count_valid:
        validation_level = 1
    if validation_level >= 1 and executable_sections_unchanged and result.validation_level_expected >= 2:
        validation_level = 2
    if validation_level >= 2 and sandbox_execution_status == "passed":
        validation_level = 3

    allowed_for_evaluation = validation_level >= min(result.validation_level_expected, 2)
    assumption = {
        "append_overlay": "append-only overlay; no executable-section modification",
        "section_slack": "non-executable section slack; executable sections unchanged",
    }.get(result.transformation_type, "validated PE-preserving transformation")
    if not allowed_for_evaluation:
        errors.append("validation_level_below_expected")

    record = ValidationRecord(
        original_sha256=original_sha,
        transformed_sha256=transformed_sha,
        hash_changed=hash_changed,
        pe_parse_original=pe_parse_original,
        pe_parse_transformed=pe_parse_transformed,
        entry_point_unchanged=entry_point_unchanged,
        section_count_valid=section_count_valid,
        executable_sections_unchanged=executable_sections_unchanged,
        transformation_type=result.transformation_type,
        bytes_added_or_modified=result.bytes_added_or_modified,
        modified_ranges=result.modified_ranges,
        validation_level=validation_level,
        label_preservation_assumption=assumption,
        sandbox_execution_status=sandbox_execution_status,
        allowed_for_evaluation=allowed_for_evaluation,
        errors=errors,
    )
    if output_json_path is not None:
        output_path = Path(output_json_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")
    return record
