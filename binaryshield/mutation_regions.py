from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from binaryshield.pe_features import PEFeatureRecord, parse_pe


@dataclass(frozen=True)
class MutationRegion:
    region_type: str
    start: int
    end: int
    size: int
    section_name: str | None
    validation_level: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def find_mutation_regions(path_or_record: str | Path | PEFeatureRecord) -> list[MutationRegion]:
    record = parse_pe(path_or_record) if not isinstance(path_or_record, PEFeatureRecord) else path_or_record
    regions: list[MutationRegion] = []
    max_raw_end = max((section.raw_end for section in record.sections), default=0)
    append_is_true_overlay = record.file_size >= max_raw_end

    regions.append(
        MutationRegion(
            region_type="append_overlay",
            start=record.file_size,
            end=record.file_size,
            size=0,
            section_name=None,
            validation_level=2 if append_is_true_overlay else 1,
            reason=(
                "append-only overlay does not modify declared section raw data"
                if append_is_true_overlay
                else "file ends inside declared section raw data; append would modify section bytes"
            ),
        )
    )

    if record.overlay_size > 0:
        regions.append(
            MutationRegion(
                region_type="existing_overlay",
                start=record.overlay_offset,
                end=record.file_size,
                size=record.overlay_size,
                section_name=None,
                validation_level=2,
                reason="existing overlay is outside declared section raw data",
            )
        )

    for section in record.sections:
        if section.slack_size <= 0:
            continue
        validation_level = 2 if not section.is_executable else 1
        reason = (
            "non-executable section slack"
            if validation_level == 2
            else "executable section slack; use only for structural tests"
        )
        regions.append(
            MutationRegion(
                region_type="section_slack",
                start=section.slack_start,
                end=section.raw_end,
                size=section.slack_size,
                section_name=section.name,
                validation_level=validation_level,
                reason=reason,
            )
        )
    return regions
