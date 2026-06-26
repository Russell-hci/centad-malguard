from __future__ import annotations

import hashlib
import random
from dataclasses import asdict, dataclass
from pathlib import Path

from binaryshield.mutation_regions import MutationRegion, find_mutation_regions


@dataclass(frozen=True)
class TransformationResult:
    original_path: str
    transformed_path: str
    transformation_type: str
    bytes_added_or_modified: int
    modified_ranges: list[tuple[int, int]]
    seed: int
    original_sha256: str
    transformed_sha256: str
    validation_level_expected: int

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["modified_ranges"] = [list(item) for item in self.modified_ranges]
        return data


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _payload(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(0, 256) for _ in range(size))


def append_overlay(
    input_path: str | Path,
    output_path: str | Path,
    payload_size: int = 1024,
    seed: int = 1337,
    require_level2: bool = True,
) -> TransformationResult:
    if payload_size <= 0:
        raise ValueError("payload_size must be positive")
    src = Path(input_path)
    dst = Path(output_path)
    append_regions = [region for region in find_mutation_regions(src) if region.region_type == "append_overlay"]
    append_region = append_regions[0] if append_regions else None
    if require_level2 and (append_region is None or append_region.validation_level < 2):
        reason = append_region.reason if append_region else "no append overlay region found"
        raise ValueError(f"append overlay is not Level-2 safe: {reason}")
    original = src.read_bytes()
    transformed = original + _payload(payload_size, seed)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(transformed)
    return TransformationResult(
        original_path=str(src),
        transformed_path=str(dst),
        transformation_type="append_overlay",
        bytes_added_or_modified=payload_size,
        modified_ranges=[(len(original), len(transformed))],
        seed=seed,
        original_sha256=_sha256(original),
        transformed_sha256=_sha256(transformed),
        validation_level_expected=2,
    )


def mutate_slack_space(
    input_path: str | Path,
    output_path: str | Path,
    max_bytes: int = 512,
    seed: int = 1337,
    allow_executable_slack: bool = False,
) -> TransformationResult:
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    src = Path(input_path)
    dst = Path(output_path)
    original = src.read_bytes()
    data = bytearray(original)
    # Only mutate bytes that already exist in the file. Some malformed or
    # truncated PE files declare section raw ranges past EOF; assigning to a
    # bytearray slice beyond EOF appends data, which can accidentally extend
    # an earlier executable section's compared byte range during validation.
    regions = [
        region
        for region in find_mutation_regions(src)
        if (
            region.region_type == "section_slack"
            and (allow_executable_slack or region.validation_level >= 2)
            and 0 <= region.start < region.end <= len(data)
        )
    ]
    if not regions:
        raise ValueError("no suitable slack-space mutation region found")
    region: MutationRegion = max(regions, key=lambda candidate: candidate.size)
    size = min(max_bytes, region.size)
    payload = _payload(size, seed)
    data[region.start : region.start + size] = payload
    transformed = bytes(data)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(transformed)
    return TransformationResult(
        original_path=str(src),
        transformed_path=str(dst),
        transformation_type="section_slack",
        bytes_added_or_modified=size,
        modified_ranges=[(region.start, region.start + size)],
        seed=seed,
        original_sha256=_sha256(original),
        transformed_sha256=_sha256(transformed),
        validation_level_expected=region.validation_level,
    )
