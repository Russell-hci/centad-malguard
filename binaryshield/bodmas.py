from __future__ import annotations

import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BODMAS_METADATA_FIELDNAMES = ["sha256", "first_seen", "family"]


@dataclass(frozen=True)
class BODMASMetadataRow:
    sha256: str
    first_seen: str
    family: str

    @property
    def label(self) -> str:
        return "benign" if not self.family else "malware"


@dataclass(frozen=True)
class BODMASRawMatch:
    sample_id: str
    path: Path
    label: str
    family: str
    first_seen: str
    sha256: str


def load_bodmas_metadata(path: str | Path) -> list[BODMASMetadataRow]:
    """Load BODMAS metadata from either headered or headerless CSV.

    The public BODMAS metadata is commonly documented as three columns:
    SHA-256, first-seen time, and malware family. Some mirrors provide a header,
    while others preserve the original headerless format, so the loader accepts
    both.
    """

    metadata_path = Path(path)
    with metadata_path.open("r", encoding="utf-8", newline="") as handle:
        raw_rows = [row for row in csv.reader(handle) if row]
    if not raw_rows:
        return []
    first = [cell.strip().lower() for cell in raw_rows[0]]
    has_header = bool(set(first) & {"sha256", "sha-256", "sha_256", "sha", "hash"})
    if has_header:
        fieldnames = first
        rows = [
            _row_from_mapping({field: (row[index].strip() if index < len(row) else "") for index, field in enumerate(fieldnames)})
            for row in raw_rows[1:]
        ]
    else:
        rows = [_row_from_sequence(row) for row in raw_rows]
    return rows


def build_raw_bodmas_matches(
    metadata_rows: list[BODMASMetadataRow],
    binaries_dir: str | Path,
    *,
    compute_hash: bool = False,
) -> list[BODMASRawMatch]:
    """Match BODMAS raw malware binaries to metadata by SHA-256.

    BODMAS releases raw binaries for malware samples only. Most downloaded raw
    binary folders name files by SHA-256, so this defaults to filename matching.
    Use compute_hash=True only on a controlled external volume because hashing a
    full raw-malware directory is slower and should not happen inside the repo.
    """

    root = Path(binaries_dir)
    by_sha = {row.sha256.lower(): row for row in metadata_rows}
    matches: list[BODMASRawMatch] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        sha = _sha_from_filename(path)
        if (not sha or sha not in by_sha) and compute_hash:
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if not sha or sha not in by_sha:
            continue
        row = by_sha[sha]
        matches.append(
            BODMASRawMatch(
                sample_id=sha,
                path=path,
                label=row.label,
                family=row.family,
                first_seen=row.first_seen,
                sha256=sha,
            )
        )
    return matches


def inspect_bodmas_npz(path: str | Path) -> dict[str, Any]:
    """Return Git-safe metadata about a BODMAS feature-vector npz file."""

    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError("numpy is required to inspect BODMAS npz feature vectors") from exc

    npz = np.load(Path(path), allow_pickle=False)
    summary: dict[str, Any] = {"arrays": {}}
    for key in npz.files:
        array = npz[key]
        summary["arrays"][key] = {
            "shape": list(array.shape),
            "dtype": str(array.dtype),
        }
    if "X" in npz.files:
        summary["feature_rows"] = int(npz["X"].shape[0])
        summary["feature_dim"] = int(npz["X"].shape[1]) if len(npz["X"].shape) > 1 else 1
    if "y" in npz.files:
        values, counts = np.unique(npz["y"], return_counts=True)
        summary["label_counts"] = {str(value): int(count) for value, count in zip(values.tolist(), counts.tolist())}
    return summary


def split_by_time_or_hash(
    rows: list[BODMASMetadataRow | BODMASRawMatch],
    *,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> list[str]:
    """Return deterministic train/val/test splits.

    BODMAS is timestamped, so sorting by first-seen date provides a practical
    temporal split. If timestamps are absent, SHA-256 order remains stable.
    """

    indexed = list(enumerate(rows))
    indexed.sort(key=lambda item: ((item[1].first_seen or ""), item[1].sha256))
    total = len(indexed)
    val_start = int(total * (1.0 - test_ratio - val_ratio))
    test_start = int(total * (1.0 - test_ratio))
    splits = ["train"] * total
    for sorted_index, (original_index, _row) in enumerate(indexed):
        if sorted_index >= test_start:
            split = "test"
        elif sorted_index >= val_start:
            split = "val"
        else:
            split = "train"
        splits[original_index] = split
    return splits


def _row_from_mapping(row: dict[str, str]) -> BODMASMetadataRow:
    sha = _first(row, ["sha256", "sha-256", "sha_256", "sha", "hash"])
    first_seen = _first(row, ["first_seen", "first seen", "firstseen", "date", "timestamp"])
    family = _first(row, ["family", "malware_family", "category", "avclass"], default="")
    return BODMASMetadataRow(sha256=sha.lower(), first_seen=first_seen, family=family.lower())


def _row_from_sequence(row: list[str]) -> BODMASMetadataRow:
    padded = [item.strip() for item in row] + ["", "", ""]
    return BODMASMetadataRow(sha256=padded[0].lower(), first_seen=padded[1], family=padded[2].lower())


def _first(row: dict[str, str], names: list[str], default: str | None = None) -> str:
    for name in names:
        if name in row:
            return row[name].strip()
    if default is not None:
        return default
    raise ValueError(f"missing required BODMAS metadata column; tried {names}")


def _sha_from_filename(path: Path) -> str | None:
    candidates = [path.name, path.stem]
    for candidate in candidates:
        normalized = candidate.lower()
        if len(normalized) == 64 and all(ch in "0123456789abcdef" for ch in normalized):
            return normalized
    return None
