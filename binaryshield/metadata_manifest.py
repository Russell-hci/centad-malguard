from __future__ import annotations

import csv
import hashlib
import random
from dataclasses import dataclass
from pathlib import Path

from binaryshield.pe_features import PEParseError, parse_pe


@dataclass(frozen=True)
class MetadataManifestRow:
    sample_id: str
    path: Path
    label: str
    family: str
    split: str
    sha256: str


def build_metadata_manifest_rows(
    metadata_path: str | Path,
    binaries_dir: str | Path,
    *,
    path_column: str | None = None,
    sha256_column: str | None = None,
    label_column: str,
    family_column: str | None = None,
    split_column: str | None = None,
    sample_id_column: str | None = None,
    default_label: str | None = None,
    default_family: str = "",
    compute_hash: bool = False,
    require_pe_parse: bool = False,
    relative_to: str | Path | None = None,
    seed: int = 1337,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> tuple[list[MetadataManifestRow], dict[str, object]]:
    """Build Git-safe manifest rows by joining external PE files to metadata.

    The function supports two common public-dataset layouts:

    - metadata has a relative file path column;
    - metadata has SHA-256 labels and the binary directory is named by hashes.

    Raw files are never copied. Returned rows contain only paths, labels, hashes,
    and split metadata suitable for sanitized manifests.
    """

    metadata = _load_csv(metadata_path)
    root = Path(binaries_dir)
    relative_root = Path(relative_to) if relative_to is not None else root
    sha_index: dict[str, Path] = {}
    if sha256_column is not None:
        sha_index = _index_files_by_sha(root, compute_hash=compute_hash)

    rows: list[MetadataManifestRow] = []
    skipped = {
        "missing_file": 0,
        "missing_label": 0,
        "sha_not_found": 0,
        "pe_parse_failed": 0,
    }
    for item in metadata:
        label = _value(item, label_column, default_label)
        if not label:
            skipped["missing_label"] += 1
            continue
        family = _value(item, family_column, default_family) if family_column else default_family
        sample_id = _value(item, sample_id_column, "") if sample_id_column else ""
        sha = _value(item, sha256_column, "") if sha256_column else ""

        path: Path | None = None
        if path_column:
            candidate_value = _value(item, path_column, "")
            if candidate_value:
                candidate = Path(candidate_value)
                path = candidate if candidate.is_absolute() else root / candidate
        if path is None and sha:
            path = sha_index.get(_normalize_sha(sha))
            if path is None:
                skipped["sha_not_found"] += 1
                continue
        if path is None or not path.exists() or not path.is_file():
            skipped["missing_file"] += 1
            continue
        if not sha:
            sha = _sha_from_filename(path) or hashlib.sha256(path.read_bytes()).hexdigest()
        if not sample_id:
            sample_id = _normalize_sha(sha) if sha else path.stem
        if require_pe_parse:
            try:
                parse_pe(path)
            except PEParseError:
                skipped["pe_parse_failed"] += 1
                continue

        stored_path = path
        try:
            stored_path = path.relative_to(relative_root)
        except ValueError:
            pass
        rows.append(
            MetadataManifestRow(
                sample_id=sample_id,
                path=stored_path,
                label=label,
                family=family,
                split=_value(item, split_column, "") if split_column else "",
                sha256=_normalize_sha(sha),
            )
        )

    rows = _assign_missing_splits(rows, seed=seed, val_ratio=val_ratio, test_ratio=test_ratio)
    summary: dict[str, object] = {
        "metadata_rows": len(metadata),
        "manifest_rows": len(rows),
        "skipped": skipped,
        "label_counts": _counts(row.label for row in rows),
        "family_counts": _counts(row.family for row in rows if row.family),
        "split_counts": _counts(row.split for row in rows),
        "path_column": path_column,
        "sha256_column": sha256_column,
        "label_column": label_column,
        "family_column": family_column,
        "split_column": split_column,
        "claim_boundary": "This manifest builder writes sanitized metadata only. It does not copy raw binaries or validate behavior preservation.",
    }
    return rows, summary


def write_metadata_manifest(rows: list[MetadataManifestRow], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_id", "path", "label", "family", "split", "sha256"])
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "sample_id": row.sample_id,
                    "path": str(row.path),
                    "label": row.label,
                    "family": row.family,
                    "split": row.split,
                    "sha256": row.sha256,
                }
            )


def _load_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("metadata CSV must have a header row")
        return [{key: (value or "").strip() for key, value in row.items()} for row in reader]


def _index_files_by_sha(root: Path, *, compute_hash: bool) -> dict[str, Path]:
    by_sha: dict[str, Path] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        sha = _sha_from_filename(path)
        if not sha and compute_hash:
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if sha:
            by_sha[_normalize_sha(sha)] = path
    return by_sha


def _value(row: dict[str, str], column: str | None, default: str | None) -> str:
    if column is None:
        return default or ""
    if column not in row:
        raise ValueError(f"metadata missing column: {column}")
    return row[column].strip() or (default or "")


def _assign_missing_splits(
    rows: list[MetadataManifestRow],
    *,
    seed: int,
    val_ratio: float,
    test_ratio: float,
) -> list[MetadataManifestRow]:
    if not rows or all(row.split for row in rows):
        return rows
    indices = list(range(len(rows)))
    rng = random.Random(seed)
    rng.shuffle(indices)
    total = len(indices)
    test_start = int(total * (1.0 - test_ratio))
    val_start = int(total * (1.0 - test_ratio - val_ratio))
    assigned = list(rows)
    for order, original_index in enumerate(indices):
        row = rows[original_index]
        if row.split:
            continue
        split = "test" if order >= test_start else "val" if order >= val_start else "train"
        assigned[original_index] = MetadataManifestRow(
            sample_id=row.sample_id,
            path=row.path,
            label=row.label,
            family=row.family,
            split=split,
            sha256=row.sha256,
        )
    return assigned


def _counts(values: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:  # type: ignore[union-attr]
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _sha_from_filename(path: Path) -> str | None:
    for candidate in (path.name, path.stem):
        normalized = _normalize_sha(candidate)
        if len(normalized) == 64 and all(ch in "0123456789abcdef" for ch in normalized):
            return normalized
    return None


def _normalize_sha(value: str) -> str:
    return value.strip().lower()
