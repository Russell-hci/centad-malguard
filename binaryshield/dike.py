from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from binaryshield.metadata_manifest import MetadataManifestRow
from binaryshield.pe_features import PEParseError, parse_pe


DIKE_FAMILY_COLUMNS = [
    "generic",
    "trojan",
    "ransomware",
    "worm",
    "backdoor",
    "spyware",
    "rootkit",
    "encrypter",
    "downloader",
]


@dataclass(frozen=True)
class DikeLabelRow:
    sha256: str
    malice: float
    family_scores: dict[str, float]

    def binary_label(self, *, malice_threshold: float) -> str:
        return "malware" if self.malice > malice_threshold else "benign"

    def family_label(self, *, malice_threshold: float, min_family_score: float) -> str:
        if self.binary_label(malice_threshold=malice_threshold) == "benign":
            return "benign"
        if not self.family_scores:
            return "unknown"
        family, score = max(self.family_scores.items(), key=lambda item: item[1])
        return family if score >= min_family_score else "unknown"


def load_dike_labels(paths: list[str | Path]) -> list[DikeLabelRow]:
    rows: list[DikeLabelRow] = []
    for path in paths:
        with Path(path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"hash", "malice"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                raise ValueError(f"Dike label file {path} missing columns: {sorted(missing)}")
            for row in reader:
                scores = {name: _float(row.get(name, "0")) for name in DIKE_FAMILY_COLUMNS if name in row}
                rows.append(
                    DikeLabelRow(
                        sha256=(row.get("hash") or "").strip().lower(),
                        malice=_float(row.get("malice", "0")),
                        family_scores=scores,
                    )
                )
    return rows


def build_dike_manifest_rows(
    label_paths: list[str | Path],
    files_dir: str | Path,
    *,
    malice_threshold: float = 0.4,
    min_family_score: float = 0.05,
    require_pe_parse: bool = True,
    relative_to: str | Path | None = None,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> tuple[list[MetadataManifestRow], dict[str, object]]:
    label_rows = load_dike_labels(label_paths)
    root = Path(files_dir)
    relative_root = Path(relative_to) if relative_to is not None else root
    files_by_sha = _index_candidate_files(root)
    manifest_rows: list[MetadataManifestRow] = []
    skipped = {
        "missing_file": 0,
        "pe_parse_failed": 0,
        "missing_hash": 0,
    }
    for label_row in label_rows:
        if not label_row.sha256:
            skipped["missing_hash"] += 1
            continue
        path = files_by_sha.get(label_row.sha256)
        if path is None:
            skipped["missing_file"] += 1
            continue
        if require_pe_parse:
            try:
                parse_pe(path)
            except PEParseError:
                skipped["pe_parse_failed"] += 1
                continue
        try:
            stored_path = path.relative_to(relative_root)
        except ValueError:
            stored_path = path
        label = label_row.binary_label(malice_threshold=malice_threshold)
        manifest_rows.append(
            MetadataManifestRow(
                sample_id=label_row.sha256,
                path=stored_path,
                label=label,
                family=label_row.family_label(malice_threshold=malice_threshold, min_family_score=min_family_score),
                split="",
                sha256=label_row.sha256,
            )
        )

    manifest_rows = _stratified_split(manifest_rows, val_ratio=val_ratio, test_ratio=test_ratio)
    summary: dict[str, object] = {
        "label_rows": len(label_rows),
        "manifest_rows": len(manifest_rows),
        "skipped": skipped,
        "malice_threshold": malice_threshold,
        "min_family_score": min_family_score,
        "label_counts": _counts(row.label for row in manifest_rows),
        "family_counts": _counts(row.family for row in manifest_rows),
        "split_counts": _counts(row.split for row in manifest_rows),
        "claim_boundary": "DikeDataset contains PE and OLE files. This builder includes only files that match metadata and pass PE parsing when required.",
    }
    return manifest_rows, summary


def _index_candidate_files(root: Path) -> dict[str, Path]:
    by_sha: dict[str, Path] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        normalized = path.stem.lower()
        if len(normalized) == 64 and all(ch in "0123456789abcdef" for ch in normalized):
            by_sha[normalized] = path
    return by_sha


def _stratified_split(rows: list[MetadataManifestRow], *, val_ratio: float, test_ratio: float) -> list[MetadataManifestRow]:
    grouped: dict[str, list[MetadataManifestRow]] = {}
    for row in rows:
        grouped.setdefault(row.label, []).append(row)
    assigned: list[MetadataManifestRow] = []
    for label in sorted(grouped):
        group = sorted(grouped[label], key=lambda row: row.sha256)
        total = len(group)
        val_start = int(total * (1.0 - test_ratio - val_ratio))
        test_start = int(total * (1.0 - test_ratio))
        for index, row in enumerate(group):
            split = "test" if index >= test_start else "val" if index >= val_start else "train"
            assigned.append(
                MetadataManifestRow(
                    sample_id=row.sample_id,
                    path=row.path,
                    label=row.label,
                    family=row.family,
                    split=split,
                    sha256=row.sha256,
                )
            )
    return sorted(assigned, key=lambda row: row.sha256)


def _counts(values: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:  # type: ignore[union-attr]
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _float(value: str | None) -> float:
    try:
        return float(value or 0.0)
    except ValueError:
        return 0.0
