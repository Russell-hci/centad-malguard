from __future__ import annotations

import csv
import hashlib
import random
from dataclasses import dataclass
from pathlib import Path

from binaryshield.metadata_manifest import MetadataManifestRow, write_metadata_manifest
from binaryshield.pe_features import PEParseError, parse_pe


PATH_COLUMNS = ["path", "file_path", "filepath", "sample_path", "filename", "file", "id", "sha256"]
LABEL_COLUMNS = ["label", "class", "target", "malware", "is_malware", "list"]
SPLIT_COLUMNS = ["split", "subset"]
SHA_COLUMNS = ["sha256", "sha", "hash"]


@dataclass(frozen=True)
class PemmlManifestConfig:
    samples_csv: Path
    dataset_root: Path
    output: Path
    summary_output: Path | None = None
    mode: str = "full"
    malware_count: int | None = None
    benign_count: int | None = None
    seed: int = 1337
    val_ratio: float = 0.15
    test_ratio: float = 0.15


def build_pemml_manifest(config: PemmlManifestConfig) -> dict[str, object]:
    metadata = _load_csv(config.samples_csv)
    if config.mode not in {"full", "balanced-subset"}:
        raise ValueError("mode must be 'full' or 'balanced-subset'")
    skipped = {"missing_path": 0, "missing_label": 0, "missing_file": 0, "pe_parse_failed": 0}
    if config.mode == "balanced-subset":
        selected = _build_balanced_subset(metadata, config, skipped)
    else:
        candidates: list[MetadataManifestRow] = []
        for row in metadata:
            manifest_row = _manifest_row_from_source(row, config.dataset_root, skipped)
            if manifest_row is not None:
                candidates.append(manifest_row)
        selected = _select_rows(candidates, config)
    selected = _assign_splits(selected, seed=config.seed, val_ratio=config.val_ratio, test_ratio=config.test_ratio)
    write_metadata_manifest(selected, config.output)
    summary = {
        "samples_csv": str(config.samples_csv),
        "dataset_root": str(config.dataset_root),
        "mode": config.mode,
        "manifest_rows": len(selected),
        "source_rows": len(metadata),
        "skipped": skipped,
        "label_counts": _counts(row.label for row in selected),
        "split_counts": _counts(row.split for row in selected),
        "seed": config.seed,
        "val_ratio": config.val_ratio,
        "test_ratio": config.test_ratio,
        "claim_boundary": (
            "PEMML manifests validate local PE parseability and labels only. They do not claim family-level validation "
            "unless reliable family columns are separately verified."
        ),
    }
    if config.summary_output is not None:
        config.summary_output.parent.mkdir(parents=True, exist_ok=True)
        import json

        config.summary_output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _manifest_row_from_source(
    row: dict[str, str],
    dataset_root: Path,
    skipped: dict[str, int],
) -> MetadataManifestRow | None:
    label = _normalize_label(_first_value(row, LABEL_COLUMNS))
    if not label:
        skipped["missing_label"] += 1
        return None
    path_value = _first_value(row, PATH_COLUMNS)
    if not path_value:
        skipped["missing_path"] += 1
        return None
    path = _resolve_path(dataset_root, path_value)
    if path is None or not path.exists() or not path.is_file():
        skipped["missing_file"] += 1
        return None
    try:
        parse_pe(path)
    except PEParseError:
        skipped["pe_parse_failed"] += 1
        return None
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    split = _first_value(row, SPLIT_COLUMNS)
    try:
        stored_path = path.relative_to(dataset_root)
    except ValueError:
        stored_path = path
    return MetadataManifestRow(
        sample_id=sha,
        path=stored_path,
        label=label,
        family="",
        split=split,
        sha256=sha,
    )


def _build_balanced_subset(
    metadata: list[dict[str, str]],
    config: PemmlManifestConfig,
    skipped: dict[str, int],
) -> list[MetadataManifestRow]:
    malware_count = config.malware_count
    benign_count = config.benign_count
    if malware_count is None or benign_count is None:
        raise ValueError("balanced-subset mode requires --malware-count and --benign-count")
    grouped_source: dict[str, list[dict[str, str]]] = {"malware": [], "benign": []}
    for row in metadata:
        label = _normalize_label(_first_value(row, LABEL_COLUMNS))
        if not label:
            skipped["missing_label"] += 1
            continue
        path_value = _first_value(row, PATH_COLUMNS)
        if not path_value:
            skipped["missing_path"] += 1
            continue
        grouped_source[label].append(row)
    needed = {"malware": malware_count, "benign": benign_count}
    if len(grouped_source["malware"]) < malware_count or len(grouped_source["benign"]) < benign_count:
        raise ValueError(
            "insufficient PEMML rows for requested balanced subset before PE validation: "
            f"malware {len(grouped_source['malware'])}/{malware_count}, benign {len(grouped_source['benign'])}/{benign_count}"
        )
    rng = random.Random(config.seed)
    selected: list[MetadataManifestRow] = []
    valid_counts = {"malware": 0, "benign": 0}
    for label in ["malware", "benign"]:
        rows = list(grouped_source[label])
        rng.shuffle(rows)
        for row in rows:
            if valid_counts[label] >= needed[label]:
                break
            manifest_row = _manifest_row_from_source(row, config.dataset_root, skipped)
            if manifest_row is None:
                continue
            selected.append(manifest_row)
            valid_counts[label] += 1
        if valid_counts[label] < needed[label]:
            raise ValueError(
                "insufficient PEMML rows for requested balanced subset after PE validation: "
                f"{label} {valid_counts[label]}/{needed[label]}"
            )
    return sorted(selected, key=lambda row: row.sha256)


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("samples.csv must have a header row")
        return [{key.lower().strip(): (value or "").strip() for key, value in row.items()} for row in reader]


def _first_value(row: dict[str, str], names: list[str]) -> str:
    for name in names:
        if row.get(name):
            return row[name]
    return ""


def _resolve_path(root: Path, value: str) -> Path | None:
    raw = Path(value)
    if raw.is_absolute():
        return raw
    direct = root / raw
    if direct.exists():
        return direct
    stem = raw.stem or raw.name
    for candidate in [
        root / stem,
        root / f"{stem}.exe",
        root / "malware" / stem,
        root / "malware" / f"{stem}.exe",
        root / "benign" / stem,
        root / "benign" / f"{stem}.exe",
        root / "samples" / stem,
        root / "samples" / f"{stem}.exe",
    ]:
        if candidate.exists():
            return candidate
    return direct


def _normalize_label(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"malware", "malicious", "1", "true", "yes", "mal", "blacklist", "blacklisted"}:
        return "malware"
    if normalized in {"benign", "goodware", "0", "false", "no", "clean", "whitelist", "whitelisted"}:
        return "benign"
    return normalized if normalized in {"malware", "benign"} else ""


def _select_rows(rows: list[MetadataManifestRow], config: PemmlManifestConfig) -> list[MetadataManifestRow]:
    if config.mode == "full":
        return sorted(rows, key=lambda row: row.sha256)
    malware_count = config.malware_count
    benign_count = config.benign_count
    if malware_count is None or benign_count is None:
        raise ValueError("balanced-subset mode requires --malware-count and --benign-count")
    rng = random.Random(config.seed)
    grouped = {
        "malware": [row for row in rows if row.label == "malware"],
        "benign": [row for row in rows if row.label == "benign"],
    }
    if len(grouped["malware"]) < malware_count or len(grouped["benign"]) < benign_count:
        raise ValueError(
            "insufficient PEMML rows for requested balanced subset: "
            f"malware {len(grouped['malware'])}/{malware_count}, benign {len(grouped['benign'])}/{benign_count}"
        )
    selected = rng.sample(grouped["malware"], malware_count) + rng.sample(grouped["benign"], benign_count)
    return sorted(selected, key=lambda row: row.sha256)


def _assign_splits(
    rows: list[MetadataManifestRow],
    *,
    seed: int,
    val_ratio: float,
    test_ratio: float,
) -> list[MetadataManifestRow]:
    if all(row.split for row in rows):
        return rows
    rng = random.Random(seed)
    grouped: dict[str, list[MetadataManifestRow]] = {}
    for row in rows:
        grouped.setdefault(row.label, []).append(row)
    assigned: list[MetadataManifestRow] = []
    for label in sorted(grouped):
        group = sorted(grouped[label], key=lambda row: row.sha256)
        rng.shuffle(group)
        total = len(group)
        val_start = int(total * (1.0 - test_ratio - val_ratio))
        test_start = int(total * (1.0 - test_ratio))
        for index, row in enumerate(group):
            split = row.split or ("test" if index >= test_start else "val" if index >= val_start else "train")
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


def _normalize_sha(value: str) -> str:
    return value.strip().lower()
