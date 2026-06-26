from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class BinarySample:
    sample_id: str
    path: Path
    label: str
    family: str | None = None
    split: str | None = None
    sha256: str | None = None


REQUIRED_MANIFEST_COLUMNS = {"sample_id", "path", "label"}


def load_manifest(manifest_path: str | Path, root_dir: str | Path | None = None) -> list[BinarySample]:
    path = Path(manifest_path)
    root = Path(root_dir) if root_dir is not None else path.parent
    samples: list[BinarySample] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_MANIFEST_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"manifest missing required columns: {sorted(missing)}")
        for row in reader:
            sample_path = Path(row["path"])
            if not sample_path.is_absolute():
                sample_path = root / sample_path
            samples.append(
                BinarySample(
                    sample_id=row["sample_id"],
                    path=sample_path,
                    label=row["label"],
                    family=row.get("family") or None,
                    split=row.get("split") or None,
                    sha256=row.get("sha256") or None,
                )
            )
    return samples


def iter_split(samples: list[BinarySample], split: str | None) -> Iterator[BinarySample]:
    for sample in samples:
        if split is None or sample.split == split:
            yield sample
