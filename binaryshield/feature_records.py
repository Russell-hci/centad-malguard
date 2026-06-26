from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FeatureRecordSample:
    sample_id: str
    record_index: int
    label: str
    family: str | None
    split: str | None
    sha256: str | None


def load_feature_manifest(path: str | Path) -> list[FeatureRecordSample]:
    manifest_path = Path(path)
    with manifest_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = {"sample_id", "record_index", "label"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"feature manifest missing required columns: {sorted(missing)}")
        return [
            FeatureRecordSample(
                sample_id=row["sample_id"],
                record_index=int(row["record_index"]),
                label=row["label"],
                family=row.get("family") or None,
                split=row.get("split") or None,
                sha256=row.get("sha256") or None,
            )
            for row in reader
        ]


def iter_feature_split(samples: list[FeatureRecordSample], split: str | None):
    for sample in samples:
        if split is None or sample.split == split:
            yield sample


def load_npz_features(path: str | Path, feature_key: str = "X"):
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError("numpy is required for PE-derived feature-record experiments") from exc

    npz = np.load(Path(path), allow_pickle=False)
    if feature_key not in npz.files:
        raise ValueError(f"feature key {feature_key!r} missing from npz; available keys: {npz.files}")
    return np.asarray(npz[feature_key], dtype=float)


def select_feature_rows(matrix, samples: list[FeatureRecordSample]):
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise ImportError("numpy is required for PE-derived feature-record experiments") from exc

    indices = [sample.record_index for sample in samples]
    if any(index < 0 or index >= matrix.shape[0] for index in indices):
        raise IndexError("feature manifest contains record_index outside feature matrix bounds")
    return np.asarray(matrix[indices], dtype=float)


def sample_targets(samples: list[FeatureRecordSample], target: str) -> list[str]:
    if target == "family":
        return [sample.family or sample.label for sample in samples]
    return [sample.label for sample in samples]
