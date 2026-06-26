from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from binaryshield.pe_features import parse_pe


@dataclass
class PEFeatureCentroidDetector:
    """Pure-Python PE-feature nearest-centroid baseline.

    This keeps BinaryShield runnable on a clean machine without sklearn. It is not
    meant to outperform tree models; it provides a second detector interface and a
    reproducible baseline for validation/demo runs.
    """

    centroids: dict[str, dict[str, float]]
    feature_names: list[str]
    class_names: list[str]
    detector_name: str = "pe_feature_centroid"

    @classmethod
    def create(cls) -> "PEFeatureCentroidDetector":
        return cls(centroids={}, feature_names=[], class_names=[])

    def fit(self, paths: list[str | Path], labels: list[str]) -> "PEFeatureCentroidDetector":
        rows = [parse_pe(path).to_vector() for path in paths]
        self.feature_names = sorted({name for row in rows for name in row})
        self.class_names = sorted(set(labels))
        grouped: dict[str, list[dict[str, float]]] = {label: [] for label in self.class_names}
        for row, label in zip(rows, labels, strict=False):
            grouped[label].append(row)
        self.centroids = {}
        for label, label_rows in grouped.items():
            self.centroids[label] = {
                name: sum(row.get(name, 0.0) for row in label_rows) / max(len(label_rows), 1)
                for name in self.feature_names
            }
        return self

    def predict(self, paths: list[str | Path]) -> list[str]:
        predictions: list[str] = []
        for path in paths:
            row = parse_pe(path).to_vector()
            predictions.append(min(self.class_names, key=lambda label: self._distance(row, self.centroids[label])))
        return predictions

    def predict_proba(self, paths: list[str | Path]) -> list[list[float]]:
        probabilities: list[list[float]] = []
        for path in paths:
            row = parse_pe(path).to_vector()
            distances = [self._distance(row, self.centroids[label]) for label in self.class_names]
            scores = [1.0 / (distance + 1e-9) for distance in distances]
            total = sum(scores) or 1.0
            probabilities.append([score / total for score in scores])
        return probabilities

    def _distance(self, row: dict[str, float], centroid: dict[str, float]) -> float:
        return math.sqrt(sum((row.get(name, 0.0) - centroid.get(name, 0.0)) ** 2 for name in self.feature_names))

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "centroids": self.centroids,
                    "feature_names": self.feature_names,
                    "class_names": self.class_names,
                    "detector_name": self.detector_name,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "PEFeatureCentroidDetector":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            centroids={label: {k: float(v) for k, v in values.items()} for label, values in payload["centroids"].items()},
            feature_names=list(payload["feature_names"]),
            class_names=list(payload["class_names"]),
            detector_name=payload.get("detector_name", "pe_feature_centroid"),
        )
