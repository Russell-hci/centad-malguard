from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class FeatureRecordCentroidDetector:
    """Dependency-light centroid classifier for PE-derived feature records."""

    centroids: dict[str, list[float]]
    class_names: list[str]
    detector_name: str = "feature_record_centroid"

    @classmethod
    def create(cls) -> "FeatureRecordCentroidDetector":
        return cls(centroids={}, class_names=[])

    def fit(self, rows: Any, labels: list[str]) -> "FeatureRecordCentroidDetector":
        self.class_names = sorted(set(labels))
        try:
            import numpy as np
        except ImportError:
            grouped = {label: [] for label in self.class_names}
            for row, label in zip(rows, labels, strict=False):
                grouped[label].append([float(value) for value in row])
            self.centroids = {label: _mean(label_rows) for label, label_rows in grouped.items()}
            return self

        matrix = np.asarray(rows, dtype=np.float32)
        label_array = np.asarray(labels, dtype=object)
        self.centroids = {
            label: np.mean(matrix[label_array == label], axis=0, dtype=np.float64).astype(float).tolist()
            for label in self.class_names
        }
        return self

    def predict_rows(self, rows: Any) -> list[str]:
        try:
            import numpy as np
        except ImportError:
            predictions: list[str] = []
            for row in rows:
                values = [float(value) for value in row]
                predictions.append(min(self.class_names, key=lambda label: _distance(values, self.centroids[label])))
            return predictions

        matrix = np.asarray(rows, dtype=np.float32)
        centroid_matrix = np.asarray([self.centroids[label] for label in self.class_names], dtype=np.float32)
        distances = np.sum((matrix[:, None, :] - centroid_matrix[None, :, :]) ** 2, axis=2)
        indices = np.argmin(distances, axis=1)
        return [self.class_names[int(index)] for index in indices]

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "centroids": self.centroids,
                    "class_names": self.class_names,
                    "detector_name": self.detector_name,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "FeatureRecordCentroidDetector":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            centroids={label: [float(value) for value in values] for label, values in payload["centroids"].items()},
            class_names=list(payload["class_names"]),
            detector_name=str(payload.get("detector_name", "feature_record_centroid")),
        )


def _mean(rows: list[list[float]]) -> list[float]:
    if not rows:
        return []
    return [sum(row[index] for row in rows) / len(rows) for index in range(len(rows[0]))]


def _distance(left: list[float], right: list[float]) -> float:
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right, strict=False)))
