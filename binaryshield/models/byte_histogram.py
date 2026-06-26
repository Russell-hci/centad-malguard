from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from binaryshield.byte_loader import load_bytes
from binaryshield.pe_features import parse_pe

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None


@dataclass
class ByteHistogramCentroidDetector:
    """Dependency-free raw-byte histogram nearest-centroid detector.

    This detector gives BinaryShield a non-neural raw-byte baseline that can run
    on machines without PyTorch. It models byte distribution rather than PE
    structure, so it is intentionally different from the PE-feature baseline.
    """

    centroids: dict[str, list[float]]
    class_names: list[str]
    detector_name: str = "byte_histogram_centroid"
    max_bytes: int | None = None

    @classmethod
    def create(cls, max_bytes: int | None = None) -> "ByteHistogramCentroidDetector":
        return cls(centroids={}, class_names=[], max_bytes=max_bytes)

    def fit(self, paths: list[str | Path], labels: list[str]) -> "ByteHistogramCentroidDetector":
        rows = [byte_histogram(path, self.max_bytes) for path in paths]
        self.class_names = sorted(set(labels))
        grouped = {label: [] for label in self.class_names}
        for row, label in zip(rows, labels, strict=False):
            grouped[label].append(row)
        self.centroids = {
            label: _mean_vectors(label_rows)
            for label, label_rows in grouped.items()
        }
        return self

    def predict(self, paths: list[str | Path]) -> list[str]:
        predictions: list[str] = []
        for path in paths:
            row = byte_histogram(path, self.max_bytes)
            predictions.append(min(self.class_names, key=lambda label: _distance(row, self.centroids[label])))
        return predictions

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "centroids": self.centroids,
                    "class_names": self.class_names,
                    "detector_name": self.detector_name,
                    "max_bytes": self.max_bytes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "ByteHistogramCentroidDetector":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            centroids={label: [float(value) for value in values] for label, values in payload["centroids"].items()},
            class_names=list(payload["class_names"]),
            detector_name=str(payload.get("detector_name", "byte_histogram_centroid")),
            max_bytes=payload.get("max_bytes"),
        )


@dataclass
class CalibratedByteHistogramDetector:
    """Binary raw-byte histogram detector with validation-calibrated threshold.

    The centroid baseline is deliberately simple, but on imbalanced malware vs
    benign datasets its nearest-centroid decision can optimize accuracy while
    leaving the minority class weak. This variant keeps the same representation
    and calibrates only the binary decision threshold on validation macro F1.
    It is a lightweight BinaryShield candidate, not a learned black-box model.
    """

    centroids: dict[str, list[float]]
    class_names: list[str]
    positive_label: str
    negative_label: str
    threshold: float
    validation_macro_f1: float
    validation_accuracy: float
    detector_name: str = "byte_histogram_calibrated"
    max_bytes: int | None = None

    @classmethod
    def create(cls, max_bytes: int | None = None) -> "CalibratedByteHistogramDetector":
        return cls(
            centroids={},
            class_names=[],
            positive_label="malware",
            negative_label="benign",
            threshold=0.0,
            validation_macro_f1=0.0,
            validation_accuracy=0.0,
            max_bytes=max_bytes,
        )

    def fit(self, paths: list[str | Path], labels: list[str]) -> "CalibratedByteHistogramDetector":
        rows = [byte_histogram(path, self.max_bytes) for path in paths]
        self.class_names = sorted(set(labels))
        grouped = {label: [] for label in self.class_names}
        for row, label in zip(rows, labels, strict=False):
            grouped[label].append(row)
        self.centroids = {label: _mean_vectors(label_rows) for label, label_rows in grouped.items()}
        self.positive_label, self.negative_label = _binary_label_order(self.class_names)
        self.threshold = _midpoint_threshold(rows, labels, self.positive_label, self.negative_label, self.centroids)
        self.validation_macro_f1 = 0.0
        self.validation_accuracy = 0.0
        return self

    def calibrate(self, paths: list[str | Path], labels: list[str]) -> "CalibratedByteHistogramDetector":
        if len(self.class_names) != 2:
            return self
        rows = [byte_histogram(path, self.max_bytes) for path in paths]
        scores = [
            _binary_score(row, self.positive_label, self.negative_label, self.centroids)
            for row in rows
        ]
        self.threshold, self.validation_macro_f1, self.validation_accuracy = _best_threshold(
            scores,
            labels,
            self.positive_label,
            self.negative_label,
        )
        return self

    def predict(self, paths: list[str | Path]) -> list[str]:
        predictions: list[str] = []
        for path in paths:
            row = byte_histogram(path, self.max_bytes)
            if len(self.class_names) != 2:
                predictions.append(min(self.class_names, key=lambda label: _distance(row, self.centroids[label])))
                continue
            score = _binary_score(row, self.positive_label, self.negative_label, self.centroids)
            predictions.append(self.positive_label if score <= self.threshold else self.negative_label)
        return predictions

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "centroids": self.centroids,
                    "class_names": self.class_names,
                    "positive_label": self.positive_label,
                    "negative_label": self.negative_label,
                    "threshold": self.threshold,
                    "validation_macro_f1": self.validation_macro_f1,
                    "validation_accuracy": self.validation_accuracy,
                    "detector_name": self.detector_name,
                    "max_bytes": self.max_bytes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "CalibratedByteHistogramDetector":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            centroids={label: [float(value) for value in values] for label, values in payload["centroids"].items()},
            class_names=list(payload["class_names"]),
            positive_label=str(payload.get("positive_label", "malware")),
            negative_label=str(payload.get("negative_label", "benign")),
            threshold=float(payload.get("threshold", 0.0)),
            validation_macro_f1=float(payload.get("validation_macro_f1", 0.0)),
            validation_accuracy=float(payload.get("validation_accuracy", 0.0)),
            detector_name=str(payload.get("detector_name", "byte_histogram_calibrated")),
            max_bytes=payload.get("max_bytes"),
        )


@dataclass
class ByteHistogramLogisticDetector:
    """Class-balanced logistic detector over raw-byte histograms.

    This is still lightweight and representation-transparent, but it is a real
    trained detector rather than a nearest-centroid baseline. It uses balanced
    class weights and validation macro-F1 threshold calibration, which makes it
    suitable for imbalanced malware/benign raw PE datasets such as DikeDataset.
    """

    weights: list[float]
    bias: float
    mean: list[float]
    scale: list[float]
    class_names: list[str]
    positive_label: str
    negative_label: str
    threshold: float
    validation_macro_f1: float
    validation_accuracy: float
    detector_name: str = "byte_histogram_logistic"
    max_bytes: int | None = None
    epochs: int = 800
    learning_rate: float = 0.05
    l2: float = 1e-4

    @classmethod
    def create(
        cls,
        max_bytes: int | None = None,
        epochs: int = 800,
        learning_rate: float = 0.05,
        l2: float = 1e-4,
    ) -> "ByteHistogramLogisticDetector":
        return cls(
            weights=[],
            bias=0.0,
            mean=[],
            scale=[],
            class_names=[],
            positive_label="malware",
            negative_label="benign",
            threshold=0.0,
            validation_macro_f1=0.0,
            validation_accuracy=0.0,
            max_bytes=max_bytes,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
        )

    def fit(self, paths: list[str | Path], labels: list[str]) -> "ByteHistogramLogisticDetector":
        _require_numpy()
        self.class_names = sorted(set(labels))
        if len(self.class_names) != 2:
            raise ValueError("ByteHistogramLogisticDetector supports binary classification only")
        self.positive_label, self.negative_label = _binary_label_order(self.class_names)
        x = np.asarray([byte_histogram(path, self.max_bytes) for path in paths], dtype=np.float64)  # type: ignore[union-attr]
        y = np.asarray([1.0 if label == self.positive_label else 0.0 for label in labels], dtype=np.float64)  # type: ignore[union-attr]
        mean = x.mean(axis=0)
        scale = x.std(axis=0)
        scale[scale < 1e-8] = 1.0
        x = (x - mean) / scale
        pos = float(y.sum())
        neg = float(len(y) - pos)
        if pos == 0 or neg == 0:
            raise ValueError("training data must contain both binary classes")
        sample_weights = np.where(y == 1.0, len(y) / (2.0 * pos), len(y) / (2.0 * neg))  # type: ignore[union-attr]
        weights = np.zeros(x.shape[1], dtype=np.float64)  # type: ignore[union-attr]
        bias = 0.0
        for _ in range(self.epochs):
            logits = x @ weights + bias
            probabilities = _sigmoid(logits)
            error = (probabilities - y) * sample_weights
            gradient = x.T @ error / len(y) + self.l2 * weights
            bias_gradient = float(error.mean())
            weights -= self.learning_rate * gradient
            bias -= self.learning_rate * bias_gradient
        self.weights = [float(value) for value in weights]
        self.bias = float(bias)
        self.mean = [float(value) for value in mean]
        self.scale = [float(value) for value in scale]
        self.threshold = 0.0
        self.validation_macro_f1 = 0.0
        self.validation_accuracy = 0.0
        return self

    def calibrate(self, paths: list[str | Path], labels: list[str]) -> "ByteHistogramLogisticDetector":
        scores = self.decision_function(paths)
        self.threshold, self.validation_macro_f1, self.validation_accuracy = _best_threshold(
            scores,
            labels,
            self.positive_label,
            self.negative_label,
            positive_when="above",
        )
        return self

    def decision_function(self, paths: list[str | Path]) -> list[float]:
        _require_numpy()
        if not self.weights:
            raise ValueError("detector is not fitted")
        x = np.asarray([byte_histogram(path, self.max_bytes) for path in paths], dtype=np.float64)  # type: ignore[union-attr]
        mean = np.asarray(self.mean, dtype=np.float64)  # type: ignore[union-attr]
        scale = np.asarray(self.scale, dtype=np.float64)  # type: ignore[union-attr]
        weights = np.asarray(self.weights, dtype=np.float64)  # type: ignore[union-attr]
        logits = ((x - mean) / scale) @ weights + self.bias
        return [float(value) for value in logits]

    def predict(self, paths: list[str | Path]) -> list[str]:
        return [
            self.positive_label if score >= self.threshold else self.negative_label
            for score in self.decision_function(paths)
        ]

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "weights": self.weights,
                    "bias": self.bias,
                    "mean": self.mean,
                    "scale": self.scale,
                    "class_names": self.class_names,
                    "positive_label": self.positive_label,
                    "negative_label": self.negative_label,
                    "threshold": self.threshold,
                    "validation_macro_f1": self.validation_macro_f1,
                    "validation_accuracy": self.validation_accuracy,
                    "detector_name": self.detector_name,
                    "max_bytes": self.max_bytes,
                    "epochs": self.epochs,
                    "learning_rate": self.learning_rate,
                    "l2": self.l2,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "ByteHistogramLogisticDetector":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            weights=[float(value) for value in payload["weights"]],
            bias=float(payload["bias"]),
            mean=[float(value) for value in payload["mean"]],
            scale=[float(value) for value in payload["scale"]],
            class_names=list(payload["class_names"]),
            positive_label=str(payload.get("positive_label", "malware")),
            negative_label=str(payload.get("negative_label", "benign")),
            threshold=float(payload.get("threshold", 0.0)),
            validation_macro_f1=float(payload.get("validation_macro_f1", 0.0)),
            validation_accuracy=float(payload.get("validation_accuracy", 0.0)),
            detector_name=str(payload.get("detector_name", "byte_histogram_logistic")),
            max_bytes=payload.get("max_bytes"),
            epochs=int(payload.get("epochs", 800)),
            learning_rate=float(payload.get("learning_rate", 0.05)),
            l2=float(payload.get("l2", 1e-4)),
        )


@dataclass
class HybridCentroidDetector:
    """Dependency-free hybrid PE-feature + raw-byte centroid detector."""

    centroids: dict[str, dict[str, float]]
    feature_names: list[str]
    class_names: list[str]
    detector_name: str = "hybrid_centroid"
    max_bytes: int | None = None

    @classmethod
    def create(cls, max_bytes: int | None = None) -> "HybridCentroidDetector":
        return cls(centroids={}, feature_names=[], class_names=[], max_bytes=max_bytes)

    def fit(self, paths: list[str | Path], labels: list[str]) -> "HybridCentroidDetector":
        rows = [hybrid_vector(path, self.max_bytes) for path in paths]
        self.feature_names = sorted({name for row in rows for name in row})
        self.class_names = sorted(set(labels))
        grouped: dict[str, list[dict[str, float]]] = {label: [] for label in self.class_names}
        for row, label in zip(rows, labels, strict=False):
            grouped[label].append(row)
        self.centroids = {
            label: {
                name: sum(row.get(name, 0.0) for row in label_rows) / max(len(label_rows), 1)
                for name in self.feature_names
            }
            for label, label_rows in grouped.items()
        }
        return self

    def predict(self, paths: list[str | Path]) -> list[str]:
        predictions: list[str] = []
        for path in paths:
            row = hybrid_vector(path, self.max_bytes)
            predictions.append(min(self.class_names, key=lambda label: self._distance(row, self.centroids[label])))
        return predictions

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
                    "max_bytes": self.max_bytes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "HybridCentroidDetector":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            centroids={label: {k: float(v) for k, v in values.items()} for label, values in payload["centroids"].items()},
            feature_names=list(payload["feature_names"]),
            class_names=list(payload["class_names"]),
            detector_name=str(payload.get("detector_name", "hybrid_centroid")),
            max_bytes=payload.get("max_bytes"),
        )


def byte_histogram(path: str | Path, max_bytes: int | None = None) -> list[float]:
    byte_values = load_bytes(path, max_bytes=max_bytes).byte_values
    counts = [0.0] * 256
    for value in byte_values:
        if 0 <= value <= 255:
            counts[value] += 1.0
    total = float(sum(counts)) or 1.0
    return [count / total for count in counts]


def hybrid_vector(path: str | Path, max_bytes: int | None = None) -> dict[str, float]:
    vector = {f"pe_{key}": float(value) for key, value in parse_pe(path).to_vector().items()}
    for index, value in enumerate(byte_histogram(path, max_bytes)):
        vector[f"byte_hist_{index:03d}"] = value
    return vector


def _mean_vectors(rows: list[list[float]]) -> list[float]:
    if not rows:
        return [0.0] * 256
    return [sum(row[index] for row in rows) / len(rows) for index in range(len(rows[0]))]


def _distance(left: list[float], right: list[float]) -> float:
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right, strict=False)))


def _binary_label_order(class_names: list[str]) -> tuple[str, str]:
    if len(class_names) != 2:
        return (class_names[0], class_names[-1]) if class_names else ("malware", "benign")
    if "malware" in class_names and "benign" in class_names:
        return "malware", "benign"
    return class_names[1], class_names[0]


def _binary_score(
    row: list[float],
    positive_label: str,
    negative_label: str,
    centroids: dict[str, list[float]],
) -> float:
    return _distance(row, centroids[positive_label]) - _distance(row, centroids[negative_label])


def _midpoint_threshold(
    rows: list[list[float]],
    labels: list[str],
    positive_label: str,
    negative_label: str,
    centroids: dict[str, list[float]],
) -> float:
    positive_scores = [
        _binary_score(row, positive_label, negative_label, centroids)
        for row, label in zip(rows, labels, strict=False)
        if label == positive_label
    ]
    negative_scores = [
        _binary_score(row, positive_label, negative_label, centroids)
        for row, label in zip(rows, labels, strict=False)
        if label == negative_label
    ]
    if not positive_scores or not negative_scores:
        return 0.0
    return (max(positive_scores) + min(negative_scores)) / 2.0


def _best_threshold(
    scores: list[float],
    labels: list[str],
    positive_label: str,
    negative_label: str,
    positive_when: str = "below",
) -> tuple[float, float, float]:
    if not scores:
        return 0.0, 0.0, 0.0
    candidates = _threshold_candidates(scores)
    best_threshold = candidates[0]
    best_macro_f1 = -1.0
    best_accuracy = -1.0
    for threshold in candidates:
        if positive_when == "above":
            predictions = [positive_label if score >= threshold else negative_label for score in scores]
        else:
            predictions = [positive_label if score <= threshold else negative_label for score in scores]
        macro_f1, accuracy = _binary_macro_f1_and_accuracy(labels, predictions, positive_label, negative_label)
        if (macro_f1, accuracy) > (best_macro_f1, best_accuracy):
            best_threshold = threshold
            best_macro_f1 = macro_f1
            best_accuracy = accuracy
    return best_threshold, best_macro_f1, best_accuracy


def _threshold_candidates(scores: list[float]) -> list[float]:
    ordered = sorted(set(scores))
    if len(ordered) == 1:
        return [ordered[0]]
    candidates = [ordered[0] - 1e-12, ordered[-1] + 1e-12]
    candidates.extend((left + right) / 2.0 for left, right in zip(ordered, ordered[1:], strict=False))
    return candidates


def _binary_macro_f1_and_accuracy(
    labels: list[str],
    predictions: list[str],
    positive_label: str,
    negative_label: str,
) -> tuple[float, float]:
    f1_scores = []
    for label in [negative_label, positive_label]:
        tp = sum(target == label and prediction == label for target, prediction in zip(labels, predictions, strict=False))
        predicted = sum(prediction == label for prediction in predictions)
        actual = sum(target == label for target in labels)
        precision = tp / predicted if predicted else 0.0
        recall = tp / actual if actual else 0.0
        f1_scores.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    accuracy = sum(target == prediction for target, prediction in zip(labels, predictions, strict=False)) / max(len(labels), 1)
    return sum(f1_scores) / len(f1_scores), accuracy


def _sigmoid(values):
    clipped = np.clip(values, -40.0, 40.0)  # type: ignore[union-attr]
    return 1.0 / (1.0 + np.exp(-clipped))  # type: ignore[union-attr]


def _require_numpy() -> None:
    if np is None:
        raise ImportError("numpy is required for ByteHistogramLogisticDetector")
