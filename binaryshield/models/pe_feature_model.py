from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
except ImportError:  # pragma: no cover - depends on local environment
    joblib = None
    np = None
    RandomForestClassifier = None
    Pipeline = None
    StandardScaler = None

from binaryshield.pe_features import parse_pe


@dataclass
class PEFeatureSklearnDetector:
    """A strong, dependency-light PE-feature baseline.

    This detector intentionally uses static PE features only. It is useful as a
    non-neural baseline for generalizability and transfer evaluation.
    """

    model: Any
    feature_names: list[str]
    class_names: list[str]
    detector_name: str = "pe_feature_sklearn"

    @classmethod
    def random_forest(
        cls,
        n_estimators: int = 200,
        random_state: int = 1337,
        class_weight: str | dict[str, float] | None = "balanced",
    ) -> "PEFeatureSklearnDetector":
        if Pipeline is None or RandomForestClassifier is None or StandardScaler is None:
            raise ImportError("scikit-learn is required for PEFeatureSklearnDetector.random_forest")
        pipeline = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    RandomForestClassifier(
                        n_estimators=n_estimators,
                        random_state=random_state,
                        class_weight=class_weight,
                        n_jobs=-1,
                    ),
                ),
            ]
        )
        return cls(model=pipeline, feature_names=[], class_names=[])

    def _vectorize_paths(self, paths: list[str | Path]):
        if np is None:
            raise ImportError("numpy is required for PEFeatureSklearnDetector")
        rows: list[dict[str, float]] = [parse_pe(path).to_vector() for path in paths]
        if not self.feature_names:
            self.feature_names = sorted(rows[0].keys()) if rows else []
        return np.asarray([[row.get(name, 0.0) for name in self.feature_names] for row in rows], dtype=float)

    def fit(self, paths: list[str | Path], labels: list[str]) -> "PEFeatureSklearnDetector":
        self.class_names = sorted(set(labels))
        x = self._vectorize_paths(paths)
        self.model.fit(x, labels)
        return self

    def predict(self, paths: list[str | Path]) -> list[str]:
        x = self._vectorize_paths(paths)
        return [str(value) for value in self.model.predict(x)]

    def predict_proba(self, paths: list[str | Path]) -> np.ndarray:
        x = self._vectorize_paths(paths)
        if hasattr(self.model, "predict_proba"):
            return np.asarray(self.model.predict_proba(x), dtype=float)
        predictions = self.predict(paths)
        proba = np.zeros((len(predictions), len(self.class_names)), dtype=float)
        index = {name: i for i, name in enumerate(self.class_names)}
        for row, label in enumerate(predictions):
            proba[row, index[label]] = 1.0
        return proba

    def save(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("joblib is required to save PEFeatureSklearnDetector")
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_names": self.feature_names,
                "class_names": self.class_names,
                "detector_name": self.detector_name,
            },
            output,
        )

    @classmethod
    def load(cls, path: str | Path) -> "PEFeatureSklearnDetector":
        if joblib is None:
            raise ImportError("joblib is required to load PEFeatureSklearnDetector")
        payload = joblib.load(path)
        return cls(
            model=payload["model"],
            feature_names=list(payload["feature_names"]),
            class_names=list(payload["class_names"]),
            detector_name=payload.get("detector_name", "pe_feature_sklearn"),
        )
