from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
except ImportError:  # pragma: no cover - optional dependency
    joblib = None
    np = None
    ExtraTreesClassifier = None
    RandomForestClassifier = None


@dataclass
class FeatureRecordSklearnDetector:
    """Sklearn detector for BODMAS-style PE-derived feature records."""

    model: Any
    class_names: list[str]
    detector_name: str

    @classmethod
    def create(
        cls,
        model_type: str = "extra_trees",
        *,
        n_estimators: int = 300,
        random_state: int = 1337,
        class_weight: str | dict[str, float] | None = "balanced",
    ) -> "FeatureRecordSklearnDetector":
        if np is None or ExtraTreesClassifier is None or RandomForestClassifier is None:
            raise ImportError("scikit-learn, joblib, and numpy are required for FeatureRecordSklearnDetector")
        if model_type == "extra_trees":
            model = ExtraTreesClassifier(
                n_estimators=n_estimators,
                random_state=random_state,
                class_weight=class_weight,
                n_jobs=-1,
                max_features="sqrt",
            )
        elif model_type == "random_forest":
            model = RandomForestClassifier(
                n_estimators=n_estimators,
                random_state=random_state,
                class_weight=class_weight,
                n_jobs=-1,
                max_features="sqrt",
            )
        else:
            raise ValueError(f"unsupported feature-record sklearn model type: {model_type}")
        return cls(model=model, class_names=[], detector_name=f"feature_record_{model_type}")

    def fit(self, rows: Any, labels: list[str]) -> "FeatureRecordSklearnDetector":
        if np is None:
            raise ImportError("numpy is required for FeatureRecordSklearnDetector")
        matrix = np.asarray(rows, dtype=np.float32)
        self.class_names = sorted(set(labels))
        self.model.fit(matrix, labels)
        return self

    def predict_rows(self, rows: Any) -> list[str]:
        if np is None:
            raise ImportError("numpy is required for FeatureRecordSklearnDetector")
        matrix = np.asarray(rows, dtype=np.float32)
        return [str(value) for value in self.model.predict(matrix)]

    def save(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("joblib is required to save FeatureRecordSklearnDetector")
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "class_names": self.class_names,
                "detector_name": self.detector_name,
            },
            output,
        )

    @classmethod
    def load(cls, path: str | Path) -> "FeatureRecordSklearnDetector":
        if joblib is None:
            raise ImportError("joblib is required to load FeatureRecordSklearnDetector")
        payload = joblib.load(path)
        return cls(
            model=payload["model"],
            class_names=list(payload["class_names"]),
            detector_name=str(payload.get("detector_name", "feature_record_sklearn")),
        )
