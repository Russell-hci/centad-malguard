from __future__ import annotations

from collections.abc import Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support


def per_family_metrics(
    targets: Sequence[int],
    predictions: Sequence[int],
    class_names: Sequence[str],
    prefix: str,
) -> pd.DataFrame:
    labels = list(range(len(class_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        targets,
        predictions,
        labels=labels,
        average=None,
        zero_division=0,
    )
    return pd.DataFrame(
        {
            "family": list(class_names),
            f"{prefix}_precision": precision.astype(float),
            f"{prefix}_recall": recall.astype(float),
            f"{prefix}_f1": f1.astype(float),
            "support": support.astype(int),
        }
    )


def balanced_robustness(per_family_recall: Sequence[float]) -> float:
    values = np.asarray(per_family_recall, dtype=float)
    return float(values.mean()) if values.size else 0.0


def worst_family_f1(per_family_f1: Sequence[float]) -> float:
    values = np.asarray(per_family_f1, dtype=float)
    return float(values.min()) if values.size else 0.0


def families_below_threshold(per_family_f1: Sequence[float], threshold: float) -> int:
    values = np.asarray(per_family_f1, dtype=float)
    return int((values < threshold).sum())

