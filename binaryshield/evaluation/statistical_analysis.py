from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

LABELS = ["benign", "malware"]


def macro_f1(targets: Iterable[str], predictions: Iterable[str]) -> float:
    return float(f1_score(list(targets), list(predictions), average="macro", labels=LABELS, zero_division=0))


def exact_mcnemar_pvalue(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    try:
        from scipy.stats import binomtest
        return float(binomtest(min(b, c), n=n, p=0.5, alternative="two-sided").pvalue)
    except Exception:
        # Exact two-sided binomial fallback.
        from math import comb
        k = min(b, c)
        prob = sum(comb(n, i) for i in range(0, k + 1)) / (2**n)
        return float(min(1.0, 2.0 * prob))


def load_prediction_csv(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {"sample_id", "target", "clean_prediction", "transformed_prediction"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"{path} missing required columns: {sorted(missing)}")
    return df


def evaluable_predictions(df: pd.DataFrame) -> pd.DataFrame:
    return df.dropna(subset=["sample_id", "target", "clean_prediction", "transformed_prediction"]).copy()


def attack_success_rate(clean_correct: np.ndarray, transformed_correct: np.ndarray) -> float:
    denom = int(clean_correct.sum())
    if denom == 0:
        return float("nan")
    return float((clean_correct & ~transformed_correct).sum() / denom)


def metric_values(df: pd.DataFrame) -> dict[str, float]:
    ev = evaluable_predictions(df)
    target = ev["target"].astype(str).to_numpy()
    clean = ev["clean_prediction"].astype(str).to_numpy()
    transformed = ev["transformed_prediction"].astype(str).to_numpy()
    clean_correct = clean == target
    transformed_correct = transformed == target
    return {
        "row_count": float(len(ev)),
        "clean_macro_f1_paired": macro_f1(target, clean),
        "transformed_macro_f1": macro_f1(target, transformed),
        "prediction_stability": float((clean == transformed).mean()) if len(ev) else float("nan"),
        "attack_success_rate": attack_success_rate(clean_correct, transformed_correct),
    }


def bootstrap_ci(
    df: pd.DataFrame,
    metric: Callable[[pd.DataFrame], float],
    *,
    samples: int = 2000,
    seed: int = 1337,
) -> tuple[float, float, float]:
    ev = evaluable_predictions(df).reset_index(drop=True)
    if ev.empty:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    n = len(ev)
    point = float(metric(ev))
    values = np.empty(samples, dtype=float)
    for i in range(samples):
        idx = rng.integers(0, n, size=n)
        values[i] = float(metric(ev.iloc[idx]))
    return point, float(np.nanpercentile(values, 2.5)), float(np.nanpercentile(values, 97.5))


def paired_flip_counts(df: pd.DataFrame) -> dict[str, int]:
    ev = evaluable_predictions(df)
    target = ev["target"].astype(str).to_numpy()
    clean = ev["clean_prediction"].astype(str).to_numpy()
    transformed = ev["transformed_prediction"].astype(str).to_numpy()
    clean_correct = clean == target
    transformed_correct = transformed == target
    return {
        "n": int(len(ev)),
        "clean_correct_to_transformed_incorrect": int((clean_correct & ~transformed_correct).sum()),
        "clean_incorrect_to_transformed_correct": int((~clean_correct & transformed_correct).sum()),
        "unchanged_correct": int((clean_correct & transformed_correct).sum()),
        "unchanged_incorrect": int((~clean_correct & ~transformed_correct).sum()),
        "total_prediction_flips": int((clean != transformed).sum()),
        "total_label_correctness_flips": int((clean_correct != transformed_correct).sum()),
    }


def mcnemar_clean_vs_transformed(df: pd.DataFrame, name: str) -> dict[str, object]:
    counts = paired_flip_counts(df)
    b = counts["clean_correct_to_transformed_incorrect"]
    c = counts["clean_incorrect_to_transformed_correct"]
    return {
        "comparison": name,
        "n": counts["n"],
        "b_clean_correct_transformed_incorrect": b,
        "c_clean_incorrect_transformed_correct": c,
        "p_value_exact_binomial": exact_mcnemar_pvalue(b, c),
        "method": "exact two-sided binomial McNemar test",
    }


def mcnemar_model_vs_model(df_a: pd.DataFrame, df_b: pd.DataFrame, name: str) -> dict[str, object]:
    a = evaluable_predictions(df_a)[["sample_id", "target", "transformed_prediction"]].rename(columns={"transformed_prediction": "pred_a"})
    b = evaluable_predictions(df_b)[["sample_id", "transformed_prediction"]].rename(columns={"transformed_prediction": "pred_b"})
    joined = a.merge(b, on="sample_id", how="inner")
    target = joined["target"].astype(str).to_numpy()
    ca = joined["pred_a"].astype(str).to_numpy() == target
    cb = joined["pred_b"].astype(str).to_numpy() == target
    b_count = int((ca & ~cb).sum())
    c_count = int((~ca & cb).sum())
    return {
        "comparison": name,
        "n": int(len(joined)),
        "b_a_correct_b_incorrect": b_count,
        "c_a_incorrect_b_correct": c_count,
        "p_value_exact_binomial": exact_mcnemar_pvalue(b_count, c_count),
        "method": "exact two-sided binomial McNemar test",
    }


def metric_ci_rows(prediction_files: dict[str, Path], samples: int = 2000, seed: int = 1337) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for condition, path in prediction_files.items():
        df = load_prediction_csv(path)
        metrics = {
            "clean_macro_f1_paired": lambda x: macro_f1(x["target"], x["clean_prediction"]),
            "transformed_macro_f1": lambda x: macro_f1(x["target"], x["transformed_prediction"]),
            "prediction_stability": lambda x: float((x["clean_prediction"].astype(str).to_numpy() == x["transformed_prediction"].astype(str).to_numpy()).mean()),
            "attack_success_rate": lambda x: attack_success_rate(
                x["clean_prediction"].astype(str).to_numpy() == x["target"].astype(str).to_numpy(),
                x["transformed_prediction"].astype(str).to_numpy() == x["target"].astype(str).to_numpy(),
            ),
        }
        for metric_name, func in metrics.items():
            point, lo, hi = bootstrap_ci(df, func, samples=samples, seed=seed)
            rows.append({"condition": condition, "metric": metric_name, "point": point, "ci_low": lo, "ci_high": hi, "bootstrap_samples": samples, "seed": seed})
    return rows


def paired_delta_rows(prediction_files: dict[str, Path], samples: int = 2000, seed: int = 1337) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for condition, path in prediction_files.items():
        df = load_prediction_csv(path)
        def clean_minus_trans(x: pd.DataFrame) -> float:
            return macro_f1(x["target"], x["clean_prediction"]) - macro_f1(x["target"], x["transformed_prediction"])
        point, lo, hi = bootstrap_ci(df, clean_minus_trans, samples=samples, seed=seed)
        rows.append({"comparison": f"clean_minus_{condition}", "metric": "macro_f1_delta", "point": point, "ci_low": lo, "ci_high": hi, "bootstrap_samples": samples, "seed": seed})
    if set(prediction_files) >= {"append", "slack"}:
        app = evaluable_predictions(load_prediction_csv(prediction_files["append"]))[["sample_id", "target", "transformed_prediction"]].rename(columns={"transformed_prediction": "append_prediction"})
        sl = evaluable_predictions(load_prediction_csv(prediction_files["slack"]))[["sample_id", "transformed_prediction"]].rename(columns={"transformed_prediction": "slack_prediction"})
        joined = app.merge(sl, on="sample_id", how="inner")
        def append_minus_slack(x: pd.DataFrame) -> float:
            return macro_f1(x["target"], x["append_prediction"]) - macro_f1(x["target"], x["slack_prediction"])
        point, lo, hi = bootstrap_ci(joined.rename(columns={"append_prediction":"clean_prediction","slack_prediction":"transformed_prediction"}), lambda x: append_minus_slack(x.rename(columns={"clean_prediction":"append_prediction","transformed_prediction":"slack_prediction"})), samples=samples, seed=seed)
        rows.append({"comparison": "append_minus_slack", "metric": "macro_f1_delta", "point": point, "ci_low": lo, "ci_high": hi, "bootstrap_samples": samples, "seed": seed})
    return rows
