from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence


def classification_summary(
    targets: Sequence[str],
    predictions: Sequence[str],
    labels: Sequence[str] | None = None,
) -> dict[str, float]:
    labels_list = list(labels) if labels is not None else sorted(set(targets) | set(predictions))
    precision, recall, f1, support = _per_label_scores(targets, predictions, labels_list)
    macro_precision = sum(precision) / len(labels_list) if labels_list else 0.0
    macro_recall = sum(recall) / len(labels_list) if labels_list else 0.0
    macro_f1 = sum(f1) / len(labels_list) if labels_list else 0.0
    result: dict[str, float] = {
        "accuracy": float(_accuracy(targets, predictions)),
        "macro_precision": float(macro_precision),
        "macro_recall": float(macro_recall),
        "macro_f1": float(macro_f1),
        "worst_class_f1": float(min(f1) if len(f1) else 0.0),
        "classes_below_f1_050": float(sum(value < 0.50 for value in f1)),
        "classes_below_f1_080": float(sum(value < 0.80 for value in f1)),
    }
    for label, label_precision, label_recall, label_f1, label_support in zip(
        labels_list, precision, recall, f1, support, strict=False
    ):
        safe = "".join(ch.lower() if ch.isalnum() else "_" for ch in label).strip("_")
        result[f"{safe}_precision"] = float(label_precision)
        result[f"{safe}_recall"] = float(label_recall)
        result[f"{safe}_f1"] = float(label_f1)
        result[f"{safe}_support"] = float(label_support)
    return result


def _accuracy(targets: Sequence[str], predictions: Sequence[str]) -> float:
    if not targets:
        return 0.0
    return sum(target == prediction for target, prediction in zip(targets, predictions, strict=False)) / len(targets)


def _per_label_scores(
    targets: Sequence[str],
    predictions: Sequence[str],
    labels: Sequence[str],
) -> tuple[list[float], list[float], list[float], list[int]]:
    true_counts = Counter(targets)
    predicted_counts = Counter(predictions)
    tp = defaultdict(int)
    for target, prediction in zip(targets, predictions, strict=False):
        if target == prediction:
            tp[target] += 1
    precision: list[float] = []
    recall: list[float] = []
    f1: list[float] = []
    support: list[int] = []
    for label in labels:
        label_tp = tp[label]
        label_precision = label_tp / predicted_counts[label] if predicted_counts[label] else 0.0
        label_recall = label_tp / true_counts[label] if true_counts[label] else 0.0
        label_f1 = (
            2 * label_precision * label_recall / (label_precision + label_recall)
            if label_precision + label_recall
            else 0.0
        )
        precision.append(float(label_precision))
        recall.append(float(label_recall))
        f1.append(float(label_f1))
        support.append(int(true_counts[label]))
    return precision, recall, f1, support


def robustness_summary(
    clean_predictions: Sequence[str],
    transformed_predictions: Sequence[str],
    targets: Sequence[str],
    labels: Sequence[str] | None = None,
) -> dict[str, float]:
    clean = classification_summary(targets, clean_predictions, labels)
    transformed = classification_summary(targets, transformed_predictions, labels)
    changed = sum(a != b for a, b in zip(clean_predictions, transformed_predictions, strict=False))
    total = max(len(clean_predictions), 1)
    attack_success = sum(
        clean_pred == target and transformed_pred != target
        for clean_pred, transformed_pred, target in zip(clean_predictions, transformed_predictions, targets, strict=False)
    )
    clean_correct = max(sum(pred == target for pred, target in zip(clean_predictions, targets, strict=False)), 1)
    return {
        "clean_accuracy": clean["accuracy"],
        "clean_macro_f1": clean["macro_f1"],
        "transformed_accuracy": transformed["accuracy"],
        "transformed_macro_f1": transformed["macro_f1"],
        "robust_min_macro_f1": min(clean["macro_f1"], transformed["macro_f1"]),
        "prediction_stability": float(1.0 - changed / total),
        "attack_success_rate": float(attack_success / clean_correct),
        "transformed_worst_class_f1": transformed["worst_class_f1"],
        "transformed_classes_below_f1_050": transformed["classes_below_f1_050"],
        "transformed_classes_below_f1_080": transformed["classes_below_f1_080"],
    }
