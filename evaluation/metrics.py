from collections.abc import Sequence

from sklearn.metrics import accuracy_score, precision_recall_fscore_support


def normalize_metric_label(label: str) -> str:
    return "".join(character.lower() if character.isalnum() else "_" for character in label).strip("_")


def compute_classification_metrics(
    targets: Sequence[int],
    predictions: Sequence[int],
    class_names: Sequence[str] | None = None,
) -> dict[str, float]:
    accuracy = accuracy_score(targets, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        targets,
        predictions,
        average="macro",
        zero_division=0,
    )

    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }

    if class_names is None:
        return metrics

    labels = list(range(len(class_names)))
    per_class_precision, per_class_recall, per_class_f1, per_class_support = precision_recall_fscore_support(
        targets,
        predictions,
        labels=labels,
        average=None,
        zero_division=0,
    )

    for index, class_name in enumerate(class_names):
        label_key = normalize_metric_label(class_name)
        metrics[f"precision_{label_key}"] = float(per_class_precision[index])
        metrics[f"recall_{label_key}"] = float(per_class_recall[index])
        metrics[f"f1_{label_key}"] = float(per_class_f1[index])
        metrics[f"support_{label_key}"] = float(per_class_support[index])

    return metrics
