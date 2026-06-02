from collections.abc import Sequence
from pathlib import Path

import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix


def save_confusion_matrix(
    targets: Sequence[int],
    predictions: Sequence[int],
    class_names: Sequence[str],
    output_path: str | Path,
) -> None:
    matrix = confusion_matrix(targets, predictions)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(10, 8))
    plt.imshow(matrix, interpolation="nearest", cmap="Blues")
    plt.colorbar()
    tick_positions = range(len(class_names))
    plt.xticks(tick_positions, class_names, rotation=75, ha="right")
    plt.yticks(tick_positions, class_names)
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
