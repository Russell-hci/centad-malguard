from collections.abc import Sequence
from pathlib import Path

import pandas as pd
import torch

from evaluation.confusion_matrix import save_confusion_matrix
from evaluation.latency import measure_inference_latency
from evaluation.metrics import compute_classification_metrics


def count_parameters(model) -> int:
    return sum(parameter.numel() for parameter in model.parameters())


def estimate_model_size_mb(model) -> float:
    parameter_bytes = sum(parameter.numel() * parameter.element_size() for parameter in model.parameters())
    buffer_bytes = sum(buffer.numel() * buffer.element_size() for buffer in model.buffers())
    return (parameter_bytes + buffer_bytes) / (1024 ** 2)


def run_inference(model, dataloader, device: str) -> tuple[list[int], list[int]]:
    model = model.to(device)
    model.eval()

    predictions: list[int] = []
    targets: list[int] = []

    with torch.inference_mode():
        for images, labels in dataloader:
            images = images.to(device)
            labels = labels.to(device)

            logits = model(images)
            batch_predictions = torch.argmax(logits, dim=1)

            predictions.extend(batch_predictions.cpu().tolist())
            targets.extend(labels.cpu().tolist())

    return targets, predictions


def benchmark_model(
    model,
    dataloader,
    class_names: Sequence[str],
    device: str = "cpu",
    confusion_matrix_path: str | Path | None = None,
    input_size: tuple[int, int, int, int] = (1, 3, 224, 224),
) -> dict[str, float]:
    targets, predictions = run_inference(model, dataloader, device=device)
    metrics = compute_classification_metrics(targets, predictions, class_names=class_names)
    latency_metrics = measure_inference_latency(model, device=device, input_size=input_size)

    results = {
        **metrics,
        **latency_metrics,
        "parameter_count": float(count_parameters(model)),
        "model_size_mb": estimate_model_size_mb(model),
    }

    if confusion_matrix_path is not None:
        save_confusion_matrix(
            targets=targets,
            predictions=predictions,
            class_names=class_names,
            output_path=confusion_matrix_path,
        )

    return results


def save_benchmark_results(results: dict[str, float], output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([results]).to_csv(output_path, index=False)
