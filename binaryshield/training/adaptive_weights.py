from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdaptiveWeightConfig:
    target_f1: float = 0.80
    max_weight: float = 5.0
    min_weight: float = 1.0
    smoothing: float = 0.5


def update_class_weights(
    previous_weights: dict[str, float],
    validation_f1: dict[str, float],
    config: AdaptiveWeightConfig = AdaptiveWeightConfig(),
) -> dict[str, float]:
    """Update weak-class weights using validation metrics only."""

    updated: dict[str, float] = {}
    labels = set(previous_weights) | set(validation_f1)
    for label in labels:
        current = previous_weights.get(label, 1.0)
        f1 = validation_f1.get(label, config.target_f1)
        deficit = max(0.0, config.target_f1 - f1)
        target = min(config.max_weight, max(config.min_weight, 1.0 + deficit / max(config.target_f1, 1e-6)))
        updated[label] = config.smoothing * current + (1.0 - config.smoothing) * target
    return updated
