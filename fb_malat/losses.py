from __future__ import annotations

from collections.abc import Sequence

import torch
import torch.nn as nn
import torch.nn.functional as F


class BalancedSoftmaxLoss(nn.Module):
    """Balanced Softmax Loss for long-tailed classification.

    The loss uses class-count adjusted logits:

        CE(logits + log(class_counts), targets)

    This matches the Balanced Softmax formulation used by AT-BSL-style
    long-tailed adversarial training. Counts are clamped to avoid log(0).
    """

    def __init__(
        self,
        class_counts: Sequence[int] | torch.Tensor,
        reduction: str = "mean",
    ) -> None:
        super().__init__()
        if reduction not in {"mean", "none"}:
            raise ValueError("BalancedSoftmaxLoss reduction must be 'mean' or 'none'.")
        counts = torch.as_tensor(class_counts, dtype=torch.float32).clamp_min(1.0)
        self.register_buffer("log_class_counts", torch.log(counts))
        self.reduction = reduction

    def forward(
        self,
        logits: torch.Tensor,
        targets: torch.Tensor,
        sample_weights: torch.Tensor | None = None,
    ) -> torch.Tensor:
        adjusted_logits = logits + self.log_class_counts.to(logits.device)
        losses = F.cross_entropy(adjusted_logits, targets, reduction="none")
        if sample_weights is not None:
            weights = sample_weights.to(device=logits.device, dtype=losses.dtype)
            losses = losses * weights
            return losses.sum() / weights.sum().clamp_min(1e-8)
        if self.reduction == "none":
            return losses
        return losses.mean()


def class_counts_from_labels(labels: Sequence[int], num_classes: int) -> torch.Tensor:
    counts = torch.zeros(num_classes, dtype=torch.float32)
    for label in labels:
        counts[int(label)] += 1.0
    return counts.clamp_min(1.0)
