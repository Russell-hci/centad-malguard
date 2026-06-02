from collections.abc import Sequence

import torch
import torch.nn as nn
import torchattacks

from preprocessing.transforms import IMAGENET_MEAN, IMAGENET_STD


class NormalizedModel(nn.Module):
    """Apply ImageNet normalization inside the model for pixel-space attacks."""

    def __init__(
        self,
        model: nn.Module,
        mean: Sequence[float] = IMAGENET_MEAN,
        std: Sequence[float] = IMAGENET_STD,
    ) -> None:
        super().__init__()
        self.model = model
        self.register_buffer("mean", torch.tensor(mean).view(1, 3, 1, 1))
        self.register_buffer("std", torch.tensor(std).view(1, 3, 1, 1))

    def forward(self, images: torch.Tensor) -> torch.Tensor:
        normalized_images = (images - self.mean) / self.std
        return self.model(normalized_images)


def denormalize_images(
    normalized_images: torch.Tensor,
    mean: Sequence[float] = IMAGENET_MEAN,
    std: Sequence[float] = IMAGENET_STD,
) -> torch.Tensor:
    mean_tensor = torch.tensor(
        mean,
        dtype=normalized_images.dtype,
        device=normalized_images.device,
    ).view(1, 3, 1, 1)
    std_tensor = torch.tensor(
        std,
        dtype=normalized_images.dtype,
        device=normalized_images.device,
    ).view(1, 3, 1, 1)
    return (normalized_images * std_tensor + mean_tensor).clamp(0.0, 1.0)


def normalize_images(
    raw_images: torch.Tensor,
    mean: Sequence[float] = IMAGENET_MEAN,
    std: Sequence[float] = IMAGENET_STD,
) -> torch.Tensor:
    mean_tensor = torch.tensor(
        mean,
        dtype=raw_images.dtype,
        device=raw_images.device,
    ).view(1, 3, 1, 1)
    std_tensor = torch.tensor(
        std,
        dtype=raw_images.dtype,
        device=raw_images.device,
    ).view(1, 3, 1, 1)
    return (raw_images - mean_tensor) / std_tensor


def build_fgsm_attack(model: nn.Module, epsilon: float) -> torchattacks.FGSM:
    return torchattacks.FGSM(model, eps=epsilon)
