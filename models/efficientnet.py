import torch.nn as nn
from torchvision.models import EfficientNet_B0_Weights, efficientnet_b0

from models.base_model import BaseModelAdapter


def build_efficientnet_b0(
    num_classes: int,
    pretrained: bool = True,
    freeze_backbone: bool = False,
) -> nn.Module:
    weights = EfficientNet_B0_Weights.DEFAULT if pretrained else None
    model = efficientnet_b0(weights=weights)

    in_features = model.classifier[-1].in_features
    model.classifier[-1] = nn.Linear(in_features, num_classes)

    set_backbone_trainable(model, is_trainable=not freeze_backbone)
    return model


def set_backbone_trainable(model: nn.Module, is_trainable: bool) -> None:
    for parameter in model.features.parameters():
        parameter.requires_grad = is_trainable


class EfficientNetB0Adapter(BaseModelAdapter):
    name = "efficientnet_b0"

    def build(
        self,
        num_classes: int,
        pretrained: bool = True,
        freeze_backbone: bool = False,
    ) -> nn.Module:
        return build_efficientnet_b0(
            num_classes=num_classes,
            pretrained=pretrained,
            freeze_backbone=freeze_backbone,
        )

    def set_backbone_trainable(self, model: nn.Module, is_trainable: bool) -> None:
        set_backbone_trainable(model=model, is_trainable=is_trainable)


EFFICIENTNET_B0_ADAPTER = EfficientNetB0Adapter()
