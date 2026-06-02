import torch.nn as nn
from torchvision.models import MobileNet_V3_Small_Weights, mobilenet_v3_small

from models.base_model import BaseModelAdapter


def build_mobilenet_v3_small(
    num_classes: int,
    pretrained: bool = True,
    freeze_backbone: bool = False,
) -> nn.Module:
    weights = MobileNet_V3_Small_Weights.DEFAULT if pretrained else None
    model = mobilenet_v3_small(weights=weights)

    in_features = model.classifier[-1].in_features
    model.classifier[-1] = nn.Linear(in_features, num_classes)

    set_backbone_trainable(model, is_trainable=not freeze_backbone)
    return model


def set_backbone_trainable(model: nn.Module, is_trainable: bool) -> None:
    for parameter in model.features.parameters():
        parameter.requires_grad = is_trainable


class MobileNetV3SmallAdapter(BaseModelAdapter):
    name = "mobilenet_v3_small"

    def build(
        self,
        num_classes: int,
        pretrained: bool = True,
        freeze_backbone: bool = False,
    ) -> nn.Module:
        return build_mobilenet_v3_small(
            num_classes=num_classes,
            pretrained=pretrained,
            freeze_backbone=freeze_backbone,
        )

    def set_backbone_trainable(self, model: nn.Module, is_trainable: bool) -> None:
        set_backbone_trainable(model=model, is_trainable=is_trainable)


MOBILENET_V3_SMALL_ADAPTER = MobileNetV3SmallAdapter()
