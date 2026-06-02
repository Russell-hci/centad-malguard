from abc import ABC, abstractmethod

import torch.nn as nn


class BaseModelAdapter(ABC):
    name: str

    @abstractmethod
    def build(
        self,
        num_classes: int,
        pretrained: bool = True,
        freeze_backbone: bool = False,
    ) -> nn.Module:
        raise NotImplementedError

    @abstractmethod
    def set_backbone_trainable(self, model: nn.Module, is_trainable: bool) -> None:
        raise NotImplementedError
