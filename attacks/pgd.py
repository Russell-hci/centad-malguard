import torch.nn as nn
import torchattacks


def build_pgd_attack(
    model: nn.Module,
    epsilon: float,
    alpha: float,
    steps: int,
    random_start: bool = True,
) -> torchattacks.PGD:
    return torchattacks.PGD(
        model,
        eps=epsilon,
        alpha=alpha,
        steps=steps,
        random_start=random_start,
    )
