from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CARFPMalATConfig:
    clean_loss_weight: float = 1.0
    transformed_loss_weight: float = 1.0
    consistency_weight: float = 0.25
    weak_class_weight: float = 1.0
    mutation_risk_weight: float = 0.1


def describe_objective(config: CARFPMalATConfig = CARFPMalATConfig()) -> dict[str, float | str]:
    """Machine-readable description of the CAR-FP-MalAT objective.

    Full GPU training depends on the final BODMAS/SOREL manifest and detector
    choice. This helper keeps the algorithm configuration explicit and auditable.
    """

    return {
        "name": "CAR-FP-MalAT",
        "expanded_name": "Class-Adaptive Robust PE-Preserving Malware Adversarial Training",
        "clean_loss_weight": config.clean_loss_weight,
        "transformed_loss_weight": config.transformed_loss_weight,
        "consistency_weight": config.consistency_weight,
        "weak_class_weight": config.weak_class_weight,
        "mutation_risk_weight": config.mutation_risk_weight,
        "selection_metric": "validation_robust_min_macro_f1",
        "test_set_rule": "never update adaptive weights or select checkpoints from test-set metrics",
    }
