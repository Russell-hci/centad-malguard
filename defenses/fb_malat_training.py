from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, WeightedRandomSampler

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.fgsm import NormalizedModel, denormalize_images, normalize_images
from attacks.pgd import build_pgd_attack
from evaluation.metrics import compute_classification_metrics
from fb_malat.losses import BalancedSoftmaxLoss
from fb_malat.metrics import families_below_threshold, worst_family_f1
from models.efficientnet import EFFICIENTNET_B0_ADAPTER
from models.mobilenet import MOBILENET_V3_SMALL_ADAPTER
from preprocessing.dataset_loader import MalwareDataset, infer_class_names
from preprocessing.transforms import (
    get_conservative_train_transforms,
    get_eval_transforms,
)
from training.train import (
    apply_finetune_policy,
    build_optimizer,
    build_scheduler,
    get_current_lr,
    save_checkpoint,
)
from utils.config import load_yaml_config
from utils.experiment import (
    TeeLogger,
    get_environment_metadata,
    sha256_file,
    utc_timestamp,
    write_json,
)
from utils.reproducibility import set_global_seed


MODEL_ADAPTERS = {
    MOBILENET_V3_SMALL_ADAPTER.name: MOBILENET_V3_SMALL_ADAPTER,
    EFFICIENTNET_B0_ADAPTER.name: EFFICIENTNET_B0_ADAPTER,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train FB-MalAT with Balanced Softmax and robust macro-F1 checkpointing.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/defense/fb_malat/at_bsl_mobilenet_v3.yaml"),
    )
    return parser.parse_args()


def resolve_device(device_config: str) -> torch.device:
    if device_config != "auto":
        return torch.device(device_config)
    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def create_experiment_dir(output_dir: str | Path, model_name: str, method: str) -> tuple[Path, str]:
    timestamp = utc_timestamp()
    base_dir = Path(output_dir)
    for suffix in ["", *[f"_{index}" for index in range(1, 100)]]:
        experiment_dir = base_dir / f"{model_name}_{method}_{timestamp}{suffix}"
        try:
            experiment_dir.mkdir(parents=True, exist_ok=False)
            return experiment_dir, timestamp
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique experiment directory in {base_dir}")


def create_fb_malat_dataloaders(config: dict[str, Any]) -> tuple[dict[str, DataLoader], list[str]]:
    class_names = infer_class_names(
        [config["train_csv"], config["val_csv"], config["test_csv"]]
    )
    image_size = int(config.get("image_size", 224))
    augmentation = config.get("augmentation") or {}
    datasets = {
        "train": MalwareDataset(
            csv_path=config["train_csv"],
            class_names=class_names,
            transform=get_conservative_train_transforms(
                image_size=image_size,
                translate=float(augmentation.get("translate", 0.0)),
                gaussian_noise_std=float(augmentation.get("gaussian_noise_std", 0.0)),
            ),
        ),
        "val": MalwareDataset(
            csv_path=config["val_csv"],
            class_names=class_names,
            transform=get_eval_transforms(image_size=image_size),
        ),
        "test": MalwareDataset(
            csv_path=config["test_csv"],
            class_names=class_names,
            transform=get_eval_transforms(image_size=image_size),
        ),
    }
    train_loader_kwargs: dict[str, Any] = {}
    if bool(config.get("balanced_sampler", False)):
        label_counts = Counter(datasets["train"].dataframe["label"])
        sample_weights = [
            1.0 / label_counts[label]
            for label in datasets["train"].dataframe["label"].tolist()
        ]
        train_loader_kwargs["sampler"] = WeightedRandomSampler(
            weights=torch.DoubleTensor(sample_weights),
            num_samples=len(sample_weights),
            replacement=True,
        )
        train_loader_kwargs["shuffle"] = False
    else:
        train_loader_kwargs["shuffle"] = True

    dataloaders = {
        "train": DataLoader(
            datasets["train"],
            batch_size=int(config.get("batch_size", 32)),
            num_workers=int(config.get("num_workers", 0)),
            pin_memory=torch.cuda.is_available(),
            **train_loader_kwargs,
        ),
        "val": DataLoader(
            datasets["val"],
            batch_size=int(config.get("eval_batch_size", config.get("batch_size", 32))),
            shuffle=False,
            num_workers=int(config.get("num_workers", 0)),
            pin_memory=torch.cuda.is_available(),
        ),
        "test": DataLoader(
            datasets["test"],
            batch_size=int(config.get("eval_batch_size", config.get("batch_size", 32))),
            shuffle=False,
            num_workers=int(config.get("num_workers", 0)),
            pin_memory=torch.cuda.is_available(),
        ),
    }
    return dataloaders, class_names


def class_counts_from_dataset(dataset: MalwareDataset, class_names: list[str]) -> list[int]:
    label_counts = Counter(dataset.dataframe["label"])
    return [int(label_counts[class_name]) for class_name in class_names]


def build_class_weight_vector(config: dict[str, Any], class_names: list[str], device: torch.device) -> torch.Tensor:
    weights = torch.ones(len(class_names), dtype=torch.float32, device=device)
    weighting = config.get("weak_family_weighting") or {}
    if not bool(weighting.get("enabled", False)):
        return weights

    multiplier = float(weighting.get("multiplier", 1.0))
    weak_families = set(str(name) for name in weighting.get("families", []))
    for index, class_name in enumerate(class_names):
        if class_name in weak_families or normalize_family_name(class_name) in weak_families:
            weights[index] = multiplier
    return weights


def load_initial_weights(model: nn.Module, config: dict[str, Any]) -> dict[str, Any] | None:
    checkpoint_path = config.get("initial_checkpoint_path")
    if not checkpoint_path:
        return None
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    return {
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_sha256": sha256_file(checkpoint_path),
        "checkpoint_best_metrics": checkpoint.get("best_metrics"),
    }


def build_attack(model: nn.Module, pgd_config: dict[str, Any]):
    device = next(model.parameters()).device
    return build_pgd_attack(
        model=NormalizedModel(model).to(device),
        epsilon=float(pgd_config["epsilon"]),
        alpha=float(pgd_config["alpha"]),
        steps=int(pgd_config["steps"]),
        random_start=bool(pgd_config.get("random_start", True)),
    )


def train_one_epoch(
    model: nn.Module,
    dataloader: DataLoader,
    criterion: BalancedSoftmaxLoss,
    optimizer: torch.optim.Optimizer,
    device: torch.device,
    config: dict[str, Any],
    class_weight_vector: torch.Tensor,
) -> dict[str, float]:
    model.train()
    pgd_config = config["adversarial_training"]["pgd"]
    attack = build_attack(model, pgd_config)
    lambda_clean = float(config["loss"].get("lambda_clean", 0.25))
    lambda_adv = float(config["loss"].get("lambda_adv", 1.0))
    max_batches = config.get("max_train_batches")

    running_loss = 0.0
    running_clean_loss = 0.0
    running_adv_loss = 0.0
    correct = 0
    total = 0

    for batch_index, (images, labels) in enumerate(dataloader):
        if max_batches is not None and batch_index >= int(max_batches):
            break
        images = images.to(device)
        labels = labels.to(device)

        raw_images = denormalize_images(images)
        adversarial_raw = attack(raw_images, labels)
        model.train()
        adversarial_images = normalize_images(adversarial_raw.detach())

        optimizer.zero_grad(set_to_none=True)
        clean_logits = model(images)
        adv_logits = model(adversarial_images)
        sample_weights = class_weight_vector[labels]
        clean_loss = criterion(clean_logits, labels, sample_weights=sample_weights)
        adv_loss = criterion(adv_logits, labels, sample_weights=sample_weights)
        loss = lambda_clean * clean_loss + lambda_adv * adv_loss
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=float(config.get("grad_clip", 1.0)))
        optimizer.step()

        batch_size = labels.size(0)
        running_loss += float(loss.item()) * batch_size
        running_clean_loss += float(clean_loss.item()) * batch_size
        running_adv_loss += float(adv_loss.item()) * batch_size
        correct += int(torch.argmax(adv_logits, dim=1).eq(labels).sum().item())
        total += batch_size

    return {
        "train_loss": running_loss / max(total, 1),
        "train_clean_loss": running_clean_loss / max(total, 1),
        "train_adv_loss": running_adv_loss / max(total, 1),
        "train_adv_accuracy": correct / max(total, 1),
    }


def evaluate(
    model: nn.Module,
    dataloader: DataLoader,
    class_names: list[str],
    device: torch.device,
    attack_config: dict[str, Any] | None = None,
    max_batches: int | None = None,
) -> dict[str, Any]:
    model.eval()
    attack = build_attack(model, attack_config) if attack_config is not None else None
    wrapped_model = NormalizedModel(model).to(device) if attack_config is not None else None
    targets: list[int] = []
    predictions: list[int] = []

    for batch_index, (images, labels) in enumerate(dataloader):
        if max_batches is not None and batch_index >= max_batches:
            break
        images = images.to(device)
        labels = labels.to(device)

        if attack is None:
            with torch.no_grad():
                logits = model(images)
        else:
            raw_images = denormalize_images(images)
            adversarial_raw = attack(raw_images, labels)
            model.eval()
            with torch.no_grad():
                logits = wrapped_model(adversarial_raw)

        targets.extend(labels.cpu().tolist())
        predictions.extend(torch.argmax(logits, dim=1).cpu().tolist())

    metrics = compute_classification_metrics(
        targets=targets,
        predictions=predictions,
        class_names=class_names,
    )
    per_family_f1 = [
        metrics[f"f1_{class_name}"]
        for class_name in [normalize_family_name(name) for name in class_names]
        if f"f1_{class_name}" in metrics
    ]
    metrics["worst_family_f1"] = worst_family_f1(per_family_f1)
    metrics["families_below_0_50_f1"] = float(families_below_threshold(per_family_f1, 0.50))
    metrics["families_below_0_80_f1"] = float(families_below_threshold(per_family_f1, 0.80))
    return {
        "targets": targets,
        "predictions": predictions,
        "metrics": metrics,
    }


def normalize_family_name(name: str) -> str:
    return "".join(character.lower() if character.isalnum() else "_" for character in name).strip("_")


def normalize_condition_name(name: str) -> str:
    return "".join(character.lower() if character.isalnum() else "_" for character in name).strip("_")


def should_improve(metric_name: str, candidate: dict[str, float], best: dict[str, float]) -> bool:
    return float(candidate.get(metric_name, -1.0)) > float(best.get(metric_name, -1.0))


def validation_attack_configs(validation_config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    attacks = validation_config.get("attacks")
    if attacks:
        parsed: list[tuple[str, dict[str, Any]]] = []
        for attack_entry in attacks:
            name = normalize_condition_name(str(attack_entry["name"]))
            attack_config = dict(attack_entry)
            attack_config.pop("name", None)
            if "attack" not in attack_config:
                attack_config["attack"] = "pgd"
            parsed.append((name, attack_config))
        return parsed

    pgd_config = dict(validation_config["pgd"])
    pgd_config.setdefault("attack", "pgd")
    return [("pgd20", pgd_config)]


def build_metadata(
    config: dict[str, Any],
    config_path: Path,
    experiment_dir: Path,
    timestamp: str,
    class_names: list[str],
    device: torch.device,
    initial_checkpoint_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "manifest_type": "fb_malat_training_experiment",
        "timestamp_utc": timestamp,
        "config_path": str(config_path),
        "config_sha256": sha256_file(config_path),
        "config": config,
        "seed": config["seed"],
        "device": str(device),
        "environment": get_environment_metadata(repo_root=PROJECT_ROOT),
        "model": config["model"],
        "method": config.get("method", "at_bsl"),
        "initial_checkpoint": initial_checkpoint_metadata,
        "dataset": {
            "train_csv": config["train_csv"],
            "val_csv": config["val_csv"],
            "test_csv": config["test_csv"],
            "train_csv_sha256": sha256_file(config["train_csv"]),
            "val_csv_sha256": sha256_file(config["val_csv"]),
            "test_csv_sha256": sha256_file(config["test_csv"]),
            "class_count": len(class_names),
            "class_names": class_names,
        },
        "output_dir": str(experiment_dir),
    }


def run_experiment(config: dict[str, Any], config_path: Path, device: torch.device) -> None:
    adapter = MODEL_ADAPTERS[str(config["model"])]
    method = str(config.get("method", "at_bsl"))
    experiment_dir, timestamp = create_experiment_dir(config["output_dir"], adapter.name, method)
    checkpoint_path = experiment_dir / "best_model.pth"
    metrics_path = experiment_dir / "metrics.csv"
    history_path = experiment_dir / "history.csv"

    print(f"FB-MalAT output directory: {experiment_dir}")
    print(f"Device: {device}")
    dataloaders, class_names = create_fb_malat_dataloaders(config)
    model = adapter.build(
        num_classes=len(class_names),
        pretrained=bool(config.get("pretrained", True)),
        freeze_backbone=False,
    )
    initial_checkpoint_metadata = load_initial_weights(model, config)
    model.to(device)

    class_counts = class_counts_from_dataset(dataloaders["train"].dataset, class_names)
    criterion = BalancedSoftmaxLoss(class_counts).to(device)
    class_weight_vector = build_class_weight_vector(config, class_names, device)
    metadata = build_metadata(
        config=config,
        config_path=config_path,
        experiment_dir=experiment_dir,
        timestamp=timestamp,
        class_names=class_names,
        device=device,
        initial_checkpoint_metadata=initial_checkpoint_metadata,
    )
    metadata["class_counts"] = dict(zip(class_names, class_counts, strict=True))
    write_json(metadata, experiment_dir / "experiment_metadata.json")

    apply_finetune_policy(model, adapter, config)
    trainable_parameters = [parameter for parameter in model.parameters() if parameter.requires_grad]
    optimizer = build_optimizer(trainable_parameters, config, float(config["learning_rate"]))
    scheduler, scheduler_step_mode = build_scheduler(
        optimizer,
        config,
        "fb_malat",
        int(config["epochs"]),
    )
    validation_attacks = validation_attack_configs(config["validation"])
    selection_metric = str(config["validation"].get("selection_metric", "pgd20_macro_f1"))
    patience = int(config.get("early_stopping", {}).get("patience", int(config["epochs"])))
    min_delta = float(config.get("early_stopping", {}).get("min_delta", 0.0))
    best_state: dict[str, Any] = {selection_metric: -1.0, "epoch": 0}
    bad_epochs = 0
    history: list[dict[str, Any]] = []
    started_at = time.perf_counter()

    for epoch in range(1, int(config["epochs"]) + 1):
        epoch_start = time.perf_counter()
        lr = get_current_lr(optimizer)
        train_metrics = train_one_epoch(
            model=model,
            dataloader=dataloaders["train"],
            criterion=criterion,
            optimizer=optimizer,
            device=device,
            config=config,
            class_weight_vector=class_weight_vector,
        )
        clean_eval = evaluate(
            model=model,
            dataloader=dataloaders["val"],
            class_names=class_names,
            device=device,
            attack_config=None,
            max_batches=config["validation"].get("max_eval_batches"),
        )["metrics"]
        row = {
            "epoch": epoch,
            "learning_rate": lr,
            **train_metrics,
            "val_clean_accuracy": clean_eval["accuracy"],
            "val_clean_macro_f1": clean_eval["f1"],
        }
        adversarial_macro_f1_values: list[float] = []
        adversarial_accuracy_values: list[float] = []
        for attack_name, attack_config in validation_attacks:
            attack_eval = evaluate(
                model=model,
                dataloader=dataloaders["val"],
                class_names=class_names,
                device=device,
                attack_config=attack_config,
                max_batches=config["validation"].get("max_eval_batches"),
            )["metrics"]
            row[f"val_{attack_name}_accuracy"] = attack_eval["accuracy"]
            row[f"val_{attack_name}_macro_f1"] = attack_eval["f1"]
            row[f"val_{attack_name}_worst_family_f1"] = attack_eval["worst_family_f1"]
            row[f"val_{attack_name}_families_below_0_50_f1"] = attack_eval["families_below_0_50_f1"]
            row[f"val_{attack_name}_families_below_0_80_f1"] = attack_eval["families_below_0_80_f1"]
            adversarial_macro_f1_values.append(float(attack_eval["f1"]))
            adversarial_accuracy_values.append(float(attack_eval["accuracy"]))

        if "val_pgd20_macro_f1" in row:
            row["val_pgd_macro_f1"] = row["val_pgd20_macro_f1"]
            row["val_pgd_accuracy"] = row["val_pgd20_accuracy"]
            row["val_pgd_worst_family_f1"] = row["val_pgd20_worst_family_f1"]
            row["val_pgd_families_below_0_50_f1"] = row["val_pgd20_families_below_0_50_f1"]
            row["val_pgd_families_below_0_80_f1"] = row["val_pgd20_families_below_0_80_f1"]

        row["val_robust_min_macro_f1"] = min(adversarial_macro_f1_values) if adversarial_macro_f1_values else 0.0
        row["val_robust_min_accuracy"] = min(adversarial_accuracy_values) if adversarial_accuracy_values else 0.0
        row["epoch_elapsed_seconds"] = time.perf_counter() - epoch_start
        if selection_metric not in row:
            row[selection_metric] = row.get("val_pgd20_macro_f1", row["val_robust_min_macro_f1"])
        history.append(row)
        print(
            f"epoch {epoch}/{config['epochs']} "
            f"train_adv_acc={row['train_adv_accuracy']:.4f} "
            f"val_clean_f1={row['val_clean_macro_f1']:.4f} "
            f"val_pgd_f1={row.get('val_pgd_macro_f1', 0.0):.4f} "
            f"val_robust_min_f1={row['val_robust_min_macro_f1']:.4f} "
            f"val_pgd_worst={row.get('val_pgd_worst_family_f1', 0.0):.4f} "
            f"elapsed={row['epoch_elapsed_seconds']:.1f}s"
        )

        if should_improve(selection_metric, row, best_state):
            improvement = float(row[selection_metric]) - float(best_state[selection_metric])
            best_state = dict(row)
            best_state["selection_metric"] = selection_metric
            save_checkpoint(
                model=model,
                output_path=checkpoint_path,
                class_names=class_names,
                config=config,
                best_metrics=best_state,
            )
            bad_epochs = 0 if improvement > min_delta else bad_epochs + 1
        else:
            bad_epochs += 1

        if scheduler is not None and scheduler_step_mode == "plateau":
            scheduler.step(1.0 - float(row[selection_metric]))
        elif scheduler is not None:
            scheduler.step()

        if bad_epochs >= patience:
            print(f"Early stopping triggered at epoch {epoch}.")
            break

    pd.DataFrame(history).to_csv(history_path, index=False)
    final_metrics = {
        "model": adapter.name,
        "method": method,
        "selection_metric": selection_metric,
        "training_elapsed_seconds": time.perf_counter() - started_at,
        **{f"best_{key}": value for key, value in best_state.items() if isinstance(value, int | float | str)},
    }
    pd.DataFrame([final_metrics]).to_csv(metrics_path, index=False)
    metadata["best_validation"] = best_state
    metadata["training_elapsed_seconds"] = final_metrics["training_elapsed_seconds"]
    metadata["checkpoint_path"] = str(checkpoint_path)
    metadata["metrics_path"] = str(metrics_path)
    metadata["history_path"] = str(history_path)
    write_json(metadata, experiment_dir / "experiment_metadata.json")
    print(f"Saved FB-MalAT outputs to: {experiment_dir}")


def main() -> None:
    args = parse_args()
    config = load_yaml_config(args.config)
    set_global_seed(
        seed=int(config["seed"]),
        deterministic=bool(config.get("deterministic", True)),
        cudnn_benchmark=bool(config.get("cudnn_benchmark", False)),
    )
    device = resolve_device(str(config.get("device", "auto")))
    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / f"fb_malat_dispatch_{utc_timestamp()}.log"
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    with log_path.open("a", encoding="utf-8") as log_handle:
        sys.stdout = TeeLogger(original_stdout, log_handle)
        sys.stderr = TeeLogger(original_stderr, log_handle)
        try:
            run_experiment(config=config, config_path=args.config, device=device)
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr


if __name__ == "__main__":
    main()
