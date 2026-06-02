import argparse
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd
import torch
import torch.nn as nn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.fgsm import NormalizedModel, denormalize_images, normalize_images
from attacks.pgd import build_pgd_attack
from evaluation.benchmark import benchmark_model, save_benchmark_results
from models.mobilenet import MOBILENET_V3_SMALL_ADAPTER
from preprocessing.dataset_loader import create_dataloaders
from training.train import (
    EarlyStopping,
    apply_finetune_policy,
    build_optimizer,
    build_scheduler,
    compute_class_weights,
    count_correct,
    get_current_lr,
    run_eval_epoch,
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


MODEL_ADAPTER = MOBILENET_V3_SMALL_ADAPTER


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run PGD adversarial training for MobileNetV3 on MalImg.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/adversarial_training_mobilenet.yaml"),
        help="Path to the adversarial-training YAML config.",
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


def create_experiment_dir(output_dir: str | Path, model_name: str) -> tuple[Path, str]:
    timestamp = utc_timestamp()
    base_dir = Path(output_dir)
    for suffix in ["", *[f"_{index}" for index in range(1, 100)]]:
        experiment_dir = base_dir / f"{model_name}_pgd_adversarial_training_{timestamp}{suffix}"
        try:
            experiment_dir.mkdir(parents=True, exist_ok=False)
            return experiment_dir, timestamp
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique experiment directory in {base_dir}")


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
        "checkpoint_config": checkpoint.get("config"),
    }


def build_attack(model: nn.Module, config: dict[str, Any]):
    pgd_config = config["adversarial_training"]["pgd"]
    device = next(model.parameters()).device
    return build_pgd_attack(
        model=NormalizedModel(model).to(device),
        epsilon=float(pgd_config["epsilon"]),
        alpha=float(pgd_config["alpha"]),
        steps=int(pgd_config["steps"]),
        random_start=bool(pgd_config.get("random_start", True)),
    )


def make_mixed_batch(
    model: nn.Module,
    normalized_images: torch.Tensor,
    labels: torch.Tensor,
    adversarial_fraction: float,
    attack,
) -> tuple[torch.Tensor, int]:
    batch_size = labels.size(0)
    adversarial_count = max(1, int(round(batch_size * adversarial_fraction)))
    adversarial_count = min(adversarial_count, batch_size)

    indices = torch.randperm(batch_size, device=labels.device)
    adversarial_indices = indices[:adversarial_count]

    raw_images = denormalize_images(normalized_images)
    adversarial_raw = attack(raw_images[adversarial_indices], labels[adversarial_indices])
    model.train()

    mixed_images = normalized_images.clone()
    mixed_images[adversarial_indices] = normalize_images(adversarial_raw.detach())
    return mixed_images, adversarial_count


def run_adversarial_train_epoch(
    model: nn.Module,
    dataloader,
    criterion,
    optimizer,
    device: torch.device,
    config: dict[str, Any],
) -> dict[str, float]:
    model.train()
    attack = build_attack(model, config)
    adversarial_fraction = float(config["adversarial_training"].get("adversarial_fraction", 0.5))
    running_loss = 0.0
    correct = 0
    total = 0
    adversarial_total = 0

    for images, labels in dataloader:
        images = images.to(device)
        labels = labels.to(device)
        mixed_images, adversarial_count = make_mixed_batch(
            model=model,
            normalized_images=images,
            labels=labels,
            adversarial_fraction=adversarial_fraction,
            attack=attack,
        )

        optimizer.zero_grad(set_to_none=True)
        logits = model(mixed_images)
        loss = criterion(logits, labels)
        loss.backward()
        optimizer.step()

        batch_size = labels.size(0)
        running_loss += float(loss.item()) * batch_size
        correct += count_correct(logits, labels)
        total += batch_size
        adversarial_total += adversarial_count

    return {
        "loss": running_loss / max(total, 1),
        "accuracy": correct / max(total, 1),
        "adversarial_fraction_actual": adversarial_total / max(total, 1),
    }


def run_stage(
    model: nn.Module,
    dataloaders,
    criterion,
    config: dict[str, Any],
    stage_name: str,
    epochs: int,
    learning_rate: float,
    device: torch.device,
    history: list[dict[str, Any]],
    best_state: dict[str, Any],
    checkpoint_path: Path,
    class_names: list[str],
) -> None:
    if epochs <= 0:
        return

    trainable_parameters = [parameter for parameter in model.parameters() if parameter.requires_grad]
    if not trainable_parameters:
        raise RuntimeError(f"No trainable parameters available for stage: {stage_name}")

    optimizer = build_optimizer(trainable_parameters, config, learning_rate)
    scheduler, scheduler_step_mode = build_scheduler(optimizer, config, stage_name, epochs)
    early_config = config.get("early_stopping") or {}
    early_stopping = EarlyStopping(
        patience=int(early_config.get("patience", epochs)),
        min_delta=float(early_config.get("min_delta", 0.0)),
    )

    for epoch in range(1, epochs + 1):
        started_at = time.perf_counter()
        current_lr = get_current_lr(optimizer)
        train_metrics = run_adversarial_train_epoch(
            model=model,
            dataloader=dataloaders["train"],
            criterion=criterion,
            optimizer=optimizer,
            device=device,
            config=config,
        )
        val_metrics = run_eval_epoch(
            model=model,
            dataloader=dataloaders["val"],
            criterion=criterion,
            device=device,
        )
        elapsed_seconds = time.perf_counter() - started_at

        row = {
            "stage": stage_name,
            "epoch": epoch,
            "train_loss": train_metrics["loss"],
            "train_accuracy": train_metrics["accuracy"],
            "train_adversarial_fraction": train_metrics["adversarial_fraction_actual"],
            "val_loss_clean": val_metrics["loss"],
            "val_accuracy_clean": val_metrics["accuracy"],
            "learning_rate": current_lr,
            "epoch_elapsed_seconds": elapsed_seconds,
        }
        history.append(row)
        print(
            f"{stage_name} epoch {epoch}/{epochs} "
            f"train_loss={train_metrics['loss']:.4f} "
            f"train_acc={train_metrics['accuracy']:.4f} "
            f"adv_frac={train_metrics['adversarial_fraction_actual']:.3f} "
            f"val_loss_clean={val_metrics['loss']:.4f} "
            f"val_acc_clean={val_metrics['accuracy']:.4f} "
            f"elapsed={elapsed_seconds:.1f}s"
        )

        if val_metrics["loss"] < best_state["val_loss_clean"]:
            best_state["val_loss_clean"] = val_metrics["loss"]
            best_state["val_accuracy_clean"] = val_metrics["accuracy"]
            best_state["stage"] = stage_name
            best_state["epoch"] = epoch
            save_checkpoint(
                model=model,
                output_path=checkpoint_path,
                class_names=class_names,
                config=config,
                best_metrics=best_state,
            )

        if scheduler is not None and scheduler_step_mode == "plateau":
            scheduler.step(val_metrics["loss"])
        elif scheduler is not None:
            scheduler.step()

        if early_stopping.should_stop(val_metrics["loss"]):
            print(f"Early stopping triggered for {stage_name} at epoch {epoch}.")
            break


def build_metadata(
    config: dict[str, Any],
    config_path: Path,
    experiment_dir: Path,
    timestamp: str,
    class_names: list[str],
    device: torch.device,
    checkpoint_path: Path,
    metrics_path: Path,
    run_log_path: Path,
    initial_checkpoint_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    environment = get_environment_metadata(repo_root=PROJECT_ROOT)
    adversarial_fraction = float(config["adversarial_training"].get("adversarial_fraction", 0.5))
    return {
        "manifest_type": "pgd_adversarial_training_experiment",
        "timestamp_utc": timestamp,
        "config_path": str(config_path),
        "config_sha256": sha256_file(config_path),
        "config": config,
        "seed": config["seed"],
        "device": str(device),
        "environment": environment,
        "model": config["model"],
        "training_protocol": {
            "initialization": "official_duplicate_aware_baseline_checkpoint"
            if initial_checkpoint_metadata
            else "torchvision_pretrained_weights",
            "initial_checkpoint": initial_checkpoint_metadata,
            "clean_fraction": 1.0 - adversarial_fraction,
            "adversarial_fraction": adversarial_fraction,
            "pgd": config["adversarial_training"]["pgd"],
        },
        "dataset": {
            "train_csv": config["train_csv"],
            "val_csv": config["val_csv"],
            "test_csv": config["test_csv"],
            "train_csv_sha256": sha256_file(config["train_csv"]),
            "val_csv_sha256": sha256_file(config["val_csv"]),
            "test_csv_sha256": sha256_file(config["test_csv"]),
            "class_count": len(class_names),
            "class_names": class_names,
            "dataset_manifest_path": config.get("dataset_manifest_path"),
            "split_manifest_path": config.get("split_manifest_path"),
        },
        "output_dir": str(experiment_dir),
        "checkpoint_path": str(checkpoint_path),
        "metrics_path": str(metrics_path),
        "run_log_path": str(run_log_path),
    }


def main() -> None:
    args = parse_args()
    config = load_yaml_config(args.config)
    if config["model"] != MODEL_ADAPTER.name:
        raise ValueError("PGD adversarial training is currently scoped to MobileNetV3 only.")

    set_global_seed(
        seed=int(config["seed"]),
        deterministic=bool(config.get("deterministic", True)),
        cudnn_benchmark=bool(config.get("cudnn_benchmark", False)),
    )
    device = resolve_device(str(config.get("device", "auto")))
    experiment_dir, timestamp = create_experiment_dir(config["output_dir"], config["model"])
    checkpoint_path = experiment_dir / "best_model.pth"
    metrics_path = experiment_dir / "metrics.csv"
    run_log_path = experiment_dir / "run.log"

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    with run_log_path.open("a", encoding="utf-8") as log_handle:
        sys.stdout = TeeLogger(original_stdout, log_handle)
        sys.stderr = TeeLogger(original_stderr, log_handle)
        try:
            run_experiment(
                config=config,
                config_path=args.config,
                experiment_dir=experiment_dir,
                timestamp=timestamp,
                checkpoint_path=checkpoint_path,
                metrics_path=metrics_path,
                run_log_path=run_log_path,
                device=device,
            )
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr


def run_experiment(
    config: dict[str, Any],
    config_path: Path,
    experiment_dir: Path,
    timestamp: str,
    checkpoint_path: Path,
    metrics_path: Path,
    run_log_path: Path,
    device: torch.device,
) -> None:
    print(f"Adversarial training output directory: {experiment_dir}")
    print(f"Device: {device}")
    print(f"PGD training config: {config['adversarial_training']['pgd']}")

    dataloaders, class_names = create_dataloaders(
        train_csv=config["train_csv"],
        val_csv=config["val_csv"],
        test_csv=config["test_csv"],
        batch_size=int(config["batch_size"]),
        num_workers=int(config["num_workers"]),
        image_size=int(config["image_size"]),
    )

    model = MODEL_ADAPTER.build(
        num_classes=len(class_names),
        pretrained=bool(config.get("pretrained", True)),
        freeze_backbone=False,
    )
    initial_checkpoint_metadata = load_initial_weights(model, config)
    model.to(device)

    class_weights = None
    if bool(config.get("weighted_loss", False)):
        class_weights = compute_class_weights(dataloaders["train"].dataset, class_names, device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    metadata = build_metadata(
        config=config,
        config_path=config_path,
        experiment_dir=experiment_dir,
        timestamp=timestamp,
        class_names=class_names,
        device=device,
        checkpoint_path=checkpoint_path,
        metrics_path=metrics_path,
        run_log_path=run_log_path,
        initial_checkpoint_metadata=initial_checkpoint_metadata,
    )
    write_json(metadata, experiment_dir / "experiment_metadata.json")

    history: list[dict[str, Any]] = []
    best_state = {
        "val_loss_clean": float("inf"),
        "val_accuracy_clean": 0.0,
        "stage": None,
        "epoch": None,
    }
    started_at = time.perf_counter()

    MODEL_ADAPTER.set_backbone_trainable(model, is_trainable=False)
    run_stage(
        model=model,
        dataloaders=dataloaders,
        criterion=criterion,
        config=config,
        stage_name="head",
        epochs=int(config.get("epochs_head", 0)),
        learning_rate=float(config["learning_rate_head"]),
        device=device,
        history=history,
        best_state=best_state,
        checkpoint_path=checkpoint_path,
        class_names=class_names,
    )

    if checkpoint_path.exists():
        checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
        model.load_state_dict(checkpoint["model_state_dict"])

    apply_finetune_policy(model, MODEL_ADAPTER, config)
    run_stage(
        model=model,
        dataloaders=dataloaders,
        criterion=criterion,
        config=config,
        stage_name="adversarial_finetune",
        epochs=int(config["epochs_finetune"]),
        learning_rate=float(config["learning_rate_finetune"]),
        device=device,
        history=history,
        best_state=best_state,
        checkpoint_path=checkpoint_path,
        class_names=class_names,
    )

    training_elapsed_seconds = time.perf_counter() - started_at
    if not checkpoint_path.exists():
        save_checkpoint(
            model=model,
            output_path=checkpoint_path,
            class_names=class_names,
            config=config,
            best_metrics=best_state,
        )

    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    pd.DataFrame(history).to_csv(experiment_dir / "history.csv", index=False)

    metrics = benchmark_model(
        model=model,
        dataloader=dataloaders["test"],
        class_names=class_names,
        device=str(device),
        confusion_matrix_path=experiment_dir / "confusion_matrix.png",
        input_size=(1, 3, int(config["image_size"]), int(config["image_size"])),
    )
    metrics.update(
        {
            "model": config["model"],
            "defense": "pgd_adversarial_training",
            "training_elapsed_seconds": training_elapsed_seconds,
            "best_val_loss_clean": best_state["val_loss_clean"],
            "best_val_accuracy_clean": best_state["val_accuracy_clean"],
            "best_stage": best_state["stage"],
            "best_epoch": best_state["epoch"],
        }
    )
    save_benchmark_results(metrics, metrics_path)

    metadata["best_validation"] = best_state
    metadata["training_elapsed_seconds"] = training_elapsed_seconds
    metadata["test_metrics"] = metrics
    write_json(metadata, experiment_dir / "experiment_metadata.json")
    print(f"Saved adversarial-training outputs to: {experiment_dir}")


if __name__ == "__main__":
    main()
