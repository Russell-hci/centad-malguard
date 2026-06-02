import argparse
import csv
import sys
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
import torch
from torch.utils.data import DataLoader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.fgsm import NormalizedModel, build_fgsm_attack, denormalize_images
from evaluation.confusion_matrix import save_confusion_matrix
from evaluation.metrics import compute_classification_metrics
from models.efficientnet import EFFICIENTNET_B0_ADAPTER
from models.mobilenet import MOBILENET_V3_SMALL_ADAPTER
from preprocessing.dataset_loader import MalwareDataset
from preprocessing.transforms import get_eval_transforms
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
    parser = argparse.ArgumentParser(description="Evaluate FGSM robustness.")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/fgsm.yaml"),
        help="Path to the FGSM evaluation config.",
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


def create_experiment_dir(output_dir: str | Path) -> tuple[Path, str]:
    timestamp = utc_timestamp()
    base_dir = Path(output_dir)
    for suffix in ["", *[f"_{index}" for index in range(1, 100)]]:
        experiment_dir = base_dir / f"fgsm_{timestamp}{suffix}"
        try:
            experiment_dir.mkdir(parents=True, exist_ok=False)
            return experiment_dir, timestamp
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique directory under {base_dir}")


def load_checkpoint_model(model_name: str, checkpoint_path: Path, device: torch.device):
    checkpoint = torch.load(checkpoint_path, map_location="cpu")
    class_names = checkpoint["class_names"]
    adapter = MODEL_ADAPTERS[model_name]
    model = adapter.build(num_classes=len(class_names), pretrained=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()
    return model, class_names


def create_test_loader(config: dict[str, Any], class_names: list[str]) -> DataLoader:
    dataset = MalwareDataset(
        csv_path=config["test_csv"],
        class_names=class_names,
        transform=get_eval_transforms(image_size=int(config.get("image_size", 224))),
    )
    return DataLoader(
        dataset,
        batch_size=int(config.get("batch_size", 32)),
        shuffle=False,
        num_workers=int(config.get("num_workers", 0)),
        pin_memory=torch.cuda.is_available(),
    )


def compute_clean_predictions(
    model: torch.nn.Module,
    dataloader: DataLoader,
    device: torch.device,
) -> tuple[list[int], list[int]]:
    targets: list[int] = []
    predictions: list[int] = []
    model.eval()
    with torch.no_grad():
        for normalized_images, labels in dataloader:
            labels = labels.to(device)
            raw_images = denormalize_images(normalized_images.to(device))
            logits = model(raw_images)
            targets.extend(labels.cpu().tolist())
            predictions.extend(torch.argmax(logits, dim=1).cpu().tolist())
    return targets, predictions


def run_sanity_check(
    model: torch.nn.Module,
    dataloader: DataLoader,
    device: torch.device,
    epsilon: float,
) -> dict[str, Any]:
    model.eval()
    normalized_images, labels = next(iter(dataloader))
    labels = labels.to(device)
    raw_images = denormalize_images(normalized_images.to(device))
    attack = build_fgsm_attack(model, epsilon)

    with torch.no_grad():
        clean_predictions = torch.argmax(model(raw_images), dim=1)

    adversarial_images = attack(raw_images, labels)
    perturbations = adversarial_images - raw_images

    model.eval()
    with torch.no_grad():
        attacked_predictions = torch.argmax(model(adversarial_images), dim=1)

    linf_per_sample = perturbations.detach().abs().flatten(1).max(dim=1).values
    return {
        "epsilon": epsilon,
        "batch_size": int(labels.size(0)),
        "clean_min": float(raw_images.min().item()),
        "clean_max": float(raw_images.max().item()),
        "adversarial_min": float(adversarial_images.min().item()),
        "adversarial_max": float(adversarial_images.max().item()),
        "max_linf_perturbation": float(linf_per_sample.max().item()),
        "mean_linf_perturbation": float(linf_per_sample.mean().item()),
        "linf_within_epsilon": bool(linf_per_sample.max().item() <= epsilon + 1e-6),
        "range_valid": bool(
            adversarial_images.min().item() >= -1e-6
            and adversarial_images.max().item() <= 1.0 + 1e-6
        ),
        "clean_batch_accuracy": float(clean_predictions.eq(labels).float().mean().item()),
        "attacked_batch_accuracy": float(attacked_predictions.eq(labels).float().mean().item()),
        "changed_predictions": int(attacked_predictions.ne(clean_predictions).sum().item()),
    }


def evaluate_epsilon(
    model: torch.nn.Module,
    dataloader: DataLoader,
    device: torch.device,
    epsilon: float,
    class_names: list[str],
) -> dict[str, Any]:
    attack = build_fgsm_attack(model, epsilon)
    targets: list[int] = []
    clean_predictions: list[int] = []
    attacked_predictions: list[int] = []
    clean_correct = 0
    attack_successes = 0

    model.eval()
    for normalized_images, labels in dataloader:
        labels = labels.to(device)
        raw_images = denormalize_images(normalized_images.to(device))

        with torch.no_grad():
            clean_batch_predictions = torch.argmax(model(raw_images), dim=1)

        adversarial_images = attack(raw_images, labels)

        model.eval()
        with torch.no_grad():
            attacked_batch_predictions = torch.argmax(model(adversarial_images), dim=1)

        clean_mask = clean_batch_predictions.eq(labels)
        clean_correct += int(clean_mask.sum().item())
        attack_successes += int(
            (clean_mask & attacked_batch_predictions.ne(labels)).sum().item()
        )

        targets.extend(labels.cpu().tolist())
        clean_predictions.extend(clean_batch_predictions.cpu().tolist())
        attacked_predictions.extend(attacked_batch_predictions.cpu().tolist())

    metrics = compute_classification_metrics(
        targets=targets,
        predictions=attacked_predictions,
        class_names=class_names,
    )
    metrics["attack_success_rate"] = (
        attack_successes / clean_correct if clean_correct else 0.0
    )
    metrics["clean_correct_samples"] = float(clean_correct)
    metrics["attack_success_samples"] = float(attack_successes)
    return {
        "targets": targets,
        "clean_predictions": clean_predictions,
        "attacked_predictions": attacked_predictions,
        "metrics": metrics,
    }


def write_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row.keys()})
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def plot_curves(summary: pd.DataFrame, output_dir: Path) -> dict[str, str]:
    paths = {}
    for metric, label, filename in [
        ("accuracy", "Accuracy", "accuracy_vs_epsilon.png"),
        ("f1", "Macro F1", "macro_f1_vs_epsilon.png"),
    ]:
        plt.figure(figsize=(8, 5))
        for model_name, model_frame in summary.groupby("model"):
            model_frame = model_frame.sort_values("epsilon")
            plt.plot(model_frame["epsilon"], model_frame[metric], marker="o", label=model_name)
        plt.xlabel("FGSM epsilon")
        plt.ylabel(label)
        plt.title(f"{label} vs FGSM Epsilon")
        plt.grid(alpha=0.3)
        plt.legend()
        plt.tight_layout()
        output_path = output_dir / filename
        plt.savefig(output_path, dpi=300)
        plt.close()
        paths[metric] = str(output_path)
    return paths


def main() -> None:
    args = parse_args()
    config = load_yaml_config(args.config)
    set_global_seed(int(config.get("seed", 42)))
    device = resolve_device(str(config.get("device", "auto")))
    experiment_dir, timestamp = create_experiment_dir(config.get("output_dir", "results/robustness/fgsm"))
    log_path = experiment_dir / "run.log"

    with log_path.open("w", encoding="utf-8") as log_handle:
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = TeeLogger(sys.stdout, log_handle)
        sys.stderr = TeeLogger(sys.stderr, log_handle)
        try:
            epsilons = [float(epsilon) for epsilon in config["epsilons"]]
            rows: list[dict[str, Any]] = []
            sanity_checks = {}
            model_outputs = {}

            print(f"FGSM output directory: {experiment_dir}")
            print(f"Device: {device}")

            for model_config in config["models"]:
                model_name = model_config["name"]
                checkpoint_path = Path(model_config["checkpoint_path"])
                baseline_metrics_path = Path(model_config["baseline_metrics_path"])
                model, class_names = load_checkpoint_model(model_name, checkpoint_path, device)
                wrapped_model = NormalizedModel(model).to(device)
                dataloader = create_test_loader(config, class_names)
                model_dir = experiment_dir / model_name
                model_dir.mkdir(parents=True, exist_ok=True)

                sanity_epsilon = float(config.get("sanity_check", {}).get("epsilon", max(epsilons)))
                sanity_checks[model_name] = run_sanity_check(
                    model=wrapped_model,
                    dataloader=dataloader,
                    device=device,
                    epsilon=sanity_epsilon,
                )
                if not sanity_checks[model_name]["linf_within_epsilon"]:
                    raise RuntimeError(f"FGSM sanity check exceeded epsilon for {model_name}.")
                if not sanity_checks[model_name]["range_valid"]:
                    raise RuntimeError(f"FGSM sanity check produced out-of-range images for {model_name}.")

                clean_targets, clean_predictions = compute_clean_predictions(
                    model=wrapped_model,
                    dataloader=dataloader,
                    device=device,
                )
                clean_metrics = compute_classification_metrics(
                    clean_targets,
                    clean_predictions,
                    class_names=class_names,
                )

                model_rows = []
                for epsilon in epsilons:
                    print(f"Evaluating {model_name} at epsilon={epsilon}")
                    result = evaluate_epsilon(
                        model=wrapped_model,
                        dataloader=dataloader,
                        device=device,
                        epsilon=epsilon,
                        class_names=class_names,
                    )
                    row = {
                        "model": model_name,
                        "epsilon": epsilon,
                        "checkpoint_path": str(checkpoint_path),
                        "baseline_metrics_path": str(baseline_metrics_path),
                        "clean_accuracy_recomputed": clean_metrics["accuracy"],
                        "clean_f1_recomputed": clean_metrics["f1"],
                        **result["metrics"],
                    }
                    rows.append(row)
                    model_rows.append(row)

                    save_confusion_matrix(
                        targets=result["targets"],
                        predictions=result["attacked_predictions"],
                        class_names=class_names,
                        output_path=model_dir / f"confusion_matrix_eps_{epsilon:.2f}.png",
                    )

                model_results_path = model_dir / "fgsm_results.csv"
                write_csv(model_rows, model_results_path)
                model_outputs[model_name] = {
                    "checkpoint_path": str(checkpoint_path),
                    "baseline_metrics_path": str(baseline_metrics_path),
                    "fgsm_results_path": str(model_results_path),
                }

            combined_results_path = experiment_dir / "fgsm_results.csv"
            write_csv(rows, combined_results_path)
            plot_paths = plot_curves(pd.DataFrame(rows), experiment_dir)
            sanity_path = experiment_dir / "sanity_check.json"
            write_json(sanity_checks, sanity_path)
            metadata_path = experiment_dir / "experiment_metadata.json"
            write_json(
                {
                    "manifest_type": "fgsm_experiment",
                    "timestamp_utc": timestamp,
                    "config_path": str(args.config),
                    "config_sha256": sha256_file(args.config),
                    "config": config,
                    "device": str(device),
                    "environment": get_environment_metadata(repo_root=PROJECT_ROOT),
                    "dataset_manifest_path": config.get("dataset_manifest_path"),
                    "split_manifest_path": config.get("split_manifest_path"),
                    "test_csv": config.get("test_csv"),
                    "test_csv_sha256": sha256_file(config["test_csv"]),
                    "combined_results_path": str(combined_results_path),
                    "sanity_check_path": str(sanity_path),
                    "plot_paths": plot_paths,
                    "model_outputs": model_outputs,
                    "run_log_path": str(log_path),
                },
                metadata_path,
            )
            print(f"Saved FGSM outputs to: {experiment_dir}")
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr


if __name__ == "__main__":
    main()
