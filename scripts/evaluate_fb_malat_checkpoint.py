from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import torch
from torch.utils.data import DataLoader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.fgsm import (
    NormalizedModel,
    build_fgsm_attack,
    denormalize_images,
)
from attacks.pgd import build_pgd_attack
from evaluation.metrics import compute_classification_metrics
from fb_malat.metrics import families_below_threshold, worst_family_f1
from models.efficientnet import EFFICIENTNET_B0_ADAPTER
from models.mobilenet import MOBILENET_V3_SMALL_ADAPTER
from preprocessing.dataset_loader import MalwareDataset
from preprocessing.transforms import get_eval_transforms
from utils.config import load_yaml_config
from utils.experiment import sha256_file, utc_timestamp
from utils.reproducibility import set_global_seed


MODEL_ADAPTERS = {
    MOBILENET_V3_SMALL_ADAPTER.name: MOBILENET_V3_SMALL_ADAPTER,
    EFFICIENTNET_B0_ADAPTER.name: EFFICIENTNET_B0_ADAPTER,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a MalGuard-X checkpoint under clean and adversarial attacks.",
    )
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--model", choices=sorted(MODEL_ADAPTERS), required=True)
    parser.add_argument(
        "--configs",
        type=Path,
        nargs="+",
        default=[
            Path("configs/evaluation/fb_malat_fgsm_003.yaml"),
            Path("configs/evaluation/fb_malat_pgd20.yaml"),
            Path("configs/evaluation/fb_malat_pgd50.yaml"),
        ],
    )
    parser.add_argument("--output-dir", type=Path, default=Path("results/fb_malat/evaluations"))
    parser.add_argument("--max-batches", type=int, default=None)
    parser.add_argument("--num-workers", type=int, default=None)
    return parser.parse_args()


def resolve_device(device_config: str) -> torch.device:
    if device_config != "auto":
        return torch.device(device_config)
    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def load_model(checkpoint_path: Path, model_name: str, device: torch.device):
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    class_names = checkpoint["class_names"]
    model = MODEL_ADAPTERS[model_name].build(
        num_classes=len(class_names),
        pretrained=False,
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()
    return model, class_names


def create_loader(
    config: dict[str, Any],
    class_names: list[str],
    num_workers_override: int | None = None,
) -> DataLoader:
    dataset = MalwareDataset(
        csv_path=config["test_csv"],
        class_names=class_names,
        transform=get_eval_transforms(image_size=int(config.get("image_size", 224))),
    )
    return DataLoader(
        dataset,
        batch_size=int(config.get("batch_size", 32)),
        shuffle=False,
        num_workers=int(
            num_workers_override
            if num_workers_override is not None
            else config.get("num_workers", 0)
        ),
        pin_memory=torch.cuda.is_available(),
    )


def family_key(class_name: str) -> str:
    return "".join(character.lower() if character.isalnum() else "_" for character in class_name).strip("_")


def add_family_summary(metrics: dict[str, float], class_names: list[str]) -> dict[str, float]:
    f1_values = [metrics.get(f"f1_{family_key(name)}", 0.0) for name in class_names]
    metrics["worst_family_f1"] = worst_family_f1(f1_values)
    metrics["families_below_0_50_f1"] = float(families_below_threshold(f1_values, 0.50))
    metrics["families_below_0_80_f1"] = float(families_below_threshold(f1_values, 0.80))
    return metrics


def evaluate_clean(
    model: torch.nn.Module,
    dataloader: DataLoader,
    class_names: list[str],
    device: torch.device,
    max_batches: int | None,
) -> tuple[dict[str, float], list[int], list[int]]:
    targets: list[int] = []
    predictions: list[int] = []
    model.eval()
    with torch.no_grad():
        for batch_index, (images, labels) in enumerate(dataloader):
            if max_batches is not None and batch_index >= max_batches:
                break
            images = images.to(device)
            labels = labels.to(device)
            logits = model(images)
            targets.extend(labels.cpu().tolist())
            predictions.extend(torch.argmax(logits, dim=1).cpu().tolist())
    metrics = compute_classification_metrics(targets, predictions, class_names)
    return add_family_summary(metrics, class_names), targets, predictions


def evaluate_attack(
    model: torch.nn.Module,
    dataloader: DataLoader,
    class_names: list[str],
    device: torch.device,
    config: dict[str, Any],
    max_batches: int | None,
) -> tuple[dict[str, float], list[int], list[int]]:
    targets: list[int] = []
    predictions: list[int] = []
    clean_correct = 0
    attack_successes = 0
    wrapped = NormalizedModel(model).to(device)
    if config["attack"] == "fgsm":
        attack = build_fgsm_attack(wrapped, float(config["epsilon"]))
    elif config["attack"] == "pgd":
        attack = build_pgd_attack(
            model=wrapped,
            epsilon=float(config["epsilon"]),
            alpha=float(config["alpha"]),
            steps=int(config["steps"]),
            random_start=bool(config.get("random_start", True)),
        )
    else:
        raise ValueError(f"Unsupported attack: {config['attack']}")

    model.eval()
    for batch_index, (images, labels) in enumerate(dataloader):
        if max_batches is not None and batch_index >= max_batches:
            break
        images = images.to(device)
        labels = labels.to(device)
        raw_images = denormalize_images(images)
        with torch.no_grad():
            clean_predictions = torch.argmax(model(images), dim=1)
        adv_raw = attack(raw_images, labels)
        model.eval()
        with torch.no_grad():
            attacked_predictions = torch.argmax(wrapped(adv_raw), dim=1)

        clean_mask = clean_predictions.eq(labels)
        clean_correct += int(clean_mask.sum().item())
        attack_successes += int((clean_mask & attacked_predictions.ne(labels)).sum().item())
        targets.extend(labels.cpu().tolist())
        predictions.extend(attacked_predictions.cpu().tolist())

    metrics = compute_classification_metrics(targets, predictions, class_names)
    metrics["attack_success_rate"] = attack_successes / clean_correct if clean_correct else 0.0
    metrics["clean_correct_samples"] = float(clean_correct)
    metrics["attack_success_samples"] = float(attack_successes)
    return add_family_summary(metrics, class_names), targets, predictions


def main() -> None:
    args = parse_args()
    first_config = load_yaml_config(args.configs[0])
    set_global_seed(int(first_config.get("seed", 42)))
    device = resolve_device(str(first_config.get("device", "auto")))
    model, class_names = load_model(args.checkpoint, args.model, device)
    timestamp = utc_timestamp()
    output_dir = args.output_dir / f"{args.model}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=False)

    rows: list[dict[str, Any]] = []
    prediction_rows: list[dict[str, Any]] = []

    clean_loader = create_loader(first_config, class_names, args.num_workers)
    clean_metrics, clean_targets, clean_predictions = evaluate_clean(
        model, clean_loader, class_names, device, args.max_batches
    )
    rows.append({"condition": "clean", **clean_metrics})
    for index, (target, prediction) in enumerate(zip(clean_targets, clean_predictions, strict=True)):
        prediction_rows.append(
            {
                "condition": "clean",
                "sample_index": index,
                "target": class_names[target],
                "prediction": class_names[prediction],
            }
        )

    for config_path in args.configs:
        config = load_yaml_config(config_path)
        loader = create_loader(config, class_names, args.num_workers)
        metrics, targets, predictions = evaluate_attack(
            model,
            loader,
            class_names,
            device,
            config,
            args.max_batches,
        )
        condition = str(config.get("name", config["attack"]))
        rows.append({"condition": condition, **metrics})
        for index, (target, prediction) in enumerate(zip(targets, predictions, strict=True)):
            prediction_rows.append(
                {
                    "condition": condition,
                    "sample_index": index,
                    "target": class_names[target],
                    "prediction": class_names[prediction],
                }
            )

    pd.DataFrame(rows).to_csv(output_dir / "metrics.csv", index=False)
    pd.DataFrame(prediction_rows).to_csv(output_dir / "predictions.csv", index=False)
    metadata = {
        "generated_at_utc": timestamp,
        "checkpoint": str(args.checkpoint),
        "checkpoint_sha256": sha256_file(args.checkpoint),
        "model": args.model,
        "configs": [str(path) for path in args.configs],
        "max_batches": args.max_batches,
        "device": str(device),
        "output_dir": str(output_dir),
    }
    (output_dir / "evaluation_metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )
    print(f"Saved FB-MalAT evaluation to {output_dir}")


if __name__ == "__main__":
    main()
