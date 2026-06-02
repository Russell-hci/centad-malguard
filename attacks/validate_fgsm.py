import argparse
import csv
import sys
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.fgsm import NormalizedModel, build_fgsm_attack, denormalize_images
from models.efficientnet import EFFICIENTNET_B0_ADAPTER
from models.mobilenet import MOBILENET_V3_SMALL_ADAPTER
from preprocessing.dataset_loader import MalwareDataset
from preprocessing.transforms import get_eval_transforms
from utils.config import load_yaml_config
from utils.experiment import get_environment_metadata, utc_timestamp, write_json
from utils.reproducibility import set_global_seed


MODEL_ADAPTERS = {
    MOBILENET_V3_SMALL_ADAPTER.name: MOBILENET_V3_SMALL_ADAPTER,
    EFFICIENTNET_B0_ADAPTER.name: EFFICIENTNET_B0_ADAPTER,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate FGSM perturbations and examples.")
    parser.add_argument("--config", type=Path, default=Path("configs/fgsm.yaml"))
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/robustness/fgsm_validation"),
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


def load_model(model_name: str, checkpoint_path: Path, device: torch.device):
    checkpoint = torch.load(checkpoint_path, map_location="cpu")
    class_names = checkpoint["class_names"]
    model = MODEL_ADAPTERS[model_name].build(
        num_classes=len(class_names),
        pretrained=False,
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device).eval()
    return NormalizedModel(model).to(device).eval(), class_names


def create_loader(config: dict[str, Any], class_names: list[str]) -> DataLoader:
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


def write_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def save_example_figure(
    clean_image: torch.Tensor,
    adversarial_image: torch.Tensor,
    epsilon: float,
    output_path: Path,
    title: str,
) -> None:
    clean_np = clean_image.detach().cpu().permute(1, 2, 0).numpy()
    adv_np = adversarial_image.detach().cpu().permute(1, 2, 0).numpy()
    delta = adversarial_image - clean_image
    signed_delta = (delta.detach().cpu().permute(1, 2, 0).numpy() / (2 * epsilon)) + 0.5
    signed_delta = signed_delta.clip(0.0, 1.0)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure, axes = plt.subplots(1, 3, figsize=(9, 3))
    for axis in axes:
        axis.axis("off")
    axes[0].imshow(clean_np)
    axes[0].set_title("Clean")
    axes[1].imshow(adv_np)
    axes[1].set_title("FGSM")
    axes[2].imshow(signed_delta)
    axes[2].set_title("Signed delta")
    figure.suptitle(title, fontsize=9)
    figure.tight_layout()
    figure.savefig(output_path, dpi=200)
    plt.close(figure)


def record_example(
    examples: dict[str, dict[str, Any]],
    category: str,
    payload: dict[str, Any],
) -> None:
    if category not in examples:
        examples[category] = payload.copy()


def analyze_model_epsilon(
    model_name: str,
    model: torch.nn.Module,
    class_names: list[str],
    loader: DataLoader,
    epsilon: float,
    output_dir: Path,
    device: torch.device,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    attack = build_fgsm_attack(model, epsilon)
    model.eval()

    total = 0
    clean_correct = 0
    adversarial_correct = 0
    attack_successes = 0
    changed_predictions = 0
    mean_abs_sum = 0.0
    l2_sum = 0.0
    clipped_low = 0
    clipped_high = 0
    pixel_count = 0
    linf_values: list[float] = []
    examples: dict[str, dict[str, Any]] = {}
    global_index = 0

    for normalized_images, labels in loader:
        labels = labels.to(device)
        clean_images = denormalize_images(normalized_images.to(device))

        with torch.no_grad():
            clean_logits = model(clean_images)
            clean_probs = F.softmax(clean_logits, dim=1)
            clean_predictions_batch = clean_logits.argmax(dim=1)

        adversarial_images = attack(clean_images, labels)
        model.eval()

        with torch.no_grad():
            adversarial_logits = model(adversarial_images)
            adversarial_probs = F.softmax(adversarial_logits, dim=1)
            adversarial_predictions_batch = adversarial_logits.argmax(dim=1)

        perturbations = adversarial_images - clean_images
        flat = perturbations.detach().flatten(1)
        batch_linf = flat.abs().max(dim=1).values
        batch_l2 = flat.norm(p=2, dim=1)
        batch_mean_abs = flat.abs().mean(dim=1)

        clean_mask = clean_predictions_batch.eq(labels)
        adversarial_mask = adversarial_predictions_batch.eq(labels)
        success_mask = clean_mask & ~adversarial_mask
        failed_attack_mask = clean_mask & adversarial_mask

        batch_size = labels.size(0)
        total += batch_size
        clean_correct += int(clean_mask.sum().item())
        adversarial_correct += int(adversarial_mask.sum().item())
        attack_successes += int(success_mask.sum().item())
        changed_predictions += int(
            clean_predictions_batch.ne(adversarial_predictions_batch).sum().item()
        )
        mean_abs_sum += float(batch_mean_abs.sum().item())
        l2_sum += float(batch_l2.sum().item())
        linf_values.extend(batch_linf.cpu().tolist())
        clipped_low += int(adversarial_images.le(1e-7).sum().item())
        clipped_high += int(adversarial_images.ge(1.0 - 1e-7).sum().item())
        pixel_count += adversarial_images.numel()

        for batch_index in range(batch_size):
            true_index = int(labels[batch_index].item())
            clean_index = int(clean_predictions_batch[batch_index].item())
            adversarial_index = int(adversarial_predictions_batch[batch_index].item())
            payload = {
                "model": model_name,
                "epsilon": epsilon,
                "sample_index": global_index + batch_index,
                "true_label": class_names[true_index],
                "clean_prediction": class_names[clean_index],
                "adversarial_prediction": class_names[adversarial_index],
                "clean_true_confidence": float(clean_probs[batch_index, true_index].item()),
                "adversarial_true_confidence": float(
                    adversarial_probs[batch_index, true_index].item()
                ),
                "clean_prediction_confidence": float(
                    clean_probs[batch_index, clean_index].item()
                ),
                "adversarial_prediction_confidence": float(
                    adversarial_probs[batch_index, adversarial_index].item()
                ),
                "linf": float(batch_linf[batch_index].item()),
                "l2": float(batch_l2[batch_index].item()),
                "mean_abs": float(batch_mean_abs[batch_index].item()),
                "clean_image": clean_images[batch_index].detach().cpu(),
                "adversarial_image": adversarial_images[batch_index].detach().cpu(),
            }
            if clean_mask[batch_index]:
                record_example(examples, "clean_correct", payload)
            if success_mask[batch_index]:
                record_example(examples, "successful_attack", payload)
            if failed_attack_mask[batch_index]:
                record_example(examples, "failed_attack", payload)

        global_index += batch_size

    linf_tensor = torch.tensor(linf_values)
    stats = {
        "model": model_name,
        "epsilon": epsilon,
        "sample_count": total,
        "clean_accuracy": clean_correct / max(total, 1),
        "adversarial_accuracy": adversarial_correct / max(total, 1),
        "attack_success_rate": attack_successes / max(clean_correct, 1),
        "changed_prediction_rate": changed_predictions / max(total, 1),
        "mean_abs_perturbation": mean_abs_sum / max(total, 1),
        "mean_l2_perturbation": l2_sum / max(total, 1),
        "mean_linf_perturbation": float(linf_tensor.mean().item()),
        "std_linf_perturbation": float(linf_tensor.std(unbiased=False).item()),
        "min_linf_perturbation": float(linf_tensor.min().item()),
        "max_linf_perturbation": float(linf_tensor.max().item()),
        "linf_within_epsilon": bool(linf_tensor.max().item() <= epsilon + 1e-6),
        "adversarial_clipped_low_fraction": clipped_low / max(pixel_count, 1),
        "adversarial_clipped_high_fraction": clipped_high / max(pixel_count, 1),
    }

    example_rows = []
    for category, payload in examples.items():
        figure_path = (
            output_dir
            / "examples"
            / model_name
            / f"eps_{epsilon:.2f}_{category}.png"
        )
        save_example_figure(
            clean_image=payload.pop("clean_image"),
            adversarial_image=payload.pop("adversarial_image"),
            epsilon=epsilon,
            output_path=figure_path,
            title=f"{model_name} eps={epsilon:.2f} {category}",
        )
        payload["category"] = category
        payload["figure_path"] = str(figure_path)
        example_rows.append(payload)

    return stats, example_rows


def main() -> None:
    args = parse_args()
    config = load_yaml_config(args.config)
    set_global_seed(int(config.get("seed", 42)))
    device = resolve_device(str(config.get("device", "auto")))
    timestamp = utc_timestamp()
    output_dir = args.output_dir / f"fgsm_validation_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=False)
    epsilons = [float(epsilon) for epsilon in config["epsilons"]]

    all_stats = []
    all_examples = []
    for model_config in config["models"]:
        model_name = model_config["name"]
        model, class_names = load_model(
            model_name=model_name,
            checkpoint_path=Path(model_config["checkpoint_path"]),
            device=device,
        )
        loader = create_loader(config, class_names)
        for epsilon in epsilons:
            print(f"Validating {model_name} epsilon={epsilon}")
            stats, examples = analyze_model_epsilon(
                model_name=model_name,
                model=model,
                class_names=class_names,
                loader=loader,
                epsilon=epsilon,
                output_dir=output_dir,
                device=device,
            )
            all_stats.append(stats)
            all_examples.extend(examples)

    stats_path = output_dir / "perturbation_stats.csv"
    examples_path = output_dir / "example_analysis.csv"
    write_csv(all_stats, stats_path)
    write_csv(all_examples, examples_path)
    write_json(
        {
            "manifest_type": "fgsm_validation",
            "timestamp_utc": timestamp,
            "config_path": str(args.config),
            "config": config,
            "environment": get_environment_metadata(repo_root=PROJECT_ROOT),
            "device": str(device),
            "perturbation_stats_path": str(stats_path),
            "example_analysis_path": str(examples_path),
            "output_dir": str(output_dir),
        },
        output_dir / "validation_metadata.json",
    )
    print(f"Saved FGSM validation outputs to: {output_dir}")


if __name__ == "__main__":
    main()
