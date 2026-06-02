import argparse
import json
import math
import random
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from PIL import Image
from torchvision import transforms

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from attacks.fgsm import NormalizedModel, denormalize_images, normalize_images
from attacks.pgd import build_pgd_attack
from models.mobilenet import MOBILENET_V3_SMALL_ADAPTER
from preprocessing.transforms import IMAGENET_MEAN, IMAGENET_STD
from utils.experiment import sha256_file, utc_iso_timestamp
from utils.reproducibility import set_global_seed


BASELINE_CHECKPOINT = Path(
    "results/baseline_duplicate_aware/mobilenet_v3_small_20260601T100108Z/best_model.pth"
)
DEFENSE_CHECKPOINT = Path(
    "results/defenses/adversarial_training/"
    "mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/best_model.pth"
)
TEST_CSV = Path("datasets/splits_duplicate_aware/test.csv")
PER_CLASS_COMPARISON = Path(
    "results/defenses/adversarial_training/"
    "mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/"
    "per_class_f1_comparison.csv"
)
DEFENSE_COMPARISON = Path(
    "results/defenses/adversarial_training/"
    "mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/"
    "adversarial_training_comparison.csv"
)


@dataclass
class Prediction:
    index: int
    label: str
    confidence: float


@dataclass
class SampleRecord:
    sample_id: str
    source_index: int
    filepath: str
    family: str
    content_hash: str
    primary_category: str
    category_tags: list[str]
    selection_attack: str
    baseline_clean_pred: str
    baseline_fgsm_pred: str
    baseline_pgd_pred: str
    defense_clean_pred: str
    defense_fgsm_pred: str
    defense_pgd_pred: str
    baseline_clean_confidence: float
    baseline_fgsm_confidence: float
    baseline_pgd_confidence: float
    defense_clean_confidence: float
    defense_fgsm_confidence: float
    defense_pgd_confidence: float
    fgsm_attack_success: bool
    pgd_attack_success: bool
    fgsm_defense_recovers: bool
    pgd_defense_recovers: bool


class GradCAM:
    def __init__(self, model: nn.Module, target_layer: nn.Module) -> None:
        self.model = model
        self.target_layer = target_layer
        self.activations: torch.Tensor | None = None
        self.gradients: torch.Tensor | None = None
        self.forward_handle = target_layer.register_forward_hook(self._save_activations)
        self.backward_handle = target_layer.register_full_backward_hook(self._save_gradients)

    def _save_activations(self, _module, _inputs, output) -> None:
        self.activations = output.detach()

    def _save_gradients(self, _module, _grad_input, grad_output) -> None:
        self.gradients = grad_output[0].detach()

    def remove(self) -> None:
        self.forward_handle.remove()
        self.backward_handle.remove()

    def __call__(self, image: torch.Tensor, target_index: int) -> np.ndarray:
        self.model.zero_grad(set_to_none=True)
        logits = self.model(image)
        score = logits[:, target_index].sum()
        score.backward()

        if self.activations is None or self.gradients is None:
            raise RuntimeError("Grad-CAM hooks did not capture activations/gradients.")

        weights = self.gradients.mean(dim=(2, 3), keepdim=True)
        cam = (weights * self.activations).sum(dim=1, keepdim=True)
        cam = F.relu(cam)
        cam = F.interpolate(
            cam,
            size=image.shape[-2:],
            mode="bilinear",
            align_corners=False,
        )
        cam = cam[0, 0].detach().cpu().numpy()
        cam -= float(cam.min())
        max_value = float(cam.max())
        if max_value > 0:
            cam /= max_value
        return cam


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate CenTaD-MalGuard Grad-CAM evidence assets.",
    )
    parser.add_argument("--test-csv", type=Path, default=TEST_CSV)
    parser.add_argument("--baseline-checkpoint", type=Path, default=BASELINE_CHECKPOINT)
    parser.add_argument("--defense-checkpoint", type=Path, default=DEFENSE_CHECKPOINT)
    parser.add_argument("--per-class-comparison", type=Path, default=PER_CLASS_COMPARISON)
    parser.add_argument("--defense-comparison", type=Path, default=DEFENSE_COMPARISON)
    parser.add_argument("--output-dir", type=Path, default=Path("results/gradcam/cenTaD_malguard_gradcam"))
    parser.add_argument("--report-path", type=Path, default=Path("reports/gradcam_analysis_report.md"))
    parser.add_argument("--target-samples", type=int, default=16)
    parser.add_argument("--max-candidates", type=int, default=48)
    parser.add_argument("--candidate-batch-size", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--image-size", type=int, default=224)
    parser.add_argument("--fgsm-epsilon", type=float, default=0.03)
    parser.add_argument("--pgd-epsilon", type=float, default=0.03)
    parser.add_argument("--pgd-alpha", type=float, default=0.003)
    parser.add_argument("--pgd-steps", type=int, default=20)
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda", "mps"])
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing output directory.",
    )
    return parser.parse_args()


def resolve_device(device_name: str) -> torch.device:
    if device_name != "auto":
        return torch.device(device_name)
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def ensure_inputs(args: argparse.Namespace) -> None:
    required_paths = [
        args.test_csv,
        args.baseline_checkpoint,
        args.defense_checkpoint,
        args.per_class_comparison,
        args.defense_comparison,
    ]
    missing = [str(path) for path in required_paths if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing required canonical inputs. Restore/download them before running: "
            + ", ".join(missing)
        )


def load_checkpoint_model(checkpoint_path: Path, device: torch.device) -> tuple[nn.Module, list[str]]:
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    class_names = list(checkpoint["class_names"])
    config = checkpoint.get("config") or {}
    model = MOBILENET_V3_SMALL_ADAPTER.build(
        num_classes=len(class_names),
        pretrained=False,
        freeze_backbone=False,
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)
    model.eval()
    return model, class_names


def target_layer_description(model: nn.Module) -> tuple[nn.Module, str]:
    layer = model.features[-1]
    return layer, "model.features[-1] (final MobileNetV3 convolutional feature block)"


def build_transforms(image_size: int) -> tuple[transforms.Compose, transforms.Compose]:
    raw_transform = transforms.Compose(
        [
            transforms.Resize((image_size, image_size)),
            transforms.ToTensor(),
        ]
    )
    norm_transform = transforms.Compose(
        [
            transforms.Resize((image_size, image_size)),
            transforms.ToTensor(),
            transforms.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
        ]
    )
    return raw_transform, norm_transform


def load_image(path: Path, raw_transform, norm_transform, device: torch.device) -> tuple[torch.Tensor, torch.Tensor]:
    with Image.open(path) as image:
        rgb = image.convert("RGB")
    raw = raw_transform(rgb).unsqueeze(0).to(device)
    normalized = norm_transform(rgb).unsqueeze(0).to(device)
    return raw, normalized


def predict(model: nn.Module, normalized_image: torch.Tensor, class_names: list[str]) -> Prediction:
    with torch.inference_mode():
        logits = model(normalized_image)
        probabilities = torch.softmax(logits, dim=1)
        confidence, index = torch.max(probabilities, dim=1)
    class_index = int(index.item())
    return Prediction(
        index=class_index,
        label=class_names[class_index],
        confidence=float(confidence.item()),
    )


def predict_raw(model: nn.Module, raw_image: torch.Tensor, class_names: list[str]) -> Prediction:
    normalized = normalize_images(raw_image)
    return predict(model, normalized, class_names)


def predict_batch(model: nn.Module, normalized_images: torch.Tensor, class_names: list[str]) -> list[Prediction]:
    with torch.inference_mode():
        logits = model(normalized_images)
        probabilities = torch.softmax(logits, dim=1)
        confidences, indices = torch.max(probabilities, dim=1)
    return [
        Prediction(
            index=int(index.item()),
            label=class_names[int(index.item())],
            confidence=float(confidence.item()),
        )
        for index, confidence in zip(indices, confidences)
    ]


def predict_batch_raw(model: nn.Module, raw_images: torch.Tensor, class_names: list[str]) -> list[Prediction]:
    return predict_batch(model, normalize_images(raw_images), class_names)


def make_fgsm(
    model: nn.Module,
    raw_image: torch.Tensor,
    label: torch.Tensor,
    epsilon: float,
) -> torch.Tensor:
    wrapped = NormalizedModel(model).to(raw_image.device)
    wrapped.eval()
    raw = raw_image.detach().clone().requires_grad_(True)
    logits = wrapped(raw)
    loss = F.cross_entropy(logits, label)
    wrapped.zero_grad(set_to_none=True)
    loss.backward()
    adversarial = raw + epsilon * raw.grad.sign()
    return adversarial.detach().clamp(0.0, 1.0)


def make_pgd(
    model: nn.Module,
    raw_image: torch.Tensor,
    label: torch.Tensor,
    epsilon: float,
    alpha: float,
    steps: int,
) -> torch.Tensor:
    wrapped = NormalizedModel(model).to(raw_image.device)
    wrapped.eval()
    attack = build_pgd_attack(
        model=wrapped,
        epsilon=epsilon,
        alpha=alpha,
        steps=steps,
        random_start=True,
    )
    return attack(raw_image.detach(), label).detach().clamp(0.0, 1.0)


def make_fgsm_batch(
    model: nn.Module,
    raw_images: torch.Tensor,
    labels: torch.Tensor,
    epsilon: float,
) -> torch.Tensor:
    wrapped = NormalizedModel(model).to(raw_images.device)
    wrapped.eval()
    raw = raw_images.detach().clone().requires_grad_(True)
    logits = wrapped(raw)
    loss = F.cross_entropy(logits, labels)
    wrapped.zero_grad(set_to_none=True)
    loss.backward()
    return (raw + epsilon * raw.grad.sign()).detach().clamp(0.0, 1.0)


def make_pgd_batch(
    model: nn.Module,
    raw_images: torch.Tensor,
    labels: torch.Tensor,
    epsilon: float,
    alpha: float,
    steps: int,
) -> torch.Tensor:
    wrapped = NormalizedModel(model).to(raw_images.device)
    wrapped.eval()
    attack = build_pgd_attack(
        model=wrapped,
        epsilon=epsilon,
        alpha=alpha,
        steps=steps,
        random_start=True,
    )
    return attack(raw_images.detach(), labels).detach().clamp(0.0, 1.0)


def family_key(label: str) -> str:
    return (
        label.lower()
        .replace(".", "_")
        .replace("!", "_")
        .replace("-", "_")
        .replace(" ", "_")
    )


def load_family_groups(path: Path) -> tuple[set[str], set[str]]:
    frame = pd.read_csv(path)
    strong = set()
    weak = set()
    for row in frame.to_dict("records"):
        key = row["family_key"]
        if (
            float(row.get("clean_f1_adversarial_training", 0.0)) >= 0.95
            and float(row.get("fgsm_0.03_f1_adversarial_training", 0.0)) >= 0.80
        ):
            strong.add(key)
        if (
            float(row.get("pgd20_f1_adversarial_training", 0.0)) <= 0.01
            or float(row.get("clean_f1_adversarial_training", 0.0)) < 0.75
        ):
            weak.add(key)
    return strong, weak


def quota_satisfied(selected: list[SampleRecord], target_samples: int) -> bool:
    if len(selected) < target_samples:
        return False
    tags = [tag for record in selected for tag in record.category_tags]
    return (
        tags.count("A_defense_recovers") >= 5
        and tags.count("B_defense_still_fails") >= 3
        and tags.count("C_strong_family") >= 3
        and tags.count("D_weak_family") >= 3
    )


def build_candidate_pool(
    test_frame: pd.DataFrame,
    strong_families: set[str],
    weak_families: set[str],
    seed: int,
    max_candidates: int,
) -> pd.DataFrame:
    frame = test_frame.copy()
    frame["family_key"] = frame["label"].map(family_key)
    chunks: list[pd.DataFrame] = []

    for keys, per_family in [
        (weak_families, 4),
        (strong_families, 4),
        (set(frame["family_key"].unique()), 2),
    ]:
        subset = frame[frame["family_key"].isin(keys)]
        for offset, (_label, group) in enumerate(subset.groupby("label", sort=True)):
            count = min(per_family, len(group))
            if count:
                chunks.append(group.sample(n=count, random_state=seed + offset))

    if not chunks:
        return frame.sample(n=min(max_candidates, len(frame)), random_state=seed)

    candidates = (
        pd.concat(chunks, ignore_index=False)
        .drop_duplicates(subset=["content_hash"])
        .sample(frac=1.0, random_state=seed)
    )
    if len(candidates) < max_candidates:
        fill = frame.drop(index=candidates.index, errors="ignore").sample(
            n=min(max_candidates - len(candidates), max(len(frame) - len(candidates), 0)),
            random_state=seed,
        )
        candidates = pd.concat([candidates, fill], ignore_index=False)
    return candidates.head(max_candidates).reset_index()


def classify_record(
    family: str,
    baseline_clean: Prediction,
    baseline_fgsm: Prediction,
    baseline_pgd: Prediction,
    defense_fgsm: Prediction,
    defense_pgd: Prediction,
    strong_families: set[str],
    weak_families: set[str],
) -> tuple[str, list[str], str]:
    tags: list[str] = []
    key = family_key(family)
    if key in strong_families:
        tags.append("C_strong_family")
    if key in weak_families:
        tags.append("D_weak_family")

    fgsm_success = baseline_clean.label == family and baseline_fgsm.label != family
    pgd_success = baseline_clean.label == family and baseline_pgd.label != family
    fgsm_recovers = fgsm_success and defense_fgsm.label == family
    pgd_recovers = pgd_success and defense_pgd.label == family

    if pgd_recovers or fgsm_recovers:
        tags.insert(0, "A_defense_recovers")
        return "A_defense_recovers", tags, "pgd" if pgd_recovers else "fgsm"

    if pgd_success or fgsm_success:
        tags.insert(0, "B_defense_still_fails")
        return "B_defense_still_fails", tags, "pgd" if pgd_success else "fgsm"

    if "C_strong_family" in tags:
        return "C_strong_family", tags, "clean"
    if "D_weak_family" in tags:
        return "D_weak_family", tags, "clean"
    return "unselected", tags, "clean"


def select_samples(
    args: argparse.Namespace,
    baseline_model: nn.Module,
    defense_model: nn.Module,
    class_names: list[str],
    device: torch.device,
) -> tuple[list[SampleRecord], dict[str, dict[str, torch.Tensor]]]:
    raw_transform, norm_transform = build_transforms(args.image_size)
    test_frame = pd.read_csv(args.test_csv)
    strong_families, weak_families = load_family_groups(args.per_class_comparison)
    candidates = build_candidate_pool(
        test_frame=test_frame,
        strong_families=strong_families,
        weak_families=weak_families,
        seed=args.seed,
        max_candidates=args.max_candidates,
    )

    selected: list[SampleRecord] = []
    seen_hashes: set[str] = set()
    image_cache: dict[str, dict[str, torch.Tensor]] = {}
    tag_counts: dict[str, int] = {}

    for start in range(0, len(candidates), args.candidate_batch_size):
        if len(selected) >= args.target_samples and quota_satisfied(selected, args.target_samples):
            break
        batch_rows = candidates.iloc[start : start + args.candidate_batch_size].to_dict("records")
        raw_images: list[torch.Tensor] = []
        normalized_images: list[torch.Tensor] = []
        labels: list[int] = []
        valid_rows: list[dict[str, Any]] = []

        for row in batch_rows:
            filepath = Path(row["filepath"])
            family = row["label"]
            content_hash = str(row.get("content_hash") or sha256_file(filepath))
            if content_hash in seen_hashes or not filepath.exists():
                continue
            raw, normalized = load_image(filepath, raw_transform, norm_transform, device)
            raw_images.append(raw.squeeze(0))
            normalized_images.append(normalized.squeeze(0))
            labels.append(class_names.index(family))
            valid_rows.append(row)

        if not valid_rows:
            continue

        raw_batch = torch.stack(raw_images).to(device)
        normalized_batch = torch.stack(normalized_images).to(device)
        label_batch = torch.tensor(labels, dtype=torch.long, device=device)

        baseline_clean_predictions = predict_batch(baseline_model, normalized_batch, class_names)
        fgsm_batch = make_fgsm_batch(
            baseline_model,
            raw_batch,
            label_batch,
            args.fgsm_epsilon,
        )
        pgd_batch = make_pgd_batch(
            baseline_model,
            raw_batch,
            label_batch,
            args.pgd_epsilon,
            args.pgd_alpha,
            args.pgd_steps,
        )

        baseline_fgsm_predictions = predict_batch_raw(baseline_model, fgsm_batch, class_names)
        baseline_pgd_predictions = predict_batch_raw(baseline_model, pgd_batch, class_names)
        defense_clean_predictions = predict_batch(defense_model, normalized_batch, class_names)
        defense_fgsm_predictions = predict_batch_raw(defense_model, fgsm_batch, class_names)
        defense_pgd_predictions = predict_batch_raw(defense_model, pgd_batch, class_names)

        for index, row in enumerate(valid_rows):
            if len(selected) >= args.target_samples and quota_satisfied(selected, args.target_samples):
                break

            filepath = Path(row["filepath"])
            family = row["label"]
            content_hash = str(row.get("content_hash") or sha256_file(filepath))
            baseline_clean = baseline_clean_predictions[index]
            if baseline_clean.label != family and family_key(family) not in weak_families:
                continue

            baseline_fgsm = baseline_fgsm_predictions[index]
            baseline_pgd = baseline_pgd_predictions[index]
            defense_clean = defense_clean_predictions[index]
            defense_fgsm = defense_fgsm_predictions[index]
            defense_pgd = defense_pgd_predictions[index]

            primary_category, tags, selection_attack = classify_record(
                family=family,
                baseline_clean=baseline_clean,
                baseline_fgsm=baseline_fgsm,
                baseline_pgd=baseline_pgd,
                defense_fgsm=defense_fgsm,
                defense_pgd=defense_pgd,
                strong_families=strong_families,
                weak_families=weak_families,
            )
            if primary_category == "unselected":
                continue

            primary_count = tag_counts.get(primary_category, 0)
            family_count = sum(1 for record in selected if record.family == family)
            if len(selected) >= args.target_samples:
                continue
            if primary_category == "A_defense_recovers" and primary_count >= 7 and "C_strong_family" not in tags:
                continue
            if primary_category == "B_defense_still_fails" and primary_count >= 5 and "D_weak_family" not in tags:
                continue
            if family_count >= 3 and len(selected) > 8:
                continue

            sample_id = f"{len(selected) + 1:02d}_{family_key(family)}_{selection_attack}"
            selected.append(
                SampleRecord(
                    sample_id=sample_id,
                    source_index=int(row["index"]),
                    filepath=str(filepath),
                    family=family,
                    content_hash=content_hash,
                    primary_category=primary_category,
                    category_tags=tags,
                    selection_attack=selection_attack,
                    baseline_clean_pred=baseline_clean.label,
                    baseline_fgsm_pred=baseline_fgsm.label,
                    baseline_pgd_pred=baseline_pgd.label,
                    defense_clean_pred=defense_clean.label,
                    defense_fgsm_pred=defense_fgsm.label,
                    defense_pgd_pred=defense_pgd.label,
                    baseline_clean_confidence=baseline_clean.confidence,
                    baseline_fgsm_confidence=baseline_fgsm.confidence,
                    baseline_pgd_confidence=baseline_pgd.confidence,
                    defense_clean_confidence=defense_clean.confidence,
                    defense_fgsm_confidence=defense_fgsm.confidence,
                    defense_pgd_confidence=defense_pgd.confidence,
                    fgsm_attack_success=baseline_fgsm.label != family and baseline_clean.label == family,
                    pgd_attack_success=baseline_pgd.label != family and baseline_clean.label == family,
                    fgsm_defense_recovers=baseline_fgsm.label != family and defense_fgsm.label == family,
                    pgd_defense_recovers=baseline_pgd.label != family and defense_pgd.label == family,
                )
            )
            seen_hashes.add(content_hash)
            image_cache[sample_id] = {
                "clean": raw_batch[index : index + 1].detach().cpu(),
                "fgsm": fgsm_batch[index : index + 1].detach().cpu(),
                "pgd": pgd_batch[index : index + 1].detach().cpu(),
            }
            for tag in tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

    selected.sort(key=lambda record: (record.primary_category, record.family, record.sample_id))
    selected = selected[: args.target_samples]
    image_cache = {record.sample_id: image_cache[record.sample_id] for record in selected}
    return selected, image_cache


def tensor_to_image(raw_tensor: torch.Tensor) -> np.ndarray:
    tensor = raw_tensor.detach().cpu().squeeze(0).clamp(0.0, 1.0)
    return tensor.permute(1, 2, 0).numpy()


def save_raw_image(raw_tensor: torch.Tensor, path: Path) -> None:
    array = (tensor_to_image(raw_tensor) * 255).astype(np.uint8)
    Image.fromarray(array).save(path)


def save_perturbation(clean: torch.Tensor, adversarial: torch.Tensor, path: Path) -> None:
    delta = (adversarial - clean).detach().cpu().squeeze(0)
    magnitude = delta.abs().max(dim=0).values.numpy()
    if float(magnitude.max()) > 0:
        magnitude = magnitude / float(magnitude.max())
    plt.figure(figsize=(4, 4), dpi=180)
    plt.imshow(magnitude, cmap="magma")
    plt.axis("off")
    plt.tight_layout(pad=0)
    plt.savefig(path, bbox_inches="tight", pad_inches=0)
    plt.close()


def overlay_heatmap(raw_tensor: torch.Tensor, heatmap: np.ndarray, title: str, path: Path) -> None:
    image = tensor_to_image(raw_tensor)
    plt.figure(figsize=(4.8, 4.8), dpi=220)
    plt.imshow(image)
    plt.imshow(heatmap, cmap="jet", alpha=0.42, vmin=0.0, vmax=1.0)
    plt.title(title, fontsize=9)
    plt.axis("off")
    plt.tight_layout(pad=0.15)
    plt.savefig(path, bbox_inches="tight", pad_inches=0.04)
    plt.close()


def topk_iou(left: np.ndarray, right: np.ndarray, quantile: float = 0.80) -> float:
    left_threshold = np.quantile(left, quantile)
    right_threshold = np.quantile(right, quantile)
    left_mask = left >= left_threshold
    right_mask = right >= right_threshold
    union = np.logical_or(left_mask, right_mask).sum()
    if union == 0:
        return 0.0
    return float(np.logical_and(left_mask, right_mask).sum() / union)


def center_of_mass(heatmap: np.ndarray) -> tuple[float, float]:
    total = float(heatmap.sum())
    if total <= 1e-12:
        return (math.nan, math.nan)
    yy, xx = np.indices(heatmap.shape)
    return (float((xx * heatmap).sum() / total), float((yy * heatmap).sum() / total))


def center_shift(left: np.ndarray, right: np.ndarray) -> float:
    lx, ly = center_of_mass(left)
    rx, ry = center_of_mass(right)
    if any(math.isnan(value) for value in [lx, ly, rx, ry]):
        return math.nan
    diagonal = math.sqrt(left.shape[0] ** 2 + left.shape[1] ** 2)
    return float(math.sqrt((lx - rx) ** 2 + (ly - ry) ** 2) / diagonal)


def generate_assets(
    args: argparse.Namespace,
    selected: list[SampleRecord],
    image_cache: dict[str, dict[str, torch.Tensor]],
    baseline_model: nn.Module,
    defense_model: nn.Module,
    class_names: list[str],
    device: torch.device,
    target_layer_text: str,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    baseline_layer, _ = target_layer_description(baseline_model)
    defense_layer, _ = target_layer_description(defense_model)
    baseline_cam = GradCAM(baseline_model, baseline_layer)
    defense_cam = GradCAM(defense_model, defense_layer)
    metrics_rows: list[dict[str, Any]] = []
    prediction_rows: list[dict[str, Any]] = []

    try:
        for record in selected:
            sample_dir = args.output_dir / "samples" / record.sample_id
            image_dir = sample_dir / "images"
            cam_dir = sample_dir / "gradcam"
            image_dir.mkdir(parents=True, exist_ok=True)
            cam_dir.mkdir(parents=True, exist_ok=True)
            images = image_cache[record.sample_id]

            save_raw_image(images["clean"], image_dir / "clean.png")
            save_raw_image(images["fgsm"], image_dir / "fgsm_eps_0_03.png")
            save_raw_image(images["pgd"], image_dir / "pgd_eps_0_03_steps_20.png")
            save_perturbation(images["clean"], images["fgsm"], image_dir / "perturbation_fgsm.png")
            save_perturbation(images["clean"], images["pgd"], image_dir / "perturbation_pgd.png")

            heatmaps: dict[str, np.ndarray] = {}
            for model_key, model, cam in [
                ("baseline", baseline_model, baseline_cam),
                ("defense", defense_model, defense_cam),
            ]:
                for image_key in ["clean", "fgsm", "pgd"]:
                    raw = images[image_key].to(device)
                    prediction = predict_raw(model, raw, class_names)
                    heatmap = cam(normalize_images(raw), prediction.index)
                    heatmaps[f"{model_key}_{image_key}"] = heatmap
                    title = f"{model_key} on {image_key}: {prediction.label}"
                    overlay_heatmap(
                        raw_tensor=raw.detach().cpu(),
                        heatmap=heatmap,
                        title=title,
                        path=cam_dir / f"{model_key}_{image_key}_gradcam.png",
                    )
                    prediction_rows.append(
                        {
                            "sample_id": record.sample_id,
                            "family": record.family,
                            "model": model_key,
                            "image_variant": image_key,
                            "prediction": prediction.label,
                            "confidence": prediction.confidence,
                            "correct": prediction.label == record.family,
                            "target_class_for_gradcam": prediction.label,
                        }
                    )

            for model_key in ["baseline", "defense"]:
                for attack_key in ["fgsm", "pgd"]:
                    clean_heatmap = heatmaps[f"{model_key}_clean"]
                    attack_heatmap = heatmaps[f"{model_key}_{attack_key}"]
                    metrics_rows.append(
                        {
                            "sample_id": record.sample_id,
                            "family": record.family,
                            "primary_category": record.primary_category,
                            "category_tags": ";".join(record.category_tags),
                            "model": model_key,
                            "attack": attack_key,
                            "top20_iou": topk_iou(clean_heatmap, attack_heatmap),
                            "center_of_mass_shift": center_shift(clean_heatmap, attack_heatmap),
                            "target_layer": target_layer_text,
                        }
                    )

            make_sample_panel(record, sample_dir, images)
    finally:
        baseline_cam.remove()
        defense_cam.remove()

    return pd.DataFrame(prediction_rows), pd.DataFrame(metrics_rows)


def make_sample_panel(record: SampleRecord, sample_dir: Path, images: dict[str, torch.Tensor]) -> None:
    cam_dir = sample_dir / "gradcam"
    panel_path = sample_dir / "comparison_panel.png"
    fig, axes = plt.subplots(3, 4, figsize=(12, 9), dpi=180)
    variants = [
        ("clean", "Clean"),
        ("fgsm", "FGSM"),
        ("pgd", "PGD"),
    ]
    for row, (key, label) in enumerate(variants):
        axes[row, 0].imshow(tensor_to_image(images[key]))
        axes[row, 0].set_title(label, fontsize=9)
        axes[row, 0].axis("off")

        perturbation_path = sample_dir / "images" / (
            "perturbation_fgsm.png" if key == "fgsm" else "perturbation_pgd.png"
        )
        if key == "clean":
            axes[row, 1].text(0.5, 0.5, "Reference", ha="center", va="center", fontsize=10)
            axes[row, 1].axis("off")
        else:
            axes[row, 1].imshow(Image.open(perturbation_path))
            axes[row, 1].set_title("Perturbation", fontsize=9)
            axes[row, 1].axis("off")

        axes[row, 2].imshow(Image.open(cam_dir / f"baseline_{key}_gradcam.png"))
        axes[row, 2].set_title("Clean model Grad-CAM", fontsize=9)
        axes[row, 2].axis("off")

        axes[row, 3].imshow(Image.open(cam_dir / f"defense_{key}_gradcam.png"))
        axes[row, 3].set_title("Robust model Grad-CAM", fontsize=9)
        axes[row, 3].axis("off")

    fig.suptitle(
        f"{record.sample_id} | true family: {record.family} | {record.primary_category}",
        fontsize=12,
    )
    plt.tight_layout(rect=(0, 0, 1, 0.96))
    plt.savefig(panel_path, bbox_inches="tight")
    plt.close(fig)


def copy_representative_panels(output_dir: Path, selected: list[SampleRecord]) -> dict[str, str | None]:
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    def first_with(tag: str) -> SampleRecord | None:
        for record in selected:
            if tag in record.category_tags:
                return record
        return None

    picks = {
        "success_case_comparison_panel": first_with("A_defense_recovers"),
        "failure_case_comparison_panel": first_with("B_defense_still_fails"),
    }
    paths: dict[str, str | None] = {}
    for name, record in picks.items():
        if record is None:
            paths[name] = None
            continue
        source = output_dir / "samples" / record.sample_id / "comparison_panel.png"
        destination = figures_dir / f"{name}.png"
        shutil.copyfile(source, destination)
        paths[name] = str(destination)
    return paths


def make_family_panel(output_dir: Path, selected: list[SampleRecord]) -> str | None:
    picks: list[SampleRecord] = []
    seen = set()
    for record in selected:
        if record.family in seen:
            continue
        picks.append(record)
        seen.add(record.family)
        if len(picks) >= 6:
            break
    if not picks:
        return None

    fig, axes = plt.subplots(len(picks), 3, figsize=(9, 3 * len(picks)), dpi=180)
    if len(picks) == 1:
        axes = np.array([axes])
    for row_index, record in enumerate(picks):
        sample_dir = output_dir / "samples" / record.sample_id
        axes[row_index, 0].imshow(Image.open(sample_dir / "images" / "clean.png"))
        axes[row_index, 0].set_title(f"{record.family}\nclean", fontsize=9)
        axes[row_index, 0].axis("off")
        axes[row_index, 1].imshow(Image.open(sample_dir / "gradcam" / "baseline_pgd_gradcam.png"))
        axes[row_index, 1].set_title(f"clean model PGD\n{record.baseline_pgd_pred}", fontsize=9)
        axes[row_index, 1].axis("off")
        axes[row_index, 2].imshow(Image.open(sample_dir / "gradcam" / "defense_pgd_gradcam.png"))
        axes[row_index, 2].set_title(f"robust model PGD\n{record.defense_pgd_pred}", fontsize=9)
        axes[row_index, 2].axis("off")
    fig.suptitle("Family-level Grad-CAM comparison under PGD attack", fontsize=13)
    plt.tight_layout(rect=(0, 0, 1, 0.98))
    path = output_dir / "figures" / "family_level_comparison_panel.png"
    plt.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return str(path)


def make_attention_summary(output_dir: Path, metrics: pd.DataFrame) -> str:
    summary = (
        metrics.groupby(["model", "attack"], as_index=False)
        .agg(
            top20_iou_mean=("top20_iou", "mean"),
            center_shift_mean=("center_of_mass_shift", "mean"),
        )
        .sort_values(["attack", "model"])
    )
    summary.to_csv(output_dir / "metadata" / "attention_stability_summary.csv", index=False)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4), dpi=200)
    for attack in ["fgsm", "pgd"]:
        subset = summary[summary["attack"] == attack]
        axes[0].bar(
            [f"{attack}\n{model}" for model in subset["model"]],
            subset["top20_iou_mean"],
            label=attack,
        )
        axes[1].bar(
            [f"{attack}\n{model}" for model in subset["model"]],
            subset["center_shift_mean"],
            label=attack,
        )
    axes[0].set_title("Top-20% Heatmap IoU")
    axes[0].set_ylabel("Higher means more overlap")
    axes[0].set_ylim(0, 1)
    axes[1].set_title("Center-of-Mass Shift")
    axes[1].set_ylabel("Lower means less shift")
    axes[1].set_ylim(0, max(0.05, float(summary["center_shift_mean"].max()) * 1.2))
    for axis in axes:
        axis.tick_params(axis="x", labelrotation=0)
        axis.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    path = output_dir / "figures" / "attention_stability_summary.png"
    plt.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return str(path)


def records_to_frame(records: list[SampleRecord]) -> pd.DataFrame:
    rows = []
    for record in records:
        row = record.__dict__.copy()
        row["category_tags"] = ";".join(record.category_tags)
        rows.append(row)
    return pd.DataFrame(rows)


def write_report(
    args: argparse.Namespace,
    selected: list[SampleRecord],
    predictions: pd.DataFrame,
    metrics: pd.DataFrame,
    representative_paths: dict[str, str | None],
    family_panel_path: str | None,
    attention_summary_path: str,
    target_layer_text: str,
    run_metadata: dict[str, Any],
) -> None:
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    metric_summary = (
        metrics.groupby(["model", "attack"], as_index=False)
        .agg(
            top20_iou_mean=("top20_iou", "mean"),
            top20_iou_median=("top20_iou", "median"),
            center_shift_mean=("center_of_mass_shift", "mean"),
            center_shift_median=("center_of_mass_shift", "median"),
        )
        .sort_values(["attack", "model"])
    )
    category_counts = pd.Series(
        [tag for record in selected for tag in record.category_tags]
    ).value_counts()
    success_panel = representative_paths.get("success_case_comparison_panel")
    failure_panel = representative_paths.get("failure_case_comparison_panel")

    lines = [
        "# CenTaD-MalGuard Grad-CAM Analysis Report",
        "",
        f"Generated at: `{run_metadata['created_at_utc']}`",
        "",
        "## Methodology",
        "",
        "This phase generated the explainability evidence package for CenTaD-MalGuard using the finalized duplicate-aware MalImg protocol and the official MobileNetV3 checkpoints. No baseline experiment was rerun and no model was retrained. FGSM and PGD examples were generated only for the curated visualization set so the final demo, poster, and report can show concrete attack and defense behavior.",
        "",
        f"Target layer: `{target_layer_text}`. This is the final convolutional feature block before MobileNetV3 pooling/classification, so it provides class-discriminative spatial evidence while retaining enough spatial resolution for visual explanation.",
        "",
        "Grad-CAM target class: the model's predicted class for each image variant. This explains the decision the model actually made, including wrong attacked predictions.",
        "",
        "Attack settings for visual assets:",
        "",
        f"- FGSM epsilon: `{run_metadata['fgsm_epsilon']}` in raw pixel space.",
        f"- PGD epsilon: `{run_metadata['pgd_epsilon']}`, alpha: `{run_metadata['pgd_alpha']}`, steps: `{run_metadata['pgd_steps']}`, random start: true.",
        "- Adversarial examples were generated against the clean MobileNetV3 baseline, then evaluated with both clean and adversarially trained MobileNetV3 for side-by-side explanation.",
        "",
        "## Sample Selection Rationale",
        "",
        f"Selected samples: `{len(selected)}`.",
        "",
        "The selection pipeline scans the official duplicate-aware test split deterministically and prioritizes four evidence categories: A, baseline correct -> attack succeeds -> defense recovers; B, baseline correct -> attack succeeds -> defense still fails; C, strong-performing malware families; D, weak-performing malware families.",
        "",
        "Category tag counts:",
        "",
    ]
    for tag, count in category_counts.items():
        lines.append(f"- `{tag}`: {int(count)}")
    lines.extend(
        [
            "",
            f"Selected sample metadata is stored in `{args.output_dir / 'metadata' / 'selected_samples.csv'}`.",
            "",
            "## Visual Findings",
            "",
            "The generated panels support the core project narrative: attacks can alter classifier behavior and associated attention maps, while adversarial training often improves robustness and may make attention more stable on selected examples. The evidence is intentionally mixed: both recovery cases and failure cases are included so the final presentation does not overstate the defense.",
            "",
        ]
    )
    if success_panel:
        lines.extend(
            [
                "Success-case panel:",
                "",
                f"![Success case]({Path(success_panel).resolve()})",
                "",
            ]
        )
    if failure_panel:
        lines.extend(
            [
                "Failure-case panel:",
                "",
                f"![Failure case]({Path(failure_panel).resolve()})",
                "",
            ]
        )
    if family_panel_path:
        lines.extend(
            [
                "Family-level comparison panel:",
                "",
                f"![Family comparison]({Path(family_panel_path).resolve()})",
                "",
            ]
        )
    lines.extend(
        [
            "## Quantitative Findings",
            "",
            "Attention stability was measured with lightweight, interpretable metrics:",
            "",
            "- Top-20% heatmap IoU: overlap between the most activated heatmap regions before and after attack. Higher is more stable.",
            "- Center-of-mass shift: normalized movement of the heatmap activation center. Lower is more stable.",
            "",
            "| Model | Attack | Mean Top-20% IoU | Median Top-20% IoU | Mean Center Shift | Median Center Shift |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in metric_summary.to_dict("records"):
        lines.append(
            f"| {row['model']} | {row['attack']} | "
            f"{row['top20_iou_mean']:.4f} | {row['top20_iou_median']:.4f} | "
            f"{row['center_shift_mean']:.4f} | {row['center_shift_median']:.4f} |"
        )
    lines.extend(
        [
            "",
            f"![Attention stability summary]({Path(attention_summary_path).resolve()})",
            "",
            "These metrics should be interpreted as supporting evidence, not proof of semantic understanding. Grad-CAM is sensitive to target class and model internals, and malware image regions are not directly human-semantic in the same way natural-image objects are.",
            "",
            "## Limitations",
            "",
            "- The Grad-CAM set is curated for explanation and demonstration, not a replacement for the official full-test robustness metrics.",
            "- The visual attacks are generated against the clean MobileNetV3 baseline for side-by-side comparison; official defense robustness numbers remain the primary quantitative evidence.",
            "- Grad-CAM can show attention shifts but cannot prove that highlighted regions correspond to causally meaningful malware semantics.",
            "- Some malware families remain weak under PGD, consistent with the low PGD-20 macro F1 after adversarial training.",
            "- CPU-only local generation may differ in runtime from the original Runpod environment, but it does not change the finalized experimental conclusions.",
            "",
            "## Implications for Adversarial Robustness",
            "",
            "The explainability package reinforces the final CenTaD-MalGuard narrative: attacks disrupt classifier behavior and attention; PGD adversarial training improves robustness and may stabilize attention on representative examples, while strong PGD attacks still expose family-balanced weaknesses. The adversarially trained MobileNetV3 should therefore be presented as a substantially stronger lightweight solution, not as a complete solution to adversarial malware classification.",
            "",
            "## Reproducibility Notes",
            "",
            f"- Output directory: `{args.output_dir}`",
            f"- Baseline checkpoint SHA-256: `{run_metadata['baseline_checkpoint_sha256']}`",
            f"- Defense checkpoint SHA-256: `{run_metadata['defense_checkpoint_sha256']}`",
            f"- Test CSV SHA-256: `{run_metadata['test_csv_sha256']}`",
            f"- Seed: `{run_metadata['seed']}`",
            "",
        ]
    )
    args.report_path.write_text("\n".join(lines))


def main() -> None:
    args = parse_args()
    set_global_seed(args.seed, deterministic=True, cudnn_benchmark=False)
    random.seed(args.seed)
    np.random.seed(args.seed)
    ensure_inputs(args)

    if args.output_dir.exists() and args.overwrite:
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "metadata").mkdir(parents=True, exist_ok=True)
    (args.output_dir / "figures").mkdir(parents=True, exist_ok=True)

    device = resolve_device(args.device)
    baseline_model, class_names = load_checkpoint_model(args.baseline_checkpoint, device)
    defense_model, defense_class_names = load_checkpoint_model(args.defense_checkpoint, device)
    if class_names != defense_class_names:
        raise ValueError("Baseline and defense checkpoints use different class orderings.")
    _, target_layer_text = target_layer_description(baseline_model)

    selected, image_cache = select_samples(
        args=args,
        baseline_model=baseline_model,
        defense_model=defense_model,
        class_names=class_names,
        device=device,
    )
    if not selected:
        raise RuntimeError("No samples were selected. Check dataset/checkpoint availability.")

    selected_frame = records_to_frame(selected)
    selected_frame.to_csv(args.output_dir / "metadata" / "selected_samples.csv", index=False)

    predictions, metrics = generate_assets(
        args=args,
        selected=selected,
        image_cache=image_cache,
        baseline_model=baseline_model,
        defense_model=defense_model,
        class_names=class_names,
        device=device,
        target_layer_text=target_layer_text,
    )
    predictions.to_csv(args.output_dir / "metadata" / "predictions.csv", index=False)
    metrics.to_csv(args.output_dir / "metadata" / "attention_stability_metrics.csv", index=False)
    representative_paths = copy_representative_panels(args.output_dir, selected)
    family_panel_path = make_family_panel(args.output_dir, selected)
    attention_summary_path = make_attention_summary(args.output_dir, metrics)

    defense_comparison = pd.read_csv(args.defense_comparison)
    shutil.copyfile(
        args.defense_comparison,
        args.output_dir / "metadata" / "adversarial_training_comparison.csv",
    )
    run_metadata = {
        "created_at_utc": utc_iso_timestamp(),
        "seed": args.seed,
        "device": str(device),
        "image_size": args.image_size,
        "target_samples_requested": args.target_samples,
        "target_samples_selected": len(selected),
        "max_candidates": args.max_candidates,
        "fgsm_epsilon": args.fgsm_epsilon,
        "pgd_epsilon": args.pgd_epsilon,
        "pgd_alpha": args.pgd_alpha,
        "pgd_steps": args.pgd_steps,
        "target_layer": target_layer_text,
        "baseline_checkpoint": str(args.baseline_checkpoint),
        "defense_checkpoint": str(args.defense_checkpoint),
        "baseline_checkpoint_sha256": sha256_file(args.baseline_checkpoint),
        "defense_checkpoint_sha256": sha256_file(args.defense_checkpoint),
        "test_csv": str(args.test_csv),
        "test_csv_sha256": sha256_file(args.test_csv),
        "defense_comparison_metrics": defense_comparison.to_dict("records"),
    }
    (args.output_dir / "metadata" / "run_metadata.json").write_text(
        json.dumps(run_metadata, indent=2, sort_keys=True)
    )

    write_report(
        args=args,
        selected=selected,
        predictions=predictions,
        metrics=metrics,
        representative_paths=representative_paths,
        family_panel_path=family_panel_path,
        attention_summary_path=attention_summary_path,
        target_layer_text=target_layer_text,
        run_metadata=run_metadata,
    )
    print(f"Generated {len(selected)} Grad-CAM evidence samples.")
    print(f"Assets: {args.output_dir}")
    print(f"Report: {args.report_path}")


if __name__ == "__main__":
    main()
