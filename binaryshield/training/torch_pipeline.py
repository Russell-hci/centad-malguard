from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from binaryshield.byte_loader import load_bytes
from binaryshield.datasets import BinarySample, iter_split, load_manifest
from binaryshield.evaluation.metrics import classification_summary
from binaryshield.pe_features import parse_pe
from binaryshield.training.adaptive_weights import AdaptiveWeightConfig, update_class_weights
from binaryshield.training.car_fp_malat import CARFPMalATConfig, describe_objective
from binaryshield.transformations import append_overlay, mutate_slack_space
from binaryshield.validation import validate_transformation

try:
    import torch
    import torch.nn.functional as F
    from torch.utils.data import DataLoader, Dataset
except ImportError:  # pragma: no cover - depends on GPU/runtime env
    torch = None
    F = None
    DataLoader = None
    Dataset = object  # type: ignore[assignment,misc]


@dataclass(frozen=True)
class TorchTrainingConfig:
    manifest: str
    root_dir: str | None
    output_dir: str
    model_type: str = "raw_byte_cnn"
    target: str = "label"
    max_bytes: int = 65536
    batch_size: int = 16
    epochs: int = 5
    learning_rate: float = 0.001
    device: str = "auto"
    transformed_training: bool = False
    transformation: str = "append_overlay"
    transform_payload_size: int = 1024
    use_car_fp_malat: bool = False
    consistency_weight: float = 0.25
    clean_loss_weight: float = 1.0
    transformed_loss_weight: float = 1.0
    adaptive_class_weights: bool = True
    adaptive_target_f1: float = 0.80
    adaptive_max_weight: float = 5.0
    adaptive_smoothing: float = 0.5

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


if torch is not None:

    class BinaryTorchDataset(Dataset):
        def __init__(
            self,
        samples: list[BinarySample],
        label_to_index: dict[str, int],
        target: str,
        max_bytes: int,
        feature_names: list[str] | None = None,
        transformed_training: bool = False,
        transformation: str = "append_overlay",
        transform_payload_size: int = 1024,
        transform_output_dir: str | Path | None = None,
        ) -> None:
            self.samples = samples
            self.label_to_index = label_to_index
            self.target = target
            self.max_bytes = max_bytes
            self.feature_names = feature_names or _infer_feature_names(samples[: min(len(samples), 64)])
            self.transformed_training = transformed_training
            self.transformation = transformation
            self.transform_payload_size = transform_payload_size
            self.transform_output_dir = Path(transform_output_dir) if transform_output_dir is not None else None

        def __len__(self) -> int:
            return len(self.samples) * 2 if self.transformed_training else len(self.samples)

        def __getitem__(self, index: int):
            use_transformed = self.transformed_training and index % 2 == 1
            sample_index = index // 2 if self.transformed_training else index
            sample = self.samples[sample_index]
            label = _sample_target(sample, self.target)
            path = self._path_for_sample(sample, sample_index) if use_transformed else sample.path
            byte_values = load_bytes(path, self.max_bytes).byte_values
            if len(byte_values) < self.max_bytes:
                byte_values = byte_values + [256] * (self.max_bytes - len(byte_values))
            vector = parse_pe(path).to_vector()
            feature_values = [float(vector.get(name, 0.0)) for name in self.feature_names]
            return {
                "bytes": torch.tensor(byte_values, dtype=torch.long),
                "features": torch.tensor(feature_values, dtype=torch.float32),
                "label": torch.tensor(self.label_to_index[label], dtype=torch.long),
            }

        def _path_for_sample(self, sample: BinarySample, index: int) -> Path:
            if not self.transformed_training:
                return sample.path
            if self.transform_output_dir is None:
                raise ValueError("transform_output_dir is required for transformed_training")
            output_path = self.transform_output_dir / self.transformation / f"{sample.sample_id}_{index}.bin"
            validation_path = self.transform_output_dir / "validation" / self.transformation / f"{sample.sample_id}_{index}.json"
            if output_path.exists() and validation_path.exists():
                return output_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if self.transformation == "append_overlay":
                result = append_overlay(
                    sample.path,
                    output_path,
                    payload_size=self.transform_payload_size,
                    seed=index,
                )
            elif self.transformation == "section_slack":
                result = mutate_slack_space(
                    sample.path,
                    output_path,
                    max_bytes=self.transform_payload_size,
                    seed=index,
                )
            else:
                raise ValueError(f"unsupported transformed_training transformation: {self.transformation}")
            validation = validate_transformation(result, validation_path)
            return output_path if validation.allowed_for_evaluation else sample.path


    class PairedBinaryTorchDataset(Dataset):
        def __init__(
            self,
            samples: list[BinarySample],
            label_to_index: dict[str, int],
            target: str,
            max_bytes: int,
            feature_names: list[str],
            transformation: str,
            transform_payload_size: int,
            transform_output_dir: str | Path,
        ) -> None:
            self.samples = samples
            self.label_to_index = label_to_index
            self.target = target
            self.max_bytes = max_bytes
            self.feature_names = feature_names
            self.transformation = transformation
            self.transform_payload_size = transform_payload_size
            self.transform_output_dir = Path(transform_output_dir)

        def __len__(self) -> int:
            return len(self.samples)

        def __getitem__(self, index: int):
            sample = self.samples[index]
            label = _sample_target(sample, self.target)
            transformed_path = self._transformed_path_for_sample(sample, index)
            clean = _tensorize_path(sample.path, self.max_bytes, self.feature_names)
            transformed = _tensorize_path(transformed_path, self.max_bytes, self.feature_names)
            return {
                "bytes": clean["bytes"],
                "features": clean["features"],
                "transformed_bytes": transformed["bytes"],
                "transformed_features": transformed["features"],
                "label": torch.tensor(self.label_to_index[label], dtype=torch.long),
            }

        def _transformed_path_for_sample(self, sample: BinarySample, index: int) -> Path:
            output_path = self.transform_output_dir / self.transformation / f"{sample.sample_id}_{index}.bin"
            validation_path = self.transform_output_dir / "validation" / self.transformation / f"{sample.sample_id}_{index}.json"
            if output_path.exists() and validation_path.exists():
                return output_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if self.transformation == "append_overlay":
                result = append_overlay(
                    sample.path,
                    output_path,
                    payload_size=self.transform_payload_size,
                    seed=index,
                )
            elif self.transformation == "section_slack":
                result = mutate_slack_space(
                    sample.path,
                    output_path,
                    max_bytes=self.transform_payload_size,
                    seed=index,
                )
            else:
                raise ValueError(f"unsupported CAR-FP-MalAT transformation: {self.transformation}")
            validation = validate_transformation(result, validation_path)
            return output_path if validation.allowed_for_evaluation else sample.path


def train_torch_detector(config: TorchTrainingConfig) -> dict[str, object]:
    if torch is None or DataLoader is None or F is None:
        raise ImportError("PyTorch is required for raw-byte and hybrid BinaryShield training")
    from binaryshield.models.byte_cnn import RawByteCNN
    from binaryshield.models.hybrid_binaryshield import HybridBinaryShield

    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    samples = load_manifest(config.manifest, config.root_dir)
    train_samples = list(iter_split(samples, "train"))
    val_samples = list(iter_split(samples, "val")) or list(iter_split(samples, "test"))
    if not train_samples or not val_samples:
        raise ValueError("manifest must contain train and val/test splits")
    class_names = sorted({_sample_target(sample, config.target) for sample in samples})
    label_to_index = {label: index for index, label in enumerate(class_names)}
    feature_names = _infer_feature_names(train_samples[: min(len(train_samples), 64)])
    if config.use_car_fp_malat:
        if not config.transformed_training:
            raise ValueError("use_car_fp_malat requires transformed_training=True")
        train_dataset = PairedBinaryTorchDataset(
            train_samples,
            label_to_index,
            config.target,
            config.max_bytes,
            feature_names,
            config.transformation,
            config.transform_payload_size,
            output_dir / "car_fp_malat_training",
        )
    else:
        train_dataset = BinaryTorchDataset(
            train_samples,
            label_to_index,
            config.target,
            config.max_bytes,
            feature_names,
            transformed_training=config.transformed_training,
            transformation=config.transformation,
            transform_payload_size=config.transform_payload_size,
            transform_output_dir=output_dir / "transformed_training",
        )
    val_dataset = BinaryTorchDataset(val_samples, label_to_index, config.target, config.max_bytes, feature_names)
    train_loader = DataLoader(train_dataset, batch_size=config.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=config.batch_size, shuffle=False)
    device = _resolve_device(config.device)
    if config.model_type == "raw_byte_cnn":
        model = RawByteCNN(num_classes=len(class_names)).to(device)
    elif config.model_type == "hybrid_binaryshield":
        model = HybridBinaryShield(num_classes=len(class_names), pe_feature_dim=len(feature_names)).to(device)
    else:
        raise ValueError(f"unsupported model_type: {config.model_type}")
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate)
    history: list[dict[str, float]] = []
    best_selection_score = -1.0
    best_path = output_dir / "best_model.pt"
    class_weight_map = _initial_class_weights(train_samples, config.target, class_names)
    objective = describe_objective(
        CARFPMalATConfig(
            clean_loss_weight=config.clean_loss_weight,
            transformed_loss_weight=config.transformed_loss_weight,
            consistency_weight=config.consistency_weight,
            weak_class_weight=1.0,
        )
    )
    for epoch in range(1, config.epochs + 1):
        class_weight_tensor = _class_weight_tensor(class_weight_map, class_names, device)
        if config.use_car_fp_malat:
            train_metrics = _run_car_fp_malat_epoch(model, train_loader, optimizer, device, config, class_weight_tensor)
        else:
            train_metrics = {"train_loss": _run_epoch(model, train_loader, optimizer, device, config.model_type, class_weight_tensor)}
        val_metrics = _evaluate_torch_model(model, val_loader, device, config.model_type, class_names)
        row = {"epoch": float(epoch), **train_metrics, **val_metrics}
        history.append(row)
        if config.adaptive_class_weights:
            class_weight_map = _update_weight_map(class_weight_map, val_metrics, class_names, config)
        selection_score = val_metrics.get("macro_f1", val_metrics["accuracy"])
        if selection_score > best_selection_score:
            best_selection_score = selection_score
            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "class_names": class_names,
                    "feature_names": feature_names,
                    "config": config.to_dict(),
                },
                best_path,
            )
    summary = {
        "config": config.to_dict(),
        "objective": objective if config.use_car_fp_malat else {"name": "cross_entropy"},
        "class_names": class_names,
        "feature_names": feature_names,
        "history": history,
        "best_model": str(best_path),
        "best_selection_score": best_selection_score,
        "claim_boundary": "Training metrics are valid only for the provided manifest and evaluated transformations.",
    }
    (output_dir / "training_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _sample_target(sample: BinarySample, target: str) -> str:
    if target == "family" and sample.family:
        return sample.family
    return sample.label


def _infer_feature_names(samples: list[BinarySample]) -> list[str]:
    names: set[str] = set()
    for sample in samples:
        try:
            names.update(parse_pe(sample.path).to_vector().keys())
        except Exception:
            continue
    return sorted(names)


def _tensorize_path(path: str | Path, max_bytes: int, feature_names: list[str]):
    byte_values = load_bytes(path, max_bytes).byte_values
    if len(byte_values) < max_bytes:
        byte_values = byte_values + [256] * (max_bytes - len(byte_values))
    vector = parse_pe(path).to_vector()
    feature_values = [float(vector.get(name, 0.0)) for name in feature_names]
    return {
        "bytes": torch.tensor(byte_values, dtype=torch.long),
        "features": torch.tensor(feature_values, dtype=torch.float32),
    }


def _resolve_device(device: str):
    if torch is None:
        raise ImportError("PyTorch is required")
    if device != "auto":
        return torch.device(device)
    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def _forward(model, batch, model_type: str):
    if model_type == "hybrid_binaryshield":
        return model(batch["bytes"], batch["features"])
    return model(batch["bytes"])


def _run_epoch(model, loader, optimizer, device, model_type: str, class_weight_tensor=None) -> float:
    model.train()
    total_loss = 0.0
    total = 0
    for batch in loader:
        batch = {key: value.to(device) for key, value in batch.items()}
        optimizer.zero_grad(set_to_none=True)
        logits = _forward(model, batch, model_type)
        loss = F.cross_entropy(logits, batch["label"], weight=class_weight_tensor)
        loss.backward()
        optimizer.step()
        batch_size = int(batch["label"].shape[0])
        total_loss += float(loss.detach().cpu()) * batch_size
        total += batch_size
    return total_loss / max(total, 1)


def _run_car_fp_malat_epoch(model, loader, optimizer, device, config: TorchTrainingConfig, class_weight_tensor) -> dict[str, float]:
    model.train()
    total_loss = 0.0
    total_clean_loss = 0.0
    total_transformed_loss = 0.0
    total_consistency_loss = 0.0
    total = 0
    for batch in loader:
        batch = {key: value.to(device) for key, value in batch.items()}
        optimizer.zero_grad(set_to_none=True)
        clean_logits = _forward(model, batch, config.model_type)
        transformed_batch = {
            "bytes": batch["transformed_bytes"],
            "features": batch["transformed_features"],
        }
        transformed_logits = _forward(model, transformed_batch, config.model_type)
        clean_loss = F.cross_entropy(clean_logits, batch["label"], weight=class_weight_tensor)
        transformed_loss = F.cross_entropy(transformed_logits, batch["label"], weight=class_weight_tensor)
        consistency_loss = _symmetric_kl(clean_logits, transformed_logits)
        loss = (
            config.clean_loss_weight * clean_loss
            + config.transformed_loss_weight * transformed_loss
            + config.consistency_weight * consistency_loss
        )
        loss.backward()
        optimizer.step()
        batch_size = int(batch["label"].shape[0])
        total_loss += float(loss.detach().cpu()) * batch_size
        total_clean_loss += float(clean_loss.detach().cpu()) * batch_size
        total_transformed_loss += float(transformed_loss.detach().cpu()) * batch_size
        total_consistency_loss += float(consistency_loss.detach().cpu()) * batch_size
        total += batch_size
    denom = max(total, 1)
    return {
        "train_loss": total_loss / denom,
        "train_clean_loss": total_clean_loss / denom,
        "train_transformed_loss": total_transformed_loss / denom,
        "train_consistency_loss": total_consistency_loss / denom,
    }


def _evaluate_torch_model(model, loader, device, model_type: str, class_names: list[str]) -> dict[str, float]:
    model.eval()
    target_indices: list[int] = []
    prediction_indices: list[int] = []
    with torch.inference_mode():
        for batch in loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            predictions = torch.argmax(_forward(model, batch, model_type), dim=1)
            prediction_indices.extend(int(value) for value in predictions.detach().cpu().tolist())
            target_indices.extend(int(value) for value in batch["label"].detach().cpu().tolist())
    targets = [class_names[index] for index in target_indices]
    predictions = [class_names[index] for index in prediction_indices]
    metrics = classification_summary(targets, predictions, class_names)
    return {
        "accuracy": metrics["accuracy"],
        "macro_f1": metrics["macro_f1"],
        "worst_class_f1": metrics["worst_class_f1"],
        "classes_below_f1_050": metrics["classes_below_f1_050"],
        "classes_below_f1_080": metrics["classes_below_f1_080"],
        **{f"val_{key}": value for key, value in metrics.items() if key.endswith("_f1")},
    }


def _symmetric_kl(left_logits, right_logits):
    left_log_prob = F.log_softmax(left_logits, dim=1)
    right_log_prob = F.log_softmax(right_logits, dim=1)
    left_prob = F.softmax(left_logits, dim=1)
    right_prob = F.softmax(right_logits, dim=1)
    return 0.5 * (
        F.kl_div(left_log_prob, right_prob.detach(), reduction="batchmean")
        + F.kl_div(right_log_prob, left_prob.detach(), reduction="batchmean")
    )


def _initial_class_weights(samples: list[BinarySample], target: str, class_names: list[str]) -> dict[str, float]:
    counts = {name: 0 for name in class_names}
    for sample in samples:
        counts[_sample_target(sample, target)] += 1
    total = sum(counts.values())
    num_classes = max(len(class_names), 1)
    return {
        name: total / max(num_classes * count, 1)
        for name, count in counts.items()
    }


def _class_weight_tensor(class_weight_map: dict[str, float], class_names: list[str], device):
    return torch.tensor([float(class_weight_map.get(name, 1.0)) for name in class_names], dtype=torch.float32, device=device)


def _update_weight_map(
    previous: dict[str, float],
    val_metrics: dict[str, float],
    class_names: list[str],
    config: TorchTrainingConfig,
) -> dict[str, float]:
    validation_f1 = {name: float(val_metrics.get(f"val_{_safe_label(name)}_f1", config.adaptive_target_f1)) for name in class_names}
    return update_class_weights(
        previous,
        validation_f1,
        AdaptiveWeightConfig(
            target_f1=config.adaptive_target_f1,
            max_weight=config.adaptive_max_weight,
            smoothing=config.adaptive_smoothing,
        ),
    )


def _safe_label(label: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in label).strip("_")
