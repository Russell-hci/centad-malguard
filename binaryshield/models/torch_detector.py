from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from binaryshield.byte_loader import load_bytes
from binaryshield.pe_features import parse_pe

try:
    import torch
except ImportError:  # pragma: no cover - depends on runtime
    torch = None


@dataclass
class TorchBinaryShieldDetector:
    """Prediction wrapper for raw-byte and hybrid BinaryShield checkpoints."""

    model: object
    class_names: list[str]
    model_type: str
    feature_names: list[str]
    max_bytes: int
    device: object
    detector_name: str

    @classmethod
    def load(cls, checkpoint_path: str | Path, device: str = "auto") -> "TorchBinaryShieldDetector":
        if torch is None:
            raise ImportError("PyTorch is required to load BinaryShield torch detectors")
        from binaryshield.models.byte_cnn import RawByteCNN
        from binaryshield.models.hybrid_binaryshield import HybridBinaryShield

        resolved_device = _resolve_device(device)
        checkpoint = torch.load(checkpoint_path, map_location=resolved_device, weights_only=False)
        config = checkpoint.get("config", {})
        class_names = list(checkpoint["class_names"])
        feature_names = list(checkpoint.get("feature_names", []))
        model_type = str(config.get("model_type", "raw_byte_cnn"))
        max_bytes = int(config.get("max_bytes", 65536))
        if model_type == "raw_byte_cnn":
            model = RawByteCNN(num_classes=len(class_names))
        elif model_type == "hybrid_binaryshield":
            model = HybridBinaryShield(num_classes=len(class_names), pe_feature_dim=len(feature_names))
        else:
            raise ValueError(f"unsupported checkpoint model_type: {model_type}")
        model.load_state_dict(checkpoint["model_state_dict"])
        model.to(resolved_device)
        model.eval()
        return cls(
            model=model,
            class_names=class_names,
            model_type=model_type,
            feature_names=feature_names,
            max_bytes=max_bytes,
            device=resolved_device,
            detector_name=f"torch_{model_type}",
        )

    def predict(self, paths: list[str | Path]) -> list[str]:
        if torch is None:
            raise ImportError("PyTorch is required")
        predictions: list[str] = []
        with torch.inference_mode():
            for path in paths:
                byte_values = load_bytes(path, self.max_bytes).byte_values
                if len(byte_values) < self.max_bytes:
                    byte_values = byte_values + [256] * (self.max_bytes - len(byte_values))
                byte_tensor = torch.tensor([byte_values], dtype=torch.long, device=self.device)
                if self.model_type == "hybrid_binaryshield":
                    vector = parse_pe(path).to_vector()
                    features = [float(vector.get(name, 0.0)) for name in self.feature_names]
                    feature_tensor = torch.tensor([features], dtype=torch.float32, device=self.device)
                    logits = self.model(byte_tensor, feature_tensor)  # type: ignore[misc,operator]
                else:
                    logits = self.model(byte_tensor)  # type: ignore[misc,operator]
                index = int(torch.argmax(logits, dim=1).item())
                predictions.append(self.class_names[index])
        return predictions


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
