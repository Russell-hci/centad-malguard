from __future__ import annotations

import json
from pathlib import Path

from binaryshield.models.byte_histogram import (
    ByteHistogramCentroidDetector,
    CalibratedByteHistogramDetector,
    ByteHistogramLogisticDetector,
    HybridCentroidDetector,
)
from binaryshield.models.pe_feature_centroid import PEFeatureCentroidDetector
from binaryshield.models.pe_feature_model import PEFeatureSklearnDetector


def load_pe_feature_detector(path: str | Path):
    model_path = Path(path)
    if model_path.suffix == ".joblib":
        return PEFeatureSklearnDetector.load(model_path)
    payload = json.loads(model_path.read_text(encoding="utf-8"))
    detector_name = str(payload.get("detector_name", "pe_feature_centroid"))
    if detector_name == "byte_histogram_centroid":
        return ByteHistogramCentroidDetector.load(model_path)
    if detector_name == "byte_histogram_calibrated":
        return CalibratedByteHistogramDetector.load(model_path)
    if detector_name == "byte_histogram_logistic":
        return ByteHistogramLogisticDetector.load(model_path)
    if detector_name == "hybrid_centroid":
        return HybridCentroidDetector.load(model_path)
    return PEFeatureCentroidDetector.load(model_path)


def load_any_detector(path: str | Path, device: str = "auto"):
    model_path = Path(path)
    if model_path.suffix in {".pt", ".pth"}:
        from binaryshield.models.torch_detector import TorchBinaryShieldDetector

        return TorchBinaryShieldDetector.load(model_path, device=device)
    return load_pe_feature_detector(model_path)
