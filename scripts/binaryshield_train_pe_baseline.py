from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import iter_split, load_manifest
from binaryshield.evaluation.metrics import classification_summary
from binaryshield.models.byte_histogram import (
    ByteHistogramCentroidDetector,
    CalibratedByteHistogramDetector,
    ByteHistogramLogisticDetector,
    HybridCentroidDetector,
)
from binaryshield.models.pe_feature_centroid import PEFeatureCentroidDetector
from binaryshield.models.pe_feature_model import PEFeatureSklearnDetector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a PE-feature sklearn baseline from a BinaryShield manifest.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/pe_feature_baseline"))
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument(
        "--model-type",
        choices=[
            "centroid",
            "sklearn_random_forest",
            "byte_histogram_centroid",
            "byte_histogram_calibrated",
            "byte_histogram_logistic",
            "hybrid_centroid",
        ],
        default="centroid",
    )
    parser.add_argument("--max-bytes", type=int, default=None, help="Optional byte cap for byte-based centroid models.")
    return parser.parse_args()


def _target(sample, target: str) -> str:
    if target == "family" and sample.family:
        return sample.family
    return sample.label


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    samples = load_manifest(args.manifest, args.root_dir)
    train = list(iter_split(samples, "train"))
    val = list(iter_split(samples, "val")) or list(iter_split(samples, "test"))
    if not train or not val:
        raise ValueError("manifest must contain train and val/test split rows")
    if args.model_type == "sklearn_random_forest":
        detector = PEFeatureSklearnDetector.random_forest()
        model_path = args.output_dir / "pe_feature_detector.joblib"
    elif args.model_type == "byte_histogram_centroid":
        detector = ByteHistogramCentroidDetector.create(max_bytes=args.max_bytes)
        model_path = args.output_dir / "byte_histogram_detector.json"
    elif args.model_type == "byte_histogram_calibrated":
        detector = CalibratedByteHistogramDetector.create(max_bytes=args.max_bytes)
        model_path = args.output_dir / "byte_histogram_calibrated_detector.json"
    elif args.model_type == "byte_histogram_logistic":
        detector = ByteHistogramLogisticDetector.create(max_bytes=args.max_bytes)
        model_path = args.output_dir / "byte_histogram_logistic_detector.json"
    elif args.model_type == "hybrid_centroid":
        detector = HybridCentroidDetector.create(max_bytes=args.max_bytes)
        model_path = args.output_dir / "hybrid_centroid_detector.json"
    else:
        detector = PEFeatureCentroidDetector.create()
        model_path = args.output_dir / "pe_feature_detector.json"
    detector.fit([sample.path for sample in train], [_target(sample, args.target) for sample in train])
    if hasattr(detector, "calibrate"):
        detector.calibrate([sample.path for sample in val], [_target(sample, args.target) for sample in val])
    predictions = detector.predict([sample.path for sample in val])
    targets = [_target(sample, args.target) for sample in val]
    metrics = classification_summary(targets, predictions, sorted(set(targets) | set(predictions)))
    detector.save(model_path)
    (args.output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
