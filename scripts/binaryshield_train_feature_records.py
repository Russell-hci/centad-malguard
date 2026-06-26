from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.evaluation.metrics import classification_summary  # noqa: E402
from binaryshield.feature_records import (  # noqa: E402
    iter_feature_split,
    load_feature_manifest,
    load_npz_features,
    sample_targets,
    select_feature_rows,
)
from binaryshield.models.feature_record_centroid import FeatureRecordCentroidDetector  # noqa: E402
from binaryshield.models.feature_record_sklearn import FeatureRecordSklearnDetector  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a PE-derived feature-record baseline.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--features-npz", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/feature_record_baseline"))
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument("--feature-key", default="X")
    parser.add_argument(
        "--model-type",
        choices=["centroid", "extra_trees", "random_forest"],
        default="centroid",
        help="Feature-record detector to train.",
    )
    parser.add_argument("--n-estimators", type=int, default=300)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    samples = load_feature_manifest(args.manifest)
    matrix = load_npz_features(args.features_npz, args.feature_key)
    train = list(iter_feature_split(samples, "train"))
    val = list(iter_feature_split(samples, "val")) or list(iter_feature_split(samples, "test"))
    if not train or not val:
        raise ValueError("feature manifest must contain train and val/test split rows")
    if args.model_type == "centroid":
        detector = FeatureRecordCentroidDetector.create()
        model_path = args.output_dir / "feature_record_centroid.json"
    else:
        detector = FeatureRecordSklearnDetector.create(args.model_type, n_estimators=args.n_estimators)
        model_path = args.output_dir / f"feature_record_{args.model_type}.joblib"
    detector.fit(select_feature_rows(matrix, train), sample_targets(train, args.target))
    predictions = detector.predict_rows(select_feature_rows(matrix, val))
    targets = sample_targets(val, args.target)
    metrics = classification_summary(targets, predictions, sorted(set(targets) | set(predictions)))
    detector.save(model_path)
    summary = {
        "model_path": str(model_path),
        "model_type": args.model_type,
        "manifest": str(args.manifest),
        "features_npz": str(args.features_npz),
        "target": args.target,
        "feature_key": args.feature_key,
        "train_samples": len(train),
        "validation_samples": len(val),
        "metrics": metrics,
        "claim_boundary": "Feature-record metrics do not validate PE-preserving transformations without raw binaries.",
    }
    (args.output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (args.output_dir / "training_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
