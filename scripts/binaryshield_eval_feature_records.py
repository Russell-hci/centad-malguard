from __future__ import annotations

import argparse
import csv
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
    parser = argparse.ArgumentParser(description="Evaluate a PE-derived feature-record baseline.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--features-npz", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/feature_record_eval"))
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument("--feature-key", default="X")
    parser.add_argument("--split", default="test")
    parser.add_argument(
        "--model-type",
        choices=["centroid", "extra_trees", "random_forest"],
        default=None,
        help="Model type. If omitted, infer from model suffix/name.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    samples = list(iter_feature_split(load_feature_manifest(args.manifest), args.split))
    matrix = load_npz_features(args.features_npz, args.feature_key)
    model_type = args.model_type or _infer_model_type(args.model)
    if model_type == "centroid":
        detector = FeatureRecordCentroidDetector.load(args.model)
    else:
        detector = FeatureRecordSklearnDetector.load(args.model)
    predictions = detector.predict_rows(select_feature_rows(matrix, samples))
    targets = sample_targets(samples, args.target)
    metrics = classification_summary(targets, predictions, sorted(set(targets) | set(predictions)))
    rows = [
        {
            "sample_id": sample.sample_id,
            "record_index": sample.record_index,
            "label": sample.label,
            "family": sample.family or "",
            "target": target,
            "prediction": prediction,
            "correct": target == prediction,
        }
        for sample, target, prediction in zip(samples, targets, predictions, strict=False)
    ]
    (args.output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    with (args.output_dir / "predictions.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys() if rows else ["sample_id"])
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(metrics, indent=2))


def _infer_model_type(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".joblib") or "extra_trees" in name or "random_forest" in name:
        if "random_forest" in name:
            return "random_forest"
        return "extra_trees"
    return "centroid"


if __name__ == "__main__":
    main()
