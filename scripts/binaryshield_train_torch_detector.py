from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.training.torch_pipeline import TorchTrainingConfig, train_torch_detector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train raw-byte or hybrid BinaryShield PyTorch detector.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/torch_detector"))
    parser.add_argument("--model-type", choices=["raw_byte_cnn", "hybrid_binaryshield"], default="raw_byte_cnn")
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument("--max-bytes", type=int, default=65536)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--device", default="auto")
    parser.add_argument("--transformed-training", action="store_true")
    parser.add_argument("--transformation", choices=["append_overlay", "section_slack"], default="append_overlay")
    parser.add_argument("--transform-payload-size", type=int, default=1024)
    parser.add_argument("--use-car-fp-malat", action="store_true")
    parser.add_argument("--consistency-weight", type=float, default=0.25)
    parser.add_argument("--clean-loss-weight", type=float, default=1.0)
    parser.add_argument("--transformed-loss-weight", type=float, default=1.0)
    parser.add_argument("--no-adaptive-class-weights", action="store_true")
    parser.add_argument("--adaptive-target-f1", type=float, default=0.80)
    parser.add_argument("--adaptive-max-weight", type=float, default=5.0)
    parser.add_argument("--adaptive-smoothing", type=float, default=0.5)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = TorchTrainingConfig(
        manifest=str(args.manifest),
        root_dir=str(args.root_dir) if args.root_dir else None,
        output_dir=str(args.output_dir),
        model_type=args.model_type,
        target=args.target,
        max_bytes=args.max_bytes,
        batch_size=args.batch_size,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        device=args.device,
        transformed_training=args.transformed_training,
        transformation=args.transformation,
        transform_payload_size=args.transform_payload_size,
        use_car_fp_malat=args.use_car_fp_malat,
        consistency_weight=args.consistency_weight,
        clean_loss_weight=args.clean_loss_weight,
        transformed_loss_weight=args.transformed_loss_weight,
        adaptive_class_weights=not args.no_adaptive_class_weights,
        adaptive_target_f1=args.adaptive_target_f1,
        adaptive_max_weight=args.adaptive_max_weight,
        adaptive_smoothing=args.adaptive_smoothing,
    )
    summary = train_torch_detector(config)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
