import argparse
import sys
from collections import Counter
from pathlib import Path
import random

import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.experiment import sha256_file, utc_iso_timestamp, write_json


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"}
DEFAULT_DATASET_DIR = Path("datasets/raw/malimg")
DEFAULT_OUTPUT_DIR = Path("datasets/splits")
DEFAULT_MANIFEST_PATH = Path("manifests/split_manifest.json")
DEFAULT_SEED = 42


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create stratified train/validation/test splits for malware images.",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET_DIR,
        help="Root dataset directory containing one subdirectory per class.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where split CSV files will be saved.",
    )
    parser.add_argument(
        "--train-size",
        type=float,
        default=0.70,
        help="Training split ratio.",
    )
    parser.add_argument(
        "--val-size",
        type=float,
        default=0.15,
        help="Validation split ratio.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.15,
        help="Test split ratio.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed used for deterministic splitting.",
    )
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path for the saved split manifest JSON.",
    )
    parser.add_argument(
        "--duplicate-aware",
        action="store_true",
        help="Keep identical content hashes within the same split.",
    )
    parser.add_argument(
        "--dataset-manifest-path",
        type=Path,
        default=None,
        help=(
            "Optional dataset manifest containing per-file SHA256 hashes. "
            "Required for fast duplicate-aware splitting unless files should be rehashed."
        ),
    )
    return parser.parse_args()


def collect_samples(dataset_dir: Path) -> pd.DataFrame:
    records: list[dict[str, str]] = []

    for file_path in sorted(dataset_dir.rglob("*")):
        if not file_path.is_file() or file_path.suffix.lower() not in IMAGE_EXTENSIONS:
            continue

        relative_path = file_path.relative_to(dataset_dir)
        label = relative_path.parts[0]
        records.append(
            {
                "filepath": str(file_path.resolve()),
                "label": label,
            }
        )

    dataframe = pd.DataFrame.from_records(records)
    if dataframe.empty:
        raise RuntimeError(f"No image files found in {dataset_dir}")

    class_counts = dataframe["label"].value_counts()
    rare_classes = class_counts[class_counts < 3].index.tolist()
    if rare_classes:
        raise RuntimeError(
            "Each class must contain at least 3 images for a stratified 70/15/15 split. "
            f"Classes below the threshold: {rare_classes}"
        )

    return dataframe


def load_manifest_hashes(dataset_manifest_path: Path, dataset_dir: Path) -> dict[str, str]:
    import json

    manifest = json.loads(dataset_manifest_path.read_text())
    manifest_root = Path(manifest["extracted_dataset_root"]).resolve()
    expected_root = dataset_dir.resolve()

    if manifest_root != expected_root:
        raise ValueError(
            "Dataset manifest root does not match --dataset-dir: "
            f"{manifest_root} != {expected_root}"
        )

    hash_map: dict[str, str] = {}
    for entry in manifest.get("files", []):
        file_hash = entry.get("sha256")
        if not file_hash:
            raise ValueError(
                "Dataset manifest does not contain per-file SHA256 hashes. "
                "Regenerate it without --skip-file-hashes."
            )
        file_path = (manifest_root / entry["relative_path"]).resolve()
        hash_map[str(file_path)] = file_hash

    return hash_map


def add_content_hashes(
    dataframe: pd.DataFrame,
    dataset_dir: Path,
    dataset_manifest_path: Path | None,
) -> pd.DataFrame:
    if dataset_manifest_path is not None:
        hash_map = load_manifest_hashes(dataset_manifest_path, dataset_dir)
        dataframe = dataframe.copy()
        dataframe["content_hash"] = dataframe["filepath"].map(
            lambda path: hash_map[str(Path(path).resolve())]
        )
        missing_hashes = dataframe["content_hash"].isna().sum()
        if missing_hashes:
            raise RuntimeError(
                f"{missing_hashes} split candidates were missing from the dataset manifest."
            )
        return dataframe

    dataframe = dataframe.copy()
    dataframe["content_hash"] = dataframe["filepath"].map(lambda path: sha256_file(Path(path)))
    return dataframe


def validate_ratios(train_size: float, val_size: float, test_size: float) -> None:
    total = train_size + val_size + test_size
    if abs(total - 1.0) > 1e-6:
        raise ValueError("Train/validation/test ratios must sum to 1.0.")


def split_dataframe(
    dataframe: pd.DataFrame,
    train_size: float,
    val_size: float,
    test_size: float,
    seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    validate_ratios(train_size, val_size, test_size)

    train_frame, remaining_frame = train_test_split(
        dataframe,
        train_size=train_size,
        stratify=dataframe["label"],
        random_state=seed,
    )

    remaining_val_fraction = val_size / (val_size + test_size)
    val_frame, test_frame = train_test_split(
        remaining_frame,
        train_size=remaining_val_fraction,
        stratify=remaining_frame["label"],
        random_state=seed,
    )

    return (
        train_frame.reset_index(drop=True),
        val_frame.reset_index(drop=True),
        test_frame.reset_index(drop=True),
    )


def split_duplicate_aware_dataframe(
    dataframe: pd.DataFrame,
    train_size: float,
    val_size: float,
    test_size: float,
    seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    validate_ratios(train_size, val_size, test_size)

    if "content_hash" not in dataframe.columns:
        raise ValueError("Duplicate-aware splitting requires a content_hash column.")

    rng = random.Random(seed)
    split_names = ["train", "val", "test"]
    ratios = {
        "train": train_size,
        "val": val_size,
        "test": test_size,
    }
    assignments: dict[str, list[pd.DataFrame]] = {name: [] for name in split_names}

    for label in sorted(dataframe["label"].unique()):
        class_frame = dataframe[dataframe["label"] == label]
        groups = [
            {
                "content_hash": content_hash,
                "size": len(group_frame),
                "frame": group_frame,
                "tie_breaker": rng.random(),
            }
            for content_hash, group_frame in class_frame.groupby("content_hash", sort=True)
        ]

        if len(groups) < 3:
            raise RuntimeError(
                f"Class {label} has only {len(groups)} unique content hashes; "
                "cannot guarantee train/val/test coverage."
            )

        targets = {name: len(class_frame) * ratio for name, ratio in ratios.items()}
        counts = {name: 0 for name in split_names}

        groups.sort(key=lambda item: (-item["size"], item["tie_breaker"], item["content_hash"]))
        for group in groups:
            group_size = group["size"]

            def score(split_name: str) -> tuple[float, float, int]:
                simulated_counts = counts.copy()
                simulated_counts[split_name] += group_size
                total_deviation = sum(
                    abs(simulated_counts[name] - targets[name]) for name in split_names
                )
                split_deficit = targets[split_name] - counts[split_name]
                return (total_deviation, -split_deficit, counts[split_name])

            selected_split = min(split_names, key=score)
            assignments[selected_split].append(group["frame"])
            counts[selected_split] += group_size

    return tuple(
        pd.concat(assignments[name], ignore_index=True).sample(
            frac=1.0,
            random_state=seed,
        ).reset_index(drop=True)
        for name in split_names
    )


def save_split(frame: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    columns = ["filepath", "label"]
    if "content_hash" in frame.columns:
        columns.append("content_hash")
    frame.to_csv(output_path, index=False, columns=columns)


def describe_split(name: str, frame: pd.DataFrame) -> None:
    distribution = Counter(frame["label"])
    print(f"{name}: {len(frame)} samples")
    for label, count in sorted(distribution.items()):
        print(f"  {label}: {count}")


def class_distribution(frame: pd.DataFrame) -> dict[str, int]:
    return dict(sorted(Counter(frame["label"]).items()))


def validate_no_overlap(*frames: pd.DataFrame) -> dict[str, object]:
    split_names = ["train", "val", "test"]
    path_sets = {
        name: set(frame["filepath"].tolist()) for name, frame in zip(split_names, frames)
    }
    overlaps: dict[str, list[str]] = {}

    for left_index, left_name in enumerate(split_names):
        for right_name in split_names[left_index + 1:]:
            overlap = sorted(path_sets[left_name].intersection(path_sets[right_name]))
            overlaps[f"{left_name}_{right_name}"] = overlap

    return {
        "has_overlap": any(overlaps.values()),
        "overlap_counts": {name: len(paths) for name, paths in overlaps.items()},
        "overlaps": overlaps,
    }


def validate_no_content_hash_overlap(*frames: pd.DataFrame) -> dict[str, object] | None:
    if any("content_hash" not in frame.columns for frame in frames):
        return None

    split_names = ["train", "val", "test"]
    hash_sets = {
        name: set(frame["content_hash"].tolist())
        for name, frame in zip(split_names, frames)
    }
    overlaps: dict[str, list[str]] = {}

    for left_index, left_name in enumerate(split_names):
        for right_name in split_names[left_index + 1:]:
            overlap = sorted(hash_sets[left_name].intersection(hash_sets[right_name]))
            overlaps[f"{left_name}_{right_name}"] = overlap

    return {
        "has_overlap": any(overlaps.values()),
        "overlap_counts": {name: len(hashes) for name, hashes in overlaps.items()},
        "overlaps": overlaps,
    }


def build_split_manifest(
    dataset_dir: Path,
    output_dir: Path,
    train_frame: pd.DataFrame,
    val_frame: pd.DataFrame,
    test_frame: pd.DataFrame,
    train_size: float,
    val_size: float,
    test_size: float,
    seed: int,
    split_strategy: str,
) -> dict:
    overlap_validation = validate_no_overlap(train_frame, val_frame, test_frame)
    content_hash_overlap_validation = validate_no_content_hash_overlap(
        train_frame,
        val_frame,
        test_frame,
    )
    csv_paths = {
        "train": output_dir / "train.csv",
        "val": output_dir / "val.csv",
        "test": output_dir / "test.csv",
    }
    split_frames = {
        "train": train_frame,
        "val": val_frame,
        "test": test_frame,
    }

    return {
        "manifest_type": "split",
        "created_at_utc": utc_iso_timestamp(),
        "dataset_root": str(dataset_dir.resolve()),
        "split_strategy": split_strategy,
        "seed": seed,
        "ratios": {
            "train": train_size,
            "val": val_size,
            "test": test_size,
        },
        "sample_counts": {
            name: len(frame) for name, frame in split_frames.items()
        },
        "class_distributions": {
            name: class_distribution(frame) for name, frame in split_frames.items()
        },
        "missing_classes": {
            name: sorted(
                set(train_frame["label"])
                .union(set(val_frame["label"]))
                .union(set(test_frame["label"]))
                .difference(set(frame["label"]))
            )
            for name, frame in split_frames.items()
        },
        "overlap_validation": overlap_validation,
        "content_hash_overlap_validation": content_hash_overlap_validation,
        "csv_hashes": {
            name: {
                "path": str(path.resolve()),
                "sha256": sha256_file(path),
            }
            for name, path in csv_paths.items()
        },
    }


def main() -> None:
    args = parse_args()
    dataframe = collect_samples(args.dataset_dir)

    if args.duplicate_aware:
        dataframe = add_content_hashes(
            dataframe=dataframe,
            dataset_dir=args.dataset_dir,
            dataset_manifest_path=args.dataset_manifest_path,
        )
        train_frame, val_frame, test_frame = split_duplicate_aware_dataframe(
            dataframe=dataframe,
            train_size=args.train_size,
            val_size=args.val_size,
            test_size=args.test_size,
            seed=args.seed,
        )
        split_strategy = "duplicate_aware_content_hash"
    else:
        train_frame, val_frame, test_frame = split_dataframe(
            dataframe=dataframe,
            train_size=args.train_size,
            val_size=args.val_size,
            test_size=args.test_size,
            seed=args.seed,
        )
        split_strategy = "stratified_file_path"

    save_split(train_frame, args.output_dir / "train.csv")
    save_split(val_frame, args.output_dir / "val.csv")
    save_split(test_frame, args.output_dir / "test.csv")
    manifest = build_split_manifest(
        dataset_dir=args.dataset_dir,
        output_dir=args.output_dir,
        train_frame=train_frame,
        val_frame=val_frame,
        test_frame=test_frame,
        train_size=args.train_size,
        val_size=args.val_size,
        test_size=args.test_size,
        seed=args.seed,
        split_strategy=split_strategy,
    )
    write_json(manifest, args.manifest_path)

    print(f"Saved splits to: {args.output_dir}")
    print(f"Saved split manifest to: {args.manifest_path}")
    describe_split("Train", train_frame)
    describe_split("Validation", val_frame)
    describe_split("Test", test_frame)


if __name__ == "__main__":
    main()
