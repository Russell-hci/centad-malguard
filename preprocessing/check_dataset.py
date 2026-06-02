import argparse
import sys
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
from PIL import Image, UnidentifiedImageError
from tqdm import tqdm

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.experiment import sha256_file, sha256_text, utc_iso_timestamp, write_json


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"}
DEFAULT_DATASET_DIR = Path("datasets/raw/malimg")
DEFAULT_OUTPUT_PATH = Path("results/class_distribution.png")
DEFAULT_MANIFEST_PATH = Path("manifests/dataset_manifest.json")
DEFAULT_KAGGLE_SLUG = "ikrambenabd/malimg-original"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a malware image dataset and plot its class distribution.",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET_DIR,
        help="Root dataset directory containing one subdirectory per class.",
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Path for the saved class distribution plot.",
    )
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path for the saved dataset manifest JSON.",
    )
    parser.add_argument(
        "--dataset-source",
        default="kaggle",
        help="Human-readable dataset source.",
    )
    parser.add_argument(
        "--kaggle-slug",
        default=DEFAULT_KAGGLE_SLUG,
        help="Kaggle dataset slug used to acquire the dataset.",
    )
    parser.add_argument(
        "--download-timestamp",
        default=None,
        help="Optional dataset download timestamp to record in the manifest.",
    )
    parser.add_argument(
        "--skip-file-hashes",
        action="store_true",
        help="Skip per-file SHA256 hashing and build a metadata-only dataset hash.",
    )
    return parser.parse_args()


def find_image_files(dataset_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in dataset_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
    )


def get_label_for_path(dataset_dir: Path, file_path: Path) -> str:
    relative_path = file_path.relative_to(dataset_dir)
    return relative_path.parts[0]


def verify_image(file_path: Path) -> bool:
    try:
        with Image.open(file_path) as image:
            image.verify()
        return True
    except (OSError, UnidentifiedImageError):
        return False


def plot_distribution(distribution: Counter[str], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    labels = list(distribution.keys())
    counts = [distribution[label] for label in labels]

    figure_width = max(12, len(labels) * 0.4)
    plt.figure(figsize=(figure_width, 6))
    plt.bar(labels, counts)
    plt.xticks(rotation=75, ha="right")
    plt.ylabel("Image Count")
    plt.title("Malware Family Distribution")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def build_dataset_manifest(
    dataset_dir: Path,
    image_files: list[Path],
    class_distribution: Counter[str],
    corrupt_files: list[Path],
    dataset_source: str,
    kaggle_slug: str,
    download_timestamp: str | None,
    skip_file_hashes: bool,
) -> dict:
    file_entries = []
    aggregate_parts = []

    for file_path in image_files:
        relative_path = str(file_path.relative_to(dataset_dir))
        file_size = file_path.stat().st_size
        file_hash = None if skip_file_hashes else sha256_file(file_path)
        file_entries.append(
            {
                "relative_path": relative_path,
                "label": get_label_for_path(dataset_dir, file_path),
                "size_bytes": file_size,
                "sha256": file_hash,
            }
        )
        aggregate_parts.append(f"{relative_path}|{file_size}|{file_hash or 'not_hashed'}")

    corrupt_relative_paths = [
        str(file_path.relative_to(dataset_dir)) for file_path in corrupt_files
    ]

    return {
        "manifest_type": "dataset",
        "created_at_utc": utc_iso_timestamp(),
        "dataset_source": dataset_source,
        "kaggle_slug": kaggle_slug,
        "download_timestamp": download_timestamp,
        "extracted_dataset_root": str(dataset_dir.resolve()),
        "sample_count": len(image_files),
        "class_count": len(class_distribution),
        "class_distribution": dict(sorted(class_distribution.items())),
        "corrupt_file_count": len(corrupt_files),
        "corrupt_files": corrupt_relative_paths,
        "hashing": {
            "algorithm": "sha256",
            "per_file_hashes": not skip_file_hashes,
            "dataset_hash": sha256_text("\n".join(aggregate_parts)),
        },
        "files": file_entries,
    }


def main() -> None:
    args = parse_args()
    dataset_dir = args.dataset_dir

    if not dataset_dir.exists():
        raise FileNotFoundError(f"Dataset directory not found: {dataset_dir}")

    image_files = find_image_files(dataset_dir)
    if not image_files:
        raise RuntimeError(f"No image files found in {dataset_dir}")

    class_distribution: Counter[str] = Counter()
    corrupt_files: list[Path] = []

    for file_path in tqdm(image_files, desc="Verifying images"):
        label = get_label_for_path(dataset_dir, file_path)
        class_distribution[label] += 1

        if not verify_image(file_path):
            corrupt_files.append(file_path)

    plot_distribution(class_distribution, args.output_path)
    manifest = build_dataset_manifest(
        dataset_dir=dataset_dir,
        image_files=image_files,
        class_distribution=class_distribution,
        corrupt_files=corrupt_files,
        dataset_source=args.dataset_source,
        kaggle_slug=args.kaggle_slug,
        download_timestamp=args.download_timestamp,
        skip_file_hashes=args.skip_file_hashes,
    )
    write_json(manifest, args.manifest_path)

    print(f"Dataset root: {dataset_dir}")
    print(f"Number of malware families: {len(class_distribution)}")
    print(f"Total images: {sum(class_distribution.values())}")
    print(f"Corrupt images: {len(corrupt_files)}")
    print("Class distribution:")
    for label, count in sorted(class_distribution.items()):
        print(f"  {label}: {count}")

    if corrupt_files:
        print("Corrupt file list:")
        for file_path in corrupt_files:
            print(f"  {file_path}")

    print(f"Saved class distribution plot to: {args.output_path}")
    print(f"Saved dataset manifest to: {args.manifest_path}")


if __name__ == "__main__":
    main()
