import argparse
import shutil
import subprocess
from pathlib import Path


DEFAULT_DATASET = "ikrambenabd/malimg-original"
DEFAULT_OUTPUT_DIR = Path("datasets/raw/malimg")
DEFAULT_ARCHIVE_NAME = "malimg-original.zip"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download the MalImg dataset using the Kaggle CLI.",
    )
    parser.add_argument(
        "--dataset",
        default=DEFAULT_DATASET,
        help="Kaggle dataset identifier.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where the extracted dataset will be stored.",
    )
    parser.add_argument(
        "--archive-name",
        default=DEFAULT_ARCHIVE_NAME,
        help="Expected name of the downloaded archive.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Redownload and overwrite any existing extracted dataset.",
    )
    return parser.parse_args()


def ensure_kaggle_cli() -> None:
    if shutil.which("kaggle") is None:
        raise RuntimeError(
            "Kaggle CLI was not found. Install it with `pip install kaggle` and "
            "configure ~/.kaggle/kaggle.json before running this script."
        )


def run_command(command: list[str]) -> None:
    subprocess.run(command, check=True)


def download_dataset(dataset: str, archive_path: Path, force: bool) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    if archive_path.exists() and not force:
        return

    if archive_path.exists():
        archive_path.unlink()

    command = [
        "kaggle",
        "datasets",
        "download",
        "-d",
        dataset,
        "-p",
        str(archive_path.parent),
    ]
    run_command(command)


def extract_archive(archive_path: Path, output_dir: Path, force: bool) -> None:
    if output_dir.exists() and any(output_dir.iterdir()) and not force:
        print(f"Dataset already extracted at {output_dir}")
        return

    if output_dir.exists() and force:
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    run_command(["unzip", "-o", str(archive_path), "-d", str(output_dir)])


def main() -> None:
    args = parse_args()
    ensure_kaggle_cli()

    archive_path = args.output_dir.parent / args.archive_name
    download_dataset(args.dataset, archive_path, args.force)
    extract_archive(archive_path, args.output_dir, args.force)

    print(f"Dataset archive: {archive_path}")
    print(f"Dataset extracted to: {args.output_dir}")


if __name__ == "__main__":
    main()
