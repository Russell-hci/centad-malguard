from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

BODMAS_DRIVE_FOLDER = "https://drive.google.com/drive/folders/1Uf-LebLWyi9eCv97iBal7kL1NgiGEsv_?usp=sharing"
BODMAS_REPO = "https://github.com/whyisyoung/BODMAS"
BODMAS_PROJECT_PAGE = "https://whyisyoung.github.io/BODMAS/"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare an external BODMAS workspace for BinaryShield.")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("/path/to/external/bodmas"),
        help="External non-repo workspace for BODMAS data.",
    )
    parser.add_argument("--min-free-gb", type=float, default=120.0)
    parser.add_argument("--allow-low-space", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    workspace = args.workspace.resolve()
    project_root = PROJECT_ROOT.resolve()
    if workspace == project_root or project_root in workspace.parents:
        raise ValueError(f"refusing to prepare BODMAS workspace inside repository: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)
    for child in ["binaries", "features", "metadata", "manifests", "downloads", "logs"]:
        (workspace / child).mkdir(exist_ok=True)
    usage = shutil.disk_usage(workspace)
    free_gb = usage.free / (1024**3)
    if free_gb < args.min_free_gb and not args.allow_low_space:
        raise RuntimeError(
            f"only {free_gb:.1f} GiB free at {workspace}; "
            f"minimum requested is {args.min_free_gb:.1f} GiB. "
            "Use Colab/Drive or another external volume, or pass --allow-low-space for metadata-only preparation."
        )
    metadata = {
        "workspace": str(workspace),
        "project_root": str(project_root),
        "free_gb": free_gb,
        "bodmas_project_page": BODMAS_PROJECT_PAGE,
        "bodmas_repository": BODMAS_REPO,
        "bodmas_google_drive_folder": BODMAS_DRIVE_FOLDER,
        "safety_rules": [
            "Do not copy malware binaries into the Git repository.",
            "Do not copy transformed malware binaries into the Git repository.",
            "Publish only sanitized manifests, hashes, aggregate metrics, validation summaries, and robustness cards.",
            "Do not claim full behavior preservation without sandbox evidence.",
        ],
        "next_steps": [
            "Download BODMAS into this workspace or a Colab/Drive equivalent.",
            "Build a sanitized manifest with scripts/binaryshield_build_manifest.py.",
            "Run scripts/binaryshield_validate_manifest.py before any training.",
        ],
    }
    (workspace / "binaryshield_bodmas_workspace.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
