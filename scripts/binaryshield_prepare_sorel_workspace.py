from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.safety import is_relative_to  # noqa: E402
from binaryshield.sorel import (  # noqa: E402
    SOREL_AWS_REGISTRY,
    SOREL_BINARY_PREFIX,
    SOREL_LIGHTGBM_PREFIX,
    SOREL_PROCESSED_PREFIX,
    SOREL_REPOSITORY,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare an external SOREL-20M subset workspace for BinaryShield.")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("/path/to/external/sorel20m_subset"),
        help="External non-repo workspace for a controlled SOREL-20M subset.",
    )
    parser.add_argument("--min-free-gb", type=float, default=120.0)
    parser.add_argument("--allow-low-space", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    workspace = args.workspace.resolve()
    if is_relative_to(workspace, PROJECT_ROOT):
        raise ValueError(f"refusing to prepare SOREL workspace inside repository: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)
    for child in [
        "binaries",
        "compressed_binaries",
        "metadata",
        "features",
        "manifests",
        "results",
        "reports",
        "logs",
        "aws_lists",
    ]:
        (workspace / child).mkdir(exist_ok=True)

    usage = shutil.disk_usage(workspace)
    free_gb = usage.free / (1024**3)
    if free_gb < args.min_free_gb and not args.allow_low_space:
        raise RuntimeError(
            f"only {free_gb:.1f} GiB free at {workspace}; minimum requested is {args.min_free_gb:.1f} GiB. "
            "Use Colab/Drive or another external volume, or pass --allow-low-space for metadata-only setup."
        )

    metadata = {
        "workspace": str(workspace),
        "project_root": str(PROJECT_ROOT),
        "free_gb": round(free_gb, 2),
        "sorel_aws_registry": SOREL_AWS_REGISTRY,
        "sorel_repository": SOREL_REPOSITORY,
        "sorel_binary_prefix": SOREL_BINARY_PREFIX,
        "sorel_processed_prefix": SOREL_PROCESSED_PREFIX,
        "sorel_lightgbm_prefix": SOREL_LIGHTGBM_PREFIX,
        "safety_rules": [
            "Use a controlled SOREL subset; do not sync the full binary tree by default.",
            "Keep disarmed malware files and decompressed PE files outside the Git repository.",
            "Publish only sanitized manifests, aggregate metrics, validation summaries, and robustness cards.",
            "Do not claim full behavior preservation without Level 3 sandbox evidence.",
            "Do not claim malware/benign raw-binary classification unless benign raw PE samples are also available.",
        ],
        "next_steps": [
            "List SOREL S3 prefixes with aws s3 ls --no-sign-request.",
            "Download a bounded subset into compressed_binaries/ or binaries/ under this workspace.",
            "Decompress only inside the external workspace if the chosen release files are compressed.",
            "Build a sanitized manifest with scripts/binaryshield_build_manifest.py.",
            "Run scripts/binaryshield_validate_manifest.py before transformation evaluation.",
        ],
    }
    (workspace / "binaryshield_sorel_workspace.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
