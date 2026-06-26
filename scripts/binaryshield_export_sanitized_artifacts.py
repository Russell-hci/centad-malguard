from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.artifact_export import export_sanitized_artifacts  # noqa: E402
from binaryshield.safety import is_relative_to  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Copy only Git-safe BinaryShield artifacts from an external run.")
    parser.add_argument("--source-dir", type=Path, required=True, help="External raw-run report/result directory.")
    parser.add_argument(
        "--destination-dir",
        type=Path,
        required=True,
        help="Repository report destination, for example reports/binaryshield/bodmas_raw_import.",
    )
    parser.add_argument("--max-file-mb", type=float, default=20.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--allow-source-inside-repo",
        action="store_true",
        help="Use only for synthetic fixture tests. Real raw runs should import from external storage.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source = args.source_dir.resolve()
    destination = args.destination_dir.resolve()
    if is_relative_to(source, PROJECT_ROOT) and not args.allow_source_inside_repo:
        raise ValueError(
            "source-dir is inside the repository. Real raw-PE imports must come from external storage; "
            "use --allow-source-inside-repo only for synthetic fixture tests."
        )
    if not is_relative_to(destination, PROJECT_ROOT):
        raise ValueError("destination-dir should be inside the repository report tree for sanitized artifacts.")
    summary = export_sanitized_artifacts(
        source,
        destination,
        max_file_mb=args.max_file_mb,
        dry_run=args.dry_run,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
