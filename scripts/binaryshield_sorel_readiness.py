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
    count_files,
    first_existing,
    sample_files,
    shell_join,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check readiness for a BinaryShield SOREL-20M subset run.")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("/path/to/external/sorel20m_subset"),
        help="External SOREL subset workspace, not inside the repository.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("reports/binaryshield/sorel_readiness"))
    parser.add_argument("--min-free-gb", type=float, default=80.0)
    parser.add_argument("--sample-raw-limit", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    workspace = args.workspace.resolve()
    if is_relative_to(workspace, PROJECT_ROOT):
        raise ValueError(f"workspace must be outside the repository: {workspace}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    binary_dir = workspace / "binaries"
    compressed_dir = workspace / "compressed_binaries"
    manifests_dir = workspace / "manifests"
    results_dir = workspace / "results"
    reports_dir = workspace / "reports"
    raw_files_sample = sample_files(binary_dir, args.sample_raw_limit)
    compressed_files_sample = sample_files(compressed_dir, args.sample_raw_limit)
    usage = shutil.disk_usage(workspace if workspace.exists() else workspace.parent)
    free_gb = usage.free / (1024**3)
    aws_cli = shutil.which("aws")
    metadata_db = first_existing(
        [
            workspace / "metadata" / "meta.db",
            workspace / "metadata" / "sqlite.db",
            workspace / "metadata" / "sorel20m.db",
            workspace / "processed-data" / "meta.db",
        ]
    )
    feature_store = first_existing(
        [
            workspace / "features" / "ember_features",
            workspace / "features" / "data.mdb",
            workspace / "lightGBM-features" / "data.mdb",
        ]
    )
    raw_ready = len(raw_files_sample) > 0 and free_gb >= args.min_free_gb
    feature_ready = metadata_db is not None or feature_store is not None
    report = {
        "workspace": str(workspace),
        "project_root": str(PROJECT_ROOT),
        "workspace_outside_repo": not is_relative_to(workspace, PROJECT_ROOT),
        "free_gb": round(free_gb, 2),
        "min_free_gb": args.min_free_gb,
        "aws_cli": {"available": aws_cli is not None, "path": aws_cli},
        "sorel_sources": {
            "aws_registry": SOREL_AWS_REGISTRY,
            "repository": SOREL_REPOSITORY,
            "binary_prefix": SOREL_BINARY_PREFIX,
            "processed_prefix": SOREL_PROCESSED_PREFIX,
            "lightgbm_prefix": SOREL_LIGHTGBM_PREFIX,
        },
        "metadata_db": _path_status(metadata_db),
        "feature_store": _path_status(feature_store),
        "raw_binaries_dir": _dir_status(binary_dir),
        "compressed_binaries_dir": _dir_status(compressed_dir),
        "raw_file_sample_count": len(raw_files_sample),
        "compressed_file_sample_count": len(compressed_files_sample),
        "tracks": {
            "raw_disarmed_pe_track_ready": raw_ready,
            "feature_metadata_track_ready": feature_ready,
            "raw_disarmed_pe_blocker": "" if raw_ready else _raw_blocker(binary_dir, raw_files_sample, free_gb, args.min_free_gb),
        },
        "commands": {
            "prepare_workspace": _prepare_command(workspace),
            "list_sorel_root": _aws_list_command(SOREL_BINARY_PREFIX),
            "list_sorel_processed": _aws_list_command(SOREL_PROCESSED_PREFIX),
            "raw_manifest": _raw_manifest_command(binary_dir, manifests_dir) if raw_files_sample else None,
            "raw_validation": _raw_validation_command(binary_dir, manifests_dir) if raw_ready else None,
            "raw_multidetector_pipeline": _raw_pipeline_command(binary_dir, manifests_dir, results_dir, reports_dir) if raw_ready else None,
            "sanitized_export": _sanitized_export_command(results_dir) if raw_ready else None,
        },
        "claim_boundary": (
            "SOREL readiness checks verify external storage, file availability, and command readiness only. "
            "SOREL disarmed malware supports Level 1/2 structural transformation validation, not full "
            "behavior preservation without sandbox evidence. Raw malware/benign classification claims require "
            "a raw benign PE source in addition to SOREL malware binaries."
        ),
    }
    (args.output_dir / "sorel_readiness.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (args.output_dir / "sorel_readiness.md").write_text(_to_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2))


def _path_status(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"exists": False, "path": None, "size_mb": None}
    size_mb = None if path.is_dir() else round(path.stat().st_size / (1024**2), 3)
    return {"exists": True, "path": str(path), "size_mb": size_mb}


def _dir_status(path: Path) -> dict[str, object]:
    return {
        "exists": path.exists(),
        "path": str(path.resolve()),
        "inside_repo": is_relative_to(path, PROJECT_ROOT),
        "file_count": count_files(path.rglob("*")) if path.exists() else 0,
    }


def _raw_blocker(raw_dir: Path, raw_files_sample: list[Path], free_gb: float, min_free_gb: float) -> str:
    blockers = []
    if not raw_dir.exists():
        blockers.append("missing raw/disarmed PE binaries directory")
    elif not raw_files_sample:
        blockers.append("raw/disarmed PE binaries directory is empty")
    if free_gb < min_free_gb:
        blockers.append(f"insufficient free space: {free_gb:.1f} GiB < {min_free_gb:.1f} GiB")
    return "; ".join(blockers) if blockers else "unknown"


def _prepare_command(workspace: Path) -> str:
    return shell_join(
        [
            "python3 scripts/binaryshield_prepare_sorel_workspace.py",
            f"--workspace {workspace}",
        ]
    )


def _aws_list_command(prefix: str) -> str:
    return f"aws s3 ls --no-sign-request {prefix}"


def _raw_manifest_command(raw_dir: Path, manifests_dir: Path) -> str:
    return shell_join(
        [
            "python3 scripts/binaryshield_build_manifest.py",
            f"--input-dir {raw_dir}",
            f"--output {manifests_dir / 'sorel_raw_malware_manifest.csv'}",
            "--label malware",
            f"--relative-to {raw_dir}",
            "--require-pe-parse",
        ]
    )


def _raw_validation_command(raw_dir: Path, manifests_dir: Path) -> str:
    return shell_join(
        [
            "python3 scripts/binaryshield_validate_manifest.py",
            f"--manifest {manifests_dir / 'sorel_raw_malware_manifest.csv'}",
            f"--root-dir {raw_dir}",
            "--output-dir reports/binaryshield/sorel_raw_validation",
        ]
    )


def _raw_pipeline_command(raw_dir: Path, manifests_dir: Path, results_dir: Path, reports_dir: Path) -> str:
    return shell_join(
        [
            "python3 scripts/binaryshield_run_pipeline.py",
            f"--manifest {manifests_dir / 'sorel_raw_malware_manifest.csv'}",
            f"--root-dir {raw_dir}",
            f"--output-dir {results_dir / 'sorel_raw_multidetector'}",
            f"--report-dir {reports_dir / 'sorel_raw_multidetector'}",
            "--target label",
            "--model-types centroid byte_histogram_centroid hybrid_centroid",
            "--candidate-model-type hybrid_centroid",
            "--strongest-n 20",
        ]
    )


def _sanitized_export_command(results_dir: Path) -> str:
    return shell_join(
        [
            "python3 scripts/binaryshield_export_sanitized_artifacts.py",
            f"--source-dir {results_dir / 'sorel_raw_multidetector'}",
            "--destination-dir reports/binaryshield/sorel_raw_multidetector_import",
        ]
    )


def _to_markdown(report: dict[str, object]) -> str:
    tracks = report["tracks"]  # type: ignore[assignment]
    commands = report["commands"]  # type: ignore[assignment]
    sources = report["sorel_sources"]  # type: ignore[assignment]
    return (
        "# BinaryShield SOREL-20M Readiness\n\n"
        f"**Workspace:** `{report['workspace']}`\n\n"
        f"**Free space:** {report['free_gb']} GiB\n\n"
        "## Source References\n\n"
        f"- AWS registry: {sources['aws_registry']}\n"
        f"- Repository: {sources['repository']}\n"
        f"- Binary prefix: `{sources['binary_prefix']}`\n"
        f"- Processed-data prefix: `{sources['processed_prefix']}`\n\n"
        "## Track Status\n\n"
        f"- Raw disarmed-PE track ready: `{tracks['raw_disarmed_pe_track_ready']}`\n"
        f"- Feature/metadata track ready: `{tracks['feature_metadata_track_ready']}`\n"
        f"- Raw disarmed-PE blocker: {tracks['raw_disarmed_pe_blocker'] or 'none'}\n\n"
        "## File Status\n\n"
        f"- Raw binaries directory: `{report['raw_binaries_dir']['path']}`\n"  # type: ignore[index]
        f"- Raw file sample count: `{report['raw_file_sample_count']}`\n"
        f"- Compressed file sample count: `{report['compressed_file_sample_count']}`\n"
        f"- Metadata DB: `{report['metadata_db']['path']}`\n"  # type: ignore[index]
        f"- Feature store: `{report['feature_store']['path']}`\n\n"  # type: ignore[index]
        "## Commands\n\n"
        f"### Prepare Workspace\n\n```bash\n{commands['prepare_workspace']}\n```\n\n"
        f"### List SOREL Binary Prefix\n\n```bash\n{commands['list_sorel_root']}\n```\n\n"
        f"### List SOREL Processed Prefix\n\n```bash\n{commands['list_sorel_processed']}\n```\n\n"
        f"### Raw Manifest\n\n```bash\n{commands['raw_manifest'] or '# not ready'}\n```\n\n"
        f"### Raw Validation\n\n```bash\n{commands['raw_validation'] or '# not ready'}\n```\n\n"
        f"### Raw Multi-Detector Pipeline\n\n```bash\n{commands['raw_multidetector_pipeline'] or '# not ready'}\n```\n\n"
        f"### Sanitized Export\n\n```bash\n{commands['sanitized_export'] or '# not ready'}\n```\n\n"
        "## Claim Boundary\n\n"
        f"{report['claim_boundary']}\n"
    )


if __name__ == "__main__":
    main()
