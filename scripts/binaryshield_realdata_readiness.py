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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check readiness for real BinaryShield BODMAS/raw-PE execution.")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("/path/to/external/bodmas"),
        help="External BODMAS workspace, not inside the repository.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("reports/binaryshield/realdata_readiness"))
    parser.add_argument("--min-free-gb", type=float, default=80.0)
    parser.add_argument("--sample-raw-limit", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    workspace = args.workspace.resolve()
    if is_relative_to(workspace, PROJECT_ROOT):
        raise ValueError(f"workspace must be outside the repository: {workspace}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    metadata = _first_existing(
        [
            workspace / "metadata" / "bodmas_metadata.csv",
            workspace / "bodmas_metadata.csv",
            workspace / "downloads" / "bodmas_metadata.csv",
        ]
    )
    category = _first_existing(
        [
            workspace / "metadata" / "bodmas_malware_category.csv",
            workspace / "bodmas_malware_category.csv",
            workspace / "downloads" / "bodmas_malware_category.csv",
        ]
    )
    features = _first_existing(
        [
            workspace / "features" / "bodmas.npz",
            workspace / "bodmas.npz",
            workspace / "downloads" / "bodmas.npz",
        ]
    )
    raw_dir = workspace / "binaries"
    manifests_dir = workspace / "manifests"
    external_results_dir = workspace / "results"
    raw_files_sample = _sample_raw_files(raw_dir, args.sample_raw_limit)
    usage = shutil.disk_usage(workspace if workspace.exists() else workspace.parent)

    report = {
        "workspace": str(workspace),
        "project_root": str(PROJECT_ROOT),
        "free_gb": round(usage.free / (1024**3), 2),
        "min_free_gb": args.min_free_gb,
        "workspace_outside_repo": not is_relative_to(workspace, PROJECT_ROOT),
        "metadata": _path_status(metadata),
        "category_metadata": _path_status(category),
        "features_npz": _path_status(features),
        "raw_binaries_dir": _dir_status(raw_dir),
        "raw_file_sample_count": len(raw_files_sample),
        "raw_file_sample_limit": args.sample_raw_limit,
        "tracks": {},
        "commands": {},
        "claim_boundary": (
            "Readiness checks verify file availability and safe paths only. "
            "They do not validate malware behavior preservation or robustness."
        ),
    }
    feature_ready = metadata is not None and features is not None and usage.free / (1024**3) >= 2.0
    raw_ready = metadata is not None and raw_dir.exists() and len(raw_files_sample) > 0 and usage.free / (1024**3) >= args.min_free_gb
    report["tracks"] = {
        "public_feature_vector_track_ready": feature_ready,
        "raw_pe_track_ready": raw_ready,
        "raw_pe_blocker": "" if raw_ready else _raw_blocker(metadata, raw_dir, raw_files_sample, usage.free / (1024**3), args.min_free_gb),
    }
    report["commands"] = {
        "feature_manifest": _feature_manifest_command(metadata, features, manifests_dir) if feature_ready else None,
        "feature_extratrees": _feature_extratrees_command(features, manifests_dir, external_results_dir) if feature_ready else None,
        "raw_manifest": _raw_manifest_command(metadata, raw_dir, manifests_dir) if metadata is not None else None,
        "raw_validation": _raw_validation_command(raw_dir, manifests_dir) if raw_ready else None,
        "raw_multidetector_pipeline": _raw_pipeline_command(raw_dir, manifests_dir, external_results_dir) if raw_ready else None,
    }

    json_path = args.output_dir / "realdata_readiness.json"
    md_path = args.output_dir / "realdata_readiness.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_to_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2))


def _first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path.resolve()
    return None


def _path_status(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"exists": False, "path": None, "size_mb": None}
    return {"exists": True, "path": str(path), "size_mb": round(path.stat().st_size / (1024**2), 3)}


def _dir_status(path: Path) -> dict[str, object]:
    return {"exists": path.exists(), "path": str(path.resolve()), "inside_repo": is_relative_to(path, PROJECT_ROOT)}


def _sample_raw_files(raw_dir: Path, limit: int) -> list[Path]:
    if not raw_dir.exists():
        return []
    sample: list[Path] = []
    for path in raw_dir.rglob("*"):
        if path.is_file():
            sample.append(path)
            if len(sample) >= limit:
                break
    return sample


def _raw_blocker(metadata: Path | None, raw_dir: Path, raw_files_sample: list[Path], free_gb: float, min_free_gb: float) -> str:
    blockers = []
    if metadata is None:
        blockers.append("missing BODMAS metadata CSV")
    if not raw_dir.exists():
        blockers.append("missing raw binaries directory")
    elif not raw_files_sample:
        blockers.append("raw binaries directory is empty")
    if free_gb < min_free_gb:
        blockers.append(f"insufficient free space: {free_gb:.1f} GiB < {min_free_gb:.1f} GiB")
    return "; ".join(blockers) if blockers else "unknown"


def _feature_manifest_command(metadata: Path | None, features: Path | None, manifests_dir: Path) -> str:
    return _shell(
        [
            "python3 scripts/binaryshield_build_bodmas_manifest.py",
            f"--metadata {metadata}",
            f"--features-npz {features}",
            f"--feature-output {manifests_dir / 'bodmas_feature_manifest.csv'}",
            "--summary-output reports/binaryshield/bodmas_feature_manifest_summary.json",
        ]
    )


def _feature_extratrees_command(features: Path | None, manifests_dir: Path, results_dir: Path) -> str:
    return _shell(
        [
            "python3 scripts/binaryshield_train_feature_records.py",
            f"--manifest {manifests_dir / 'bodmas_feature_manifest.csv'}",
            f"--features-npz {features}",
            f"--output-dir {results_dir / 'bodmas_feature_extra_trees'}",
            "--target label",
            "--model-type extra_trees",
            "--n-estimators 250",
        ]
    )


def _raw_manifest_command(metadata: Path | None, raw_dir: Path, manifests_dir: Path) -> str:
    return _shell(
        [
            "python3 scripts/binaryshield_build_bodmas_manifest.py",
            f"--metadata {metadata}",
            f"--raw-binaries-dir {raw_dir}",
            f"--raw-output {manifests_dir / 'bodmas_raw_manifest.csv'}",
            "--summary-output reports/binaryshield/bodmas_raw_manifest_summary.json",
            f"--relative-to {raw_dir}",
            "--require-pe-parse",
        ]
    )


def _raw_validation_command(raw_dir: Path, manifests_dir: Path) -> str:
    return _shell(
        [
            "python3 scripts/binaryshield_validate_manifest.py",
            f"--manifest {manifests_dir / 'bodmas_raw_manifest.csv'}",
            f"--root-dir {raw_dir}",
            "--output-dir reports/binaryshield/bodmas_raw_validation",
        ]
    )


def _raw_pipeline_command(raw_dir: Path, manifests_dir: Path, results_dir: Path) -> str:
    return _shell(
        [
            "python3 scripts/binaryshield_run_pipeline.py",
            f"--manifest {manifests_dir / 'bodmas_raw_manifest.csv'}",
            f"--root-dir {raw_dir}",
            f"--output-dir {results_dir / 'bodmas_raw_multidetector'}",
            "--report-dir reports/binaryshield/bodmas_raw_multidetector",
            "--target family",
            "--model-types centroid byte_histogram_centroid hybrid_centroid",
            "--candidate-model-type hybrid_centroid",
            "--strongest-n 20",
        ]
    )


def _shell(parts: list[str]) -> str:
    return " \\\n  ".join(parts)


def _to_markdown(report: dict[str, object]) -> str:
    tracks = report["tracks"]  # type: ignore[assignment]
    commands = report["commands"]  # type: ignore[assignment]
    return (
        "# BinaryShield Real-Data Readiness\n\n"
        f"**Workspace:** `{report['workspace']}`\n\n"
        f"**Free space:** {report['free_gb']} GiB\n\n"
        "## Track Status\n\n"
        f"- Public BODMAS feature-vector track ready: `{tracks['public_feature_vector_track_ready']}`\n"
        f"- Raw PE transformation track ready: `{tracks['raw_pe_track_ready']}`\n"
        f"- Raw PE blocker: {tracks['raw_pe_blocker'] or 'none'}\n\n"
        "## File Status\n\n"
        f"- Metadata CSV: `{report['metadata']['path']}`\n"  # type: ignore[index]
        f"- Feature NPZ: `{report['features_npz']['path']}`\n"  # type: ignore[index]
        f"- Raw binaries directory: `{report['raw_binaries_dir']['path']}`\n"  # type: ignore[index]
        f"- Raw file sample count: `{report['raw_file_sample_count']}`\n\n"
        "## Next Commands\n\n"
        f"### Feature Manifest\n\n```bash\n{commands['feature_manifest'] or '# not ready'}\n```\n\n"
        f"### Feature ExtraTrees Baseline\n\n```bash\n{commands['feature_extratrees'] or '# not ready'}\n```\n\n"
        f"### Raw Manifest\n\n```bash\n{commands['raw_manifest'] or '# not ready'}\n```\n\n"
        f"### Raw Validation\n\n```bash\n{commands['raw_validation'] or '# not ready'}\n```\n\n"
        f"### Raw Multi-Detector Pipeline\n\n```bash\n{commands['raw_multidetector_pipeline'] or '# not ready'}\n```\n\n"
        "## Claim Boundary\n\n"
        f"{report['claim_boundary']}\n"
    )


if __name__ == "__main__":
    main()
