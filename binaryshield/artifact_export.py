from __future__ import annotations

import csv
import json
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


ALLOWED_ARTIFACT_SUFFIXES = {
    ".csv",
    ".json",
    ".md",
    ".txt",
}

BLOCKED_ARTIFACT_SUFFIXES = {
    ".7z",
    ".bin",
    ".ckpt",
    ".dll",
    ".dylib",
    ".exe",
    ".joblib",
    ".npz",
    ".pkl",
    ".pt",
    ".pth",
    ".rar",
    ".so",
    ".sys",
    ".tar",
    ".tgz",
    ".zip",
}

SECRET_PATTERNS = [
    re.compile(r"4/0A[a-zA-Z0-9_\-]{20,}"),
    re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[a-z0-9._\-]+"),
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?[a-z0-9_\-./]{16,}"),
]

BLOCKED_NAME_PATTERNS = [
    re.compile(r"(?i)(^|[_-])detector\.json$"),
    re.compile(r"(?i)^feature_record_.*\.json$"),
    re.compile(r"(?i)^model(_|-)?.*\.json$"),
]


@dataclass(frozen=True)
class ArtifactExportRecord:
    relative_path: str
    source_path: str
    destination_path: str | None
    size_bytes: int
    status: str
    reason: str


def export_sanitized_artifacts(
    source_dir: str | Path,
    destination_dir: str | Path,
    *,
    max_file_mb: float = 20.0,
    dry_run: bool = False,
) -> dict[str, object]:
    source = Path(source_dir).resolve()
    destination = Path(destination_dir).resolve()
    if not source.exists() or not source.is_dir():
        raise FileNotFoundError(f"source artifact directory does not exist: {source}")
    if source == destination or _is_relative_to(destination, source):
        raise ValueError("destination must not be inside source artifact directory")
    records: list[ArtifactExportRecord] = []
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        relative = path.relative_to(source)
        record = _classify(path, relative, destination / relative, max_file_mb=max_file_mb)
        records.append(record)
        if record.status == "COPIED" and not dry_run:
            assert record.destination_path is not None
            output = Path(record.destination_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, output)
    copied = [record for record in records if record.status == "COPIED"]
    blocked = [record for record in records if record.status == "BLOCKED"]
    summary = {
        "source_dir": str(source),
        "destination_dir": str(destination),
        "dry_run": dry_run,
        "allowed_suffixes": sorted(ALLOWED_ARTIFACT_SUFFIXES),
        "blocked_suffixes": sorted(BLOCKED_ARTIFACT_SUFFIXES),
        "max_file_mb": max_file_mb,
        "total_files": len(records),
        "copied_files": len(copied),
        "blocked_files": len(blocked),
        "status": "PASS" if not blocked else "REVIEW_REQUIRED",
        "records": [asdict(record) for record in records],
        "claim_boundary": (
            "This export copies sanitized report artifacts only. It does not copy raw malware, "
            "transformed malware, datasets, checkpoints, or private credentials."
        ),
    }
    if not dry_run:
        destination.mkdir(parents=True, exist_ok=True)
        write_export_summary(summary, destination)
    return summary


def write_export_summary(summary: dict[str, object], destination_dir: str | Path) -> None:
    destination = Path(destination_dir)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "sanitized_artifact_export_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (destination / "sanitized_artifact_export_summary.md").write_text(to_markdown(summary), encoding="utf-8")
    rows = list(summary.get("records", []))
    with (destination / "sanitized_artifact_export_rows.csv").open("w", encoding="utf-8", newline="") as handle:
        fieldnames = sorted({key for row in rows for key in row}) if rows else ["relative_path", "status", "reason"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(summary: dict[str, object]) -> str:
    return (
        "# BinaryShield Sanitized Artifact Export\n\n"
        f"**Source:** `{summary.get('source_dir')}`\n\n"
        f"**Destination:** `{summary.get('destination_dir')}`\n\n"
        f"**Status:** `{summary.get('status')}`\n\n"
        f"**Copied files:** {summary.get('copied_files')}\n\n"
        f"**Blocked files:** {summary.get('blocked_files')}\n\n"
        "## Claim Boundary\n\n"
        f"{summary.get('claim_boundary')}\n"
    )


def _classify(path: Path, relative: Path, destination: Path, *, max_file_mb: float) -> ArtifactExportRecord:
    suffix = path.suffix.lower()
    size = path.stat().st_size
    if suffix in BLOCKED_ARTIFACT_SUFFIXES:
        return _record(path, relative, None, size, "BLOCKED", f"blocked suffix: {suffix}")
    if _is_blocked_model_name(path.name):
        return _record(path, relative, None, size, "BLOCKED", "model artifact filename")
    if suffix not in ALLOWED_ARTIFACT_SUFFIXES:
        return _record(path, relative, None, size, "BLOCKED", f"suffix not allowlisted: {suffix or '<none>'}")
    if size > max_file_mb * 1024 * 1024:
        return _record(path, relative, None, size, "BLOCKED", f"file exceeds {max_file_mb:.1f} MB")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return _record(path, relative, None, size, "BLOCKED", "not valid UTF-8 text")
    if _contains_secret(text):
        return _record(path, relative, None, size, "BLOCKED", "possible credential/token content")
    return _record(path, relative, destination, size, "COPIED", "")


def _contains_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def _is_blocked_model_name(name: str) -> bool:
    return any(pattern.search(name) for pattern in BLOCKED_NAME_PATTERNS)


def _record(
    source: Path,
    relative: Path,
    destination: Path | None,
    size: int,
    status: str,
    reason: str,
) -> ArtifactExportRecord:
    return ArtifactExportRecord(
        relative_path=relative.as_posix(),
        source_path=str(source),
        destination_path=str(destination) if destination else None,
        size_bytes=size,
        status=status,
        reason=reason,
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False
