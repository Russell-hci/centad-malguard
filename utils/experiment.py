import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

import torch


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(payload: dict, output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def sha256_file(file_path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(file_path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_git_commit_hash(repo_root: str | Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    return result.stdout.strip() or None


def get_git_status(repo_root: str | Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "status", "--short"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    return result.stdout.strip()


def is_git_dirty(repo_root: str | Path | None = None) -> bool | None:
    status = get_git_status(repo_root=repo_root)
    if status is None:
        return None
    return bool(status)


def get_cuda_metadata() -> dict:
    cuda_available = torch.cuda.is_available()
    metadata = {
        "cuda_available": cuda_available,
        "cuda_version": torch.version.cuda,
        "cudnn_version": torch.backends.cudnn.version(),
        "device_count": torch.cuda.device_count() if cuda_available else 0,
        "devices": [],
    }

    if cuda_available:
        for index in range(torch.cuda.device_count()):
            properties = torch.cuda.get_device_properties(index)
            metadata["devices"].append(
                {
                    "index": index,
                    "name": properties.name,
                    "total_memory_bytes": properties.total_memory,
                    "major": properties.major,
                    "minor": properties.minor,
                    "multi_processor_count": properties.multi_processor_count,
                }
            )

    return metadata


def get_environment_metadata(repo_root: str | Path | None = None) -> dict:
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "torch_version": torch.__version__,
        "cuda": get_cuda_metadata(),
        "git_commit_hash": get_git_commit_hash(repo_root=repo_root),
        "git_dirty": is_git_dirty(repo_root=repo_root),
        "git_status_short": get_git_status(repo_root=repo_root),
    }


class TeeLogger:
    def __init__(self, *streams: TextIO) -> None:
        self.streams = streams

    def write(self, message: str) -> None:
        for stream in self.streams:
            stream.write(message)
            stream.flush()

    def flush(self) -> None:
        for stream in self.streams:
            stream.flush()
