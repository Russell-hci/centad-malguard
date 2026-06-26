from __future__ import annotations

import zlib
from pathlib import Path
from typing import Iterable


SOREL_S3_ROOT = "s3://sorel-20m/09-DEC-2020"
SOREL_BINARY_PREFIX = f"{SOREL_S3_ROOT}/binaries/"
SOREL_PROCESSED_PREFIX = f"{SOREL_S3_ROOT}/processed-data/"
SOREL_LIGHTGBM_PREFIX = f"{SOREL_S3_ROOT}/lightGBM-features/"
SOREL_AWS_REGISTRY = "https://registry.opendata.aws/sorel-20m/"
SOREL_REPOSITORY = "https://github.com/sophos/SOREL-20M"


def count_files(paths: Iterable[Path]) -> int:
    return sum(1 for path in paths if path.is_file())


def sample_files(root: Path, limit: int) -> list[Path]:
    if not root.exists():
        return []
    sample: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file():
            sample.append(path)
            if len(sample) >= limit:
                break
    return sample


def first_existing(paths: Iterable[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path.resolve()
    return None


def shell_join(parts: list[str]) -> str:
    return " \\\n  ".join(parts)


def maybe_decompress_sorel_binary(data: bytes) -> tuple[bytes, bool]:
    """Return decompressed SOREL binary bytes when the object is zlib-compressed."""

    if data.startswith(b"MZ"):
        return data, False
    if data.startswith((b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")):
        return zlib.decompress(data), True
    return data, False
