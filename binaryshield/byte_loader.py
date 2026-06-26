from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ByteLoadResult:
    path: str
    original_size: int
    max_bytes: int | None
    truncated: bool
    byte_values: list[int]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def load_bytes(path: str | Path, max_bytes: int | None = 2_000_000) -> ByteLoadResult:
    """Load raw bytes as integer values, optionally truncating for model input.

    The loader performs no execution and does not interpret file contents. It is safe
    for PE fixtures and malware files stored in an approved external directory.
    """

    file_path = Path(path)
    data = file_path.read_bytes()
    original_size = len(data)
    if max_bytes is not None and original_size > max_bytes:
        data = data[:max_bytes]
    return ByteLoadResult(
        path=str(file_path),
        original_size=original_size,
        max_bytes=max_bytes,
        truncated=len(data) < original_size,
        byte_values=list(data),
    )


def chunk_bytes(byte_values: list[int], chunk_size: int = 8192, pad_value: int = 256) -> list[list[int]]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    chunks: list[list[int]] = []
    for start in range(0, len(byte_values), chunk_size):
        chunk = byte_values[start : start + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + [pad_value] * (chunk_size - len(chunk))
        chunks.append(chunk)
    return chunks or [[pad_value] * chunk_size]
