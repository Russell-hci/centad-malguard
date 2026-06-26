from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import asdict, dataclass
from pathlib import Path


IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000


class PEParseError(ValueError):
    """Raised when a file cannot be parsed as a Windows PE file."""


@dataclass(frozen=True)
class PESection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int
    entropy: float

    @property
    def raw_end(self) -> int:
        return self.raw_pointer + self.raw_size

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))

    @property
    def slack_start(self) -> int:
        if self.raw_size <= 0:
            return self.raw_pointer
        used = min(max(self.virtual_size, 0), self.raw_size)
        return self.raw_pointer + used

    @property
    def slack_size(self) -> int:
        return max(0, self.raw_end - self.slack_start)

    def to_dict(self) -> dict[str, object]:
        return asdict(self) | {
            "raw_end": self.raw_end,
            "is_executable": self.is_executable,
            "slack_start": self.slack_start,
            "slack_size": self.slack_size,
        }


@dataclass(frozen=True)
class PEFeatureRecord:
    path: str
    sha256: str
    file_size: int
    machine: int
    timestamp: int
    number_of_sections: int
    characteristics: int
    optional_header_magic: int
    address_of_entry_point: int
    image_base: int
    section_alignment: int
    file_alignment: int
    subsystem: int
    dll_characteristics: int
    overlay_offset: int
    overlay_size: int
    file_entropy: float
    sections: list[PESection]

    def to_dict(self, include_sections: bool = True) -> dict[str, object]:
        data = asdict(self)
        if include_sections:
            data["sections"] = [section.to_dict() for section in self.sections]
        else:
            data.pop("sections", None)
        return data

    def to_vector(self) -> dict[str, float]:
        executable_sections = sum(1 for section in self.sections if section.is_executable)
        raw_sizes = [section.raw_size for section in self.sections]
        entropies = [section.entropy for section in self.sections]
        slack_total = sum(section.slack_size for section in self.sections)
        return {
            "file_size": float(self.file_size),
            "machine": float(self.machine),
            "timestamp": float(self.timestamp),
            "number_of_sections": float(self.number_of_sections),
            "characteristics": float(self.characteristics),
            "optional_header_magic": float(self.optional_header_magic),
            "address_of_entry_point": float(self.address_of_entry_point),
            "image_base": float(self.image_base),
            "section_alignment": float(self.section_alignment),
            "file_alignment": float(self.file_alignment),
            "subsystem": float(self.subsystem),
            "dll_characteristics": float(self.dll_characteristics),
            "overlay_size": float(self.overlay_size),
            "overlay_ratio": float(self.overlay_size / max(self.file_size, 1)),
            "file_entropy": float(self.file_entropy),
            "executable_section_count": float(executable_sections),
            "total_raw_section_size": float(sum(raw_sizes)),
            "max_section_entropy": float(max(entropies) if entropies else 0.0),
            "mean_section_entropy": float(sum(entropies) / len(entropies) if entropies else 0.0),
            "total_slack_size": float(slack_total),
            "slack_ratio": float(slack_total / max(self.file_size, 1)),
        }


def _read_u16(data: bytes, offset: int) -> int:
    _require_len(data, offset, 2)
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    _require_len(data, offset, 4)
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int) -> int:
    _require_len(data, offset, 8)
    return struct.unpack_from("<Q", data, offset)[0]


def _require_len(data: bytes, offset: int, size: int) -> None:
    if offset < 0 or offset + size > len(data):
        raise PEParseError(f"PE structure extends beyond file size at offset {offset}")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    value = 0.0
    for count in counts:
        if count:
            probability = count / total
            value -= probability * math.log2(probability)
    return float(value)


def parse_pe(path: str | Path) -> PEFeatureRecord:
    file_path = Path(path)
    data = file_path.read_bytes()
    if len(data) < 0x40:
        raise PEParseError("file too small to contain a DOS header")
    if data[:2] != b"MZ":
        raise PEParseError("missing MZ header")

    pe_offset = _read_u32(data, 0x3C)
    _require_len(data, pe_offset, 24)
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise PEParseError("missing PE signature")

    coff = pe_offset + 4
    machine = _read_u16(data, coff)
    number_of_sections = _read_u16(data, coff + 2)
    timestamp = _read_u32(data, coff + 4)
    size_of_optional_header = _read_u16(data, coff + 16)
    characteristics = _read_u16(data, coff + 18)

    optional = coff + 20
    _require_len(data, optional, size_of_optional_header)
    magic = _read_u16(data, optional)
    if magic not in {0x10B, 0x20B}:
        raise PEParseError(f"unsupported optional header magic: 0x{magic:x}")

    address_of_entry_point = _read_u32(data, optional + 16)
    image_base = _read_u64(data, optional + 24) if magic == 0x20B else _read_u32(data, optional + 28)
    section_alignment = _read_u32(data, optional + 32)
    file_alignment = _read_u32(data, optional + 36)
    subsystem = _read_u16(data, optional + 68)
    dll_characteristics = _read_u16(data, optional + 70)

    section_table = optional + size_of_optional_header
    sections: list[PESection] = []
    max_raw_end = 0
    for index in range(number_of_sections):
        offset = section_table + index * 40
        _require_len(data, offset, 40)
        raw_name = data[offset : offset + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section_{index}"
        virtual_size = _read_u32(data, offset + 8)
        virtual_address = _read_u32(data, offset + 12)
        raw_size = _read_u32(data, offset + 16)
        raw_pointer = _read_u32(data, offset + 20)
        characteristics_section = _read_u32(data, offset + 36)
        raw_end = min(raw_pointer + raw_size, len(data)) if raw_pointer <= len(data) else len(data)
        raw_data = data[raw_pointer:raw_end] if raw_size and raw_pointer < len(data) else b""
        max_raw_end = max(max_raw_end, raw_pointer + raw_size)
        sections.append(
            PESection(
                name=name,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_size=raw_size,
                raw_pointer=raw_pointer,
                characteristics=characteristics_section,
                entropy=_entropy(raw_data),
            )
        )

    overlay_offset = min(max_raw_end, len(data))
    overlay_size = max(0, len(data) - overlay_offset)
    return PEFeatureRecord(
        path=str(file_path),
        sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data),
        machine=machine,
        timestamp=timestamp,
        number_of_sections=number_of_sections,
        characteristics=characteristics,
        optional_header_magic=magic,
        address_of_entry_point=address_of_entry_point,
        image_base=image_base,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        overlay_offset=overlay_offset,
        overlay_size=overlay_size,
        file_entropy=_entropy(data),
        sections=sections,
    )
