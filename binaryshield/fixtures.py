from __future__ import annotations

import struct
from pathlib import Path


def write_minimal_pe_fixture(path: str | Path) -> Path:
    """Write a synthetic benign PE-like fixture for parser/transform tests.

    The fixture is not malware and is not intended to execute useful behavior. It
    exists only so BinaryShield can demonstrate PE parsing and structural
    validation without storing raw malware in the repository.
    """

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    data = bytearray(0x600)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"

    coff = 0x84
    struct.pack_into("<H", data, coff, 0x14C)
    struct.pack_into("<H", data, coff + 2, 2)
    struct.pack_into("<I", data, coff + 4, 0x5E2A5A00)
    struct.pack_into("<H", data, coff + 16, 0xE0)
    struct.pack_into("<H", data, coff + 18, 0x010F)

    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<I", data, opt + 32, 0x1000)
    struct.pack_into("<I", data, opt + 36, 0x200)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<H", data, opt + 70, 0x8140)

    sec = opt + 0xE0
    data[sec : sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sec + 8, 0x180)
    struct.pack_into("<I", data, sec + 12, 0x1000)
    struct.pack_into("<I", data, sec + 16, 0x200)
    struct.pack_into("<I", data, sec + 20, 0x200)
    struct.pack_into("<I", data, sec + 36, 0x60000020)

    sec2 = sec + 40
    data[sec2 : sec2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", data, sec2 + 8, 0x100)
    struct.pack_into("<I", data, sec2 + 12, 0x2000)
    struct.pack_into("<I", data, sec2 + 16, 0x200)
    struct.pack_into("<I", data, sec2 + 20, 0x400)
    struct.pack_into("<I", data, sec2 + 36, 0x40000040)

    for index in range(0x200, 0x380):
        data[index] = index % 251
    for index in range(0x400, 0x500):
        data[index] = (index * 7) % 251
    output.write_bytes(data)
    return output
