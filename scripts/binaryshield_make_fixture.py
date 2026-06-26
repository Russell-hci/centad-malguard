from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.fixtures import write_minimal_pe_fixture


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a synthetic benign PE fixture for BinaryShield demos.")
    parser.add_argument("--output", type=Path, default=Path("binaryshield_outputs/fixtures/minimal_pe.exe"))
    args = parser.parse_args()
    output = write_minimal_pe_fixture(args.output)
    print(output)


if __name__ == "__main__":
    main()
