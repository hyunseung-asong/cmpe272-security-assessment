#!/usr/bin/env python
"""Create a large test file without holding it in memory."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


DEFAULT_SIZE = 4 * 1024 * 1024 * 1024
DEFAULT_CHUNK = 4 * 1024 * 1024


def parse_size(value: str) -> int:
    units = {
        "k": 1024,
        "kb": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
    }
    lower = value.strip().lower()
    for suffix, multiplier in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
        if lower.endswith(suffix):
            return int(lower[: -len(suffix)]) * multiplier
    return int(lower)


def write_test_file(path: Path, size: int, random_bytes: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining = size
    zero_chunk = b"\0" * DEFAULT_CHUNK
    with path.open("wb") as handle:
        while remaining:
            count = min(DEFAULT_CHUNK, remaining)
            chunk = os.urandom(count) if random_bytes else zero_chunk[:count]
            handle.write(chunk)
            remaining -= count
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("test_4gb.bin"))
    parser.add_argument("--size", default="4GB", help="bytes or units such as 1MB, 4GB")
    parser.add_argument("--random", action="store_true", help="use random bytes instead of zeros")
    args = parser.parse_args()

    size = parse_size(args.size)
    write_test_file(args.output, size, args.random)
    print(f"wrote {args.output} ({size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
