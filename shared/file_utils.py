"""File hashing and streaming helpers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from shared.constants import CHUNK_SIZE


def file_sha256(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stream_file_chunks(path: Path, chunk_size: int = CHUNK_SIZE):
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def file_size(path: Path) -> int:
    return path.stat().st_size


def fsync_file(handle) -> None:
    handle.flush()
    os.fsync(handle.fileno())
