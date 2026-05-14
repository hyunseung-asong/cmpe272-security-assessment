"""Length-prefixed framing and streaming helpers."""

from __future__ import annotations

import json
import os
import socket
import struct
import time
from pathlib import Path

from shared.constants import MAX_FRAME_SIZE


class ProtocolError(RuntimeError):
    """Raised when the peer sends malformed or incomplete protocol data."""


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def send_frame(conn: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError(f"frame too large: {len(payload)} bytes")
    conn.sendall(struct.pack("!I", len(payload)))
    conn.sendall(payload)


def recv_exact(conn: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = conn.recv(min(remaining, 1024 * 1024))
        if not chunk:
            raise ProtocolError("connection closed before expected bytes arrived")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(conn: socket.socket) -> bytes:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    if length > MAX_FRAME_SIZE:
        raise ProtocolError(f"frame too large: {length} bytes")
    return recv_exact(conn, length)


def send_json(conn: socket.socket, value: object) -> None:
    send_frame(conn, canonical_json(value))


def recv_json(conn: socket.socket) -> object:
    try:
        return json.loads(recv_frame(conn).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("peer sent invalid JSON") from exc


def safe_output_name(name: str) -> str:
    cleaned = Path(name).name
    if cleaned in ("", ".", ".."):
        raise ProtocolError("invalid file name in metadata")
    return cleaned


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def temp_path_for(final_path: Path) -> Path:
    return final_path.with_name(final_path.name + ".part")


def failed_path_for(final_path: Path) -> Path:
    return final_path.with_name(final_path.name + ".failed")


def prepare_temp_file(final_path: Path) -> Path:
    ensure_parent(final_path)
    part_path = temp_path_for(final_path)
    for stale in (part_path, failed_path_for(final_path)):
        if stale.exists():
            stale.unlink()
    return part_path


def finalize_verified_file(part_path: Path, final_path: Path) -> None:
    os.replace(part_path, final_path)


def quarantine_partial(part_path: Path, final_path: Path) -> Path | None:
    if not part_path.exists():
        return None
    failed_path = failed_path_for(final_path)
    if failed_path.exists():
        failed_path.unlink()
    os.replace(part_path, failed_path)
    return failed_path


class Throughput:
    def __init__(self) -> None:
        self.start = time.perf_counter()

    def mbps(self, byte_count: int) -> float:
        elapsed = max(time.perf_counter() - self.start, 1e-9)
        return byte_count / (1024 * 1024) / elapsed
