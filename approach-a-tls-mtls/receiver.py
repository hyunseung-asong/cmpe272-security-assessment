#!/usr/bin/env python
"""Receiver for Approach A: streaming file transfer over mutual TLS."""

from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.constants import CHUNK_SIZE, DEFAULT_HOST, TLS_PORT
from shared.file_utils import fsync_file
from shared.io_utils import (
    ProtocolError,
    Throughput,
    finalize_verified_file,
    prepare_temp_file,
    quarantine_partial,
    recv_exact,
    recv_json,
    safe_output_name,
)


def tls_context(secrets: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=str(secrets / "tls" / "receiver.crt"),
        keyfile=str(secrets / "tls" / "receiver.key"),
    )
    context.load_verify_locations(cafile=str(secrets / "tls" / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def validate_metadata(value: object) -> dict:
    if not isinstance(value, dict):
        raise ProtocolError("metadata must be a JSON object")
    if value.get("type") != "tls-file-metadata":
        raise ProtocolError("unexpected metadata type")
    file_name = safe_output_name(str(value.get("file_name", "")))
    file_size = int(value.get("file_size", -1))
    chunk_size = int(value.get("chunk_size", CHUNK_SIZE))
    sha256 = str(value.get("sha256", ""))
    if file_size < 0 or chunk_size <= 0:
        raise ProtocolError("invalid file size or chunk size")
    if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
        raise ProtocolError("invalid SHA-256 digest")
    return {
        "file_name": file_name,
        "file_size": file_size,
        "chunk_size": chunk_size,
        "sha256": sha256,
    }


def receive_one(args: argparse.Namespace) -> None:
    context = tls_context(args.secrets)
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind((args.host, args.port))
    listen.listen(1)
    print(f"mTLS receiver listening on {args.host}:{args.port}")

    with listen:
        raw_conn, peer = listen.accept()
        print(f"accepted connection from {peer[0]}:{peer[1]}")
        with raw_conn:
            with context.wrap_socket(raw_conn, server_side=True) as conn:
                metadata = validate_metadata(recv_json(conn))
                final_path = args.output_dir / metadata["file_name"]
                part_path = prepare_temp_file(final_path)
                digest = hashlib.sha256()
                remaining = metadata["file_size"]
                timer = Throughput()
                received = 0

                try:
                    with part_path.open("wb") as output:
                        while remaining:
                            block = recv_exact(conn, min(metadata["chunk_size"], remaining))
                            output.write(block)
                            digest.update(block)
                            received += len(block)
                            remaining -= len(block)
                        fsync_file(output)
                except Exception:
                    print(f"transfer failed; partial output kept at {part_path}")
                    raise

                actual = digest.hexdigest()
                if actual != metadata["sha256"]:
                    failed = quarantine_partial(part_path, final_path)
                    raise ProtocolError(
                        f"SHA-256 mismatch; quarantined partial output at {failed}"
                    )
                finalize_verified_file(part_path, final_path)
                print(f"received {received} bytes into {final_path}")
                print(f"sha256 {actual}")
                print(f"throughput {timer.mbps(received):.2f} MB/s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=TLS_PORT)
    parser.add_argument("--secrets", type=Path, default=Path("secrets"))
    parser.add_argument("--output-dir", type=Path, default=Path("received") / "tls")
    args = parser.parse_args()
    receive_one(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
