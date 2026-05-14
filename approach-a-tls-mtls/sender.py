#!/usr/bin/env python
"""Sender for Approach A: streaming file transfer over mutual TLS."""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.constants import CHUNK_SIZE, DEFAULT_HOST, PROTOCOL_VERSION, TLS_PORT
from shared.file_utils import file_sha256, file_size, stream_file_chunks
from shared.io_utils import Throughput, send_json


def tls_context(secrets: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(secrets / "tls" / "ca.crt"),
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=str(secrets / "tls" / "sender.crt"),
        keyfile=str(secrets / "tls" / "sender.key"),
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def send_file(args: argparse.Namespace) -> None:
    input_path = args.input.resolve()
    size = file_size(input_path)
    digest = file_sha256(input_path, args.chunk_size)
    metadata = {
        "type": "tls-file-metadata",
        "version": PROTOCOL_VERSION,
        "file_name": input_path.name,
        "file_size": size,
        "chunk_size": args.chunk_size,
        "sha256": digest,
    }

    context = tls_context(args.secrets)
    raw_socket = socket.create_connection((args.host, args.port), timeout=args.timeout)
    conn = context.wrap_socket(raw_socket, server_hostname=args.server_name)
    try:
        timer = Throughput()
        send_json(conn, metadata)
        sent = 0
        for chunk in stream_file_chunks(input_path, args.chunk_size):
            conn.sendall(chunk)
            sent += len(chunk)
        try:
            conn.unwrap()
        except OSError:
            # The receiver may close immediately after verifying the fixed-size payload.
            pass
        print(f"sent {sent} bytes over mTLS")
        print(f"sha256 {digest}")
        print(f"throughput {timer.mbps(sent):.2f} MB/s")
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=TLS_PORT)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--secrets", type=Path, default=Path("secrets"))
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    send_file(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
