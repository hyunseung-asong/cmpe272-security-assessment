#!/usr/bin/env python
"""Sender for Approach B: signed encrypted envelope over plain TCP."""

from __future__ import annotations

import argparse
import math
import os
import socket
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.constants import CHUNK_SIZE, DEFAULT_HOST, ENVELOPE_PORT, PROTOCOL_VERSION
from shared.crypto_utils import (
    aad_for_chunk,
    b64d,
    b64e,
    chunk_nonce,
    constant_time_equal,
    derive_session_key,
    fingerprint_ed25519,
    load_private_key,
    load_public_key,
    nonce_prefix,
    raw_x25519_public,
    signed_message,
    transcript_hash,
    verify_signed_message,
)
from shared.file_utils import file_sha256, file_size, stream_file_chunks
from shared.io_utils import ProtocolError, Throughput, send_frame, send_json, recv_json


def load_sender_private(path: Path) -> ed25519.Ed25519PrivateKey:
    key = load_private_key(path)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("sender private key must be Ed25519")
    return key


def load_receiver_public(path: Path) -> ed25519.Ed25519PublicKey:
    key = load_public_key(path)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("receiver public key must be Ed25519")
    return key


def send_file(args: argparse.Namespace) -> None:
    input_path = args.input.resolve()
    size = file_size(input_path)
    digest = file_sha256(input_path, args.chunk_size)

    sender_private = load_sender_private(args.sender_private)
    sender_public = sender_private.public_key()
    receiver_public = load_receiver_public(args.receiver_public)
    expected_receiver_fingerprint = fingerprint_ed25519(receiver_public)
    sender_fingerprint = fingerprint_ed25519(sender_public)

    with socket.create_connection((args.host, args.port), timeout=args.timeout) as conn:
        hello_message = recv_json(conn)
        hello_body = verify_signed_message(hello_message, receiver_public, "receiver-hello")
        if not constant_time_equal(
            str(hello_body.get("receiver_fingerprint", "")), expected_receiver_fingerprint
        ):
            raise ProtocolError("receiver fingerprint does not match pinned key")

        receiver_nonce = b64d(str(hello_body["receiver_nonce"]))
        receiver_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            b64d(str(hello_body["receiver_ephemeral_pub"]))
        )
        sender_ephemeral_private = x25519.X25519PrivateKey.generate()
        sender_ephemeral_public = sender_ephemeral_private.public_key()
        sender_nonce = os.urandom(16)
        transfer_id = os.urandom(16).hex()
        chunk_count = math.ceil(size / args.chunk_size) if size else 0

        manifest_body = {
            "type": "sender-manifest",
            "version": PROTOCOL_VERSION,
            "transfer_id": transfer_id,
            "timestamp": int(time.time()),
            "file_name": input_path.name,
            "file_size": size,
            "chunk_size": args.chunk_size,
            "chunk_count": chunk_count,
            "plaintext_sha256": digest,
            "sender_fingerprint": sender_fingerprint,
            "receiver_fingerprint": expected_receiver_fingerprint,
            "sender_nonce": b64e(sender_nonce),
            "receiver_nonce": hello_body["receiver_nonce"],
            "sender_ephemeral_pub": b64e(raw_x25519_public(sender_ephemeral_public)),
            "receiver_ephemeral_pub": hello_body["receiver_ephemeral_pub"],
        }
        manifest_message = signed_message(manifest_body, sender_private)
        send_json(conn, manifest_message)

        shared_secret = sender_ephemeral_private.exchange(receiver_ephemeral_public)
        key = derive_session_key(shared_secret, transcript_hash(hello_message, manifest_message))
        aesgcm = AESGCM(key)
        prefix = nonce_prefix(sender_nonce, receiver_nonce, transfer_id)

        timer = Throughput()
        sent = 0
        for index, chunk in enumerate(stream_file_chunks(input_path, args.chunk_size)):
            header = {
                "type": "chunk",
                "version": PROTOCOL_VERSION,
                "transfer_id": transfer_id,
                "index": index,
                "offset": sent,
                "plain_len": len(chunk),
                "final": index == chunk_count - 1,
            }
            ciphertext = aesgcm.encrypt(chunk_nonce(prefix, index), chunk, aad_for_chunk(header))
            send_json(conn, header)
            send_frame(conn, ciphertext)
            sent += len(chunk)

        print(f"sent {sent} encrypted envelope bytes of plaintext")
        print(f"sha256 {digest}")
        print(f"transfer_id {transfer_id}")
        print(f"throughput {timer.mbps(sent):.2f} MB/s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=ENVELOPE_PORT)
    parser.add_argument("--sender-private", type=Path, default=Path("secrets/envelope/sender_ed25519_private.pem"))
    parser.add_argument("--receiver-public", type=Path, default=Path("secrets/envelope/receiver_ed25519_public.pem"))
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    send_file(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
