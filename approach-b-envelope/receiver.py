#!/usr/bin/env python
"""Receiver for Approach B: signed encrypted envelope over plain TCP."""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
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
from shared.file_utils import fsync_file
from shared.io_utils import (
    ProtocolError,
    Throughput,
    finalize_verified_file,
    prepare_temp_file,
    quarantine_partial,
    recv_frame,
    recv_json,
    safe_output_name,
    send_json,
)


def load_receiver_private(path: Path) -> ed25519.Ed25519PrivateKey:
    key = load_private_key(path)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("receiver private key must be Ed25519")
    return key


def load_sender_public(path: Path) -> ed25519.Ed25519PublicKey:
    key = load_public_key(path)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("sender public key must be Ed25519")
    return key


def validate_manifest(
    body: dict,
    sender_fingerprint: str,
    receiver_fingerprint: str,
    receiver_nonce_text: str,
    receiver_ephemeral_text: str,
    max_clock_skew: int,
) -> dict:
    if body.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported manifest version")
    if not constant_time_equal(str(body.get("sender_fingerprint", "")), sender_fingerprint):
        raise ProtocolError("sender fingerprint does not match pinned key")
    if not constant_time_equal(str(body.get("receiver_fingerprint", "")), receiver_fingerprint):
        raise ProtocolError("manifest is not addressed to this receiver")
    if body.get("receiver_nonce") != receiver_nonce_text:
        raise ProtocolError("manifest does not bind receiver nonce")
    if body.get("receiver_ephemeral_pub") != receiver_ephemeral_text:
        raise ProtocolError("manifest does not bind receiver ephemeral key")
    timestamp = int(body.get("timestamp", 0))
    if abs(int(time.time()) - timestamp) > max_clock_skew:
        raise ProtocolError("manifest timestamp is outside the replay window")

    file_name = safe_output_name(str(body.get("file_name", "")))
    file_size = int(body.get("file_size", -1))
    chunk_size = int(body.get("chunk_size", CHUNK_SIZE))
    chunk_count = int(body.get("chunk_count", -1))
    digest = str(body.get("plaintext_sha256", ""))
    transfer_id = str(body.get("transfer_id", ""))
    if file_size < 0 or chunk_size <= 0 or chunk_count < 0:
        raise ProtocolError("invalid file size, chunk size, or chunk count")
    expected_count = (file_size + chunk_size - 1) // chunk_size if file_size else 0
    if chunk_count != expected_count:
        raise ProtocolError("chunk count does not match file size")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ProtocolError("invalid plaintext SHA-256 digest")
    if len(transfer_id) != 32 or any(ch not in "0123456789abcdef" for ch in transfer_id):
        raise ProtocolError("invalid transfer id")
    return {
        "file_name": file_name,
        "file_size": file_size,
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "plaintext_sha256": digest,
        "transfer_id": transfer_id,
        "sender_nonce": b64d(str(body["sender_nonce"])),
        "receiver_nonce": b64d(str(body["receiver_nonce"])),
        "sender_ephemeral_pub": b64d(str(body["sender_ephemeral_pub"])),
    }


def receive_one(args: argparse.Namespace) -> None:
    receiver_private = load_receiver_private(args.receiver_private)
    receiver_public = receiver_private.public_key()
    sender_public = load_sender_public(args.sender_public)
    receiver_fingerprint = fingerprint_ed25519(receiver_public)
    sender_fingerprint = fingerprint_ed25519(sender_public)

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind((args.host, args.port))
    listen.listen(1)
    print(f"envelope receiver listening on {args.host}:{args.port}")

    with listen:
        conn, peer = listen.accept()
        print(f"accepted connection from {peer[0]}:{peer[1]}")
        with conn:
            receiver_ephemeral_private = x25519.X25519PrivateKey.generate()
            receiver_ephemeral_public = receiver_ephemeral_private.public_key()
            receiver_nonce = os.urandom(16)
            receiver_nonce_text = b64e(receiver_nonce)
            receiver_ephemeral_text = b64e(raw_x25519_public(receiver_ephemeral_public))
            hello_body = {
                "type": "receiver-hello",
                "version": PROTOCOL_VERSION,
                "receiver_fingerprint": receiver_fingerprint,
                "receiver_nonce": receiver_nonce_text,
                "receiver_ephemeral_pub": receiver_ephemeral_text,
            }
            hello_message = signed_message(hello_body, receiver_private)
            send_json(conn, hello_message)

            manifest_message = recv_json(conn)
            manifest_body = verify_signed_message(
                manifest_message, sender_public, "sender-manifest"
            )
            manifest = validate_manifest(
                manifest_body,
                sender_fingerprint,
                receiver_fingerprint,
                receiver_nonce_text,
                receiver_ephemeral_text,
                args.max_clock_skew,
            )
            sender_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
                manifest["sender_ephemeral_pub"]
            )
            shared_secret = receiver_ephemeral_private.exchange(sender_ephemeral_public)
            key = derive_session_key(shared_secret, transcript_hash(hello_message, manifest_message))
            aesgcm = AESGCM(key)
            prefix = nonce_prefix(
                manifest["sender_nonce"], manifest["receiver_nonce"], manifest["transfer_id"]
            )

            final_path = args.output_dir / manifest["file_name"]
            part_path = prepare_temp_file(final_path)
            digest = hashlib.sha256()
            received = 0
            timer = Throughput()

            try:
                with part_path.open("wb") as output:
                    for expected_index in range(manifest["chunk_count"]):
                        header_value = recv_json(conn)
                        if not isinstance(header_value, dict):
                            raise ProtocolError("chunk header must be a JSON object")
                        header = header_value
                        expected_offset = expected_index * manifest["chunk_size"]
                        expected_final = expected_index == manifest["chunk_count"] - 1
                        if header.get("type") != "chunk" or header.get("version") != PROTOCOL_VERSION:
                            raise ProtocolError("invalid chunk header")
                        if header.get("transfer_id") != manifest["transfer_id"]:
                            raise ProtocolError("chunk belongs to the wrong transfer")
                        if int(header.get("index", -1)) != expected_index:
                            raise ProtocolError("unexpected chunk index")
                        if int(header.get("offset", -1)) != expected_offset:
                            raise ProtocolError("unexpected chunk offset")
                        if bool(header.get("final")) != expected_final:
                            raise ProtocolError("unexpected final-chunk flag")
                        plain_len = int(header.get("plain_len", -1))
                        if plain_len < 0 or plain_len > manifest["chunk_size"]:
                            raise ProtocolError("invalid chunk plaintext length")

                        ciphertext = recv_frame(conn)
                        try:
                            plaintext = aesgcm.decrypt(
                                chunk_nonce(prefix, expected_index),
                                ciphertext,
                                aad_for_chunk(header),
                            )
                        except InvalidTag as exc:
                            raise ProtocolError("chunk AEAD authentication failed") from exc
                        if len(plaintext) != plain_len:
                            raise ProtocolError("decrypted chunk length mismatch")
                        output.write(plaintext)
                        digest.update(plaintext)
                        received += len(plaintext)
                    fsync_file(output)
            except Exception:
                print(f"transfer failed; partial output kept at {part_path}")
                raise

            if received != manifest["file_size"]:
                failed = quarantine_partial(part_path, final_path)
                raise ProtocolError(f"file size mismatch; quarantined output at {failed}")
            actual = digest.hexdigest()
            if not constant_time_equal(actual, manifest["plaintext_sha256"]):
                failed = quarantine_partial(part_path, final_path)
                raise ProtocolError(f"SHA-256 mismatch; quarantined output at {failed}")
            finalize_verified_file(part_path, final_path)
            print(f"received {received} bytes into {final_path}")
            print(f"sha256 {actual}")
            print(f"transfer_id {manifest['transfer_id']}")
            print(f"throughput {timer.mbps(received):.2f} MB/s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=ENVELOPE_PORT)
    parser.add_argument("--receiver-private", type=Path, default=Path("secrets/envelope/receiver_ed25519_private.pem"))
    parser.add_argument("--sender-public", type=Path, default=Path("secrets/envelope/sender_ed25519_public.pem"))
    parser.add_argument("--output-dir", type=Path, default=Path("received") / "envelope")
    parser.add_argument("--max-clock-skew", type=int, default=300)
    args = parser.parse_args()
    receive_one(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
