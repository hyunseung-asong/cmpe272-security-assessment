"""Cryptographic helper functions for the envelope approach."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared.io_utils import ProtocolError, canonical_json


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProtocolError("invalid base64 field") from exc


def load_private_key(path: Path):
    with path.open("rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def load_public_key(path: Path):
    with path.open("rb") as handle:
        return serialization.load_pem_public_key(handle.read())


def raw_ed25519_public(public_key: ed25519.Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def raw_x25519_public(public_key: x25519.X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint_ed25519(public_key: ed25519.Ed25519PublicKey) -> str:
    return hashlib.sha256(raw_ed25519_public(public_key)).hexdigest()


def signed_message(body: dict, private_key: ed25519.Ed25519PrivateKey) -> dict:
    body_bytes = canonical_json(body)
    return {"body": body, "signature": b64e(private_key.sign(body_bytes))}


def verify_signed_message(
    message: object,
    public_key: ed25519.Ed25519PublicKey,
    expected_type: str,
) -> dict:
    if not isinstance(message, dict) or not isinstance(message.get("body"), dict):
        raise ProtocolError("signed message is malformed")
    signature = b64d(message.get("signature", ""))
    body = message["body"]
    if body.get("type") != expected_type:
        raise ProtocolError(f"expected {expected_type} message")
    try:
        public_key.verify(signature, canonical_json(body))
    except InvalidSignature as exc:
        raise ProtocolError(f"{expected_type} signature verification failed") from exc
    return body


def transcript_hash(*messages: dict) -> bytes:
    digest = hashlib.sha256()
    for message in messages:
        digest.update(canonical_json(message))
    return digest.digest()


def derive_session_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"cmpe272-envelope-v1 aes-256-gcm",
    ).derive(shared_secret)


def nonce_prefix(sender_nonce: bytes, receiver_nonce: bytes, transfer_id: str) -> bytes:
    return hashlib.sha256(
        b"cmpe272-envelope-v1 nonce" + sender_nonce + receiver_nonce + transfer_id.encode("ascii")
    ).digest()[:4]


def chunk_nonce(prefix: bytes, index: int) -> bytes:
    if len(prefix) != 4:
        raise ProtocolError("nonce prefix must be 4 bytes")
    return prefix + index.to_bytes(8, "big")


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def aad_for_chunk(header: dict) -> bytes:
    return canonical_json(
        {
            "transfer_id": header["transfer_id"],
            "index": header["index"],
            "offset": header["offset"],
            "plain_len": header["plain_len"],
            "final": header["final"],
        }
    )


def require_json_dict(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ProtocolError(f"{label} must be a JSON object")
    json.dumps(value)
    return value
