#!/usr/bin/env python
"""Generate local assessment keys and certificates."""

from __future__ import annotations

import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


VALID_DAYS = 365


def write_bytes(path: Path, data: bytes, force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        print(f"exists, keeping: {path}")
        return
    path.write_bytes(data)
    print(f"wrote: {path}")


def private_key_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_pem(key) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name("cmpe272-local-ca"))
        .issuer_name(name("cmpe272-local-ca"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    usage: ExtendedKeyUsageOID,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if usage == ExtendedKeyUsageOID.SERVER_AUTH:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def generate_tls(out: Path, force: bool) -> None:
    ca_key, ca_cert = make_ca()
    receiver_key, receiver_cert = make_leaf(
        "localhost", ca_key, ca_cert, ExtendedKeyUsageOID.SERVER_AUTH
    )
    sender_key, sender_cert = make_leaf(
        "assessment-sender", ca_key, ca_cert, ExtendedKeyUsageOID.CLIENT_AUTH
    )

    write_bytes(out / "tls" / "ca.key", private_key_pem(ca_key), force)
    write_bytes(out / "tls" / "ca.crt", cert_pem(ca_cert), force)
    write_bytes(out / "tls" / "receiver.key", private_key_pem(receiver_key), force)
    write_bytes(out / "tls" / "receiver.crt", cert_pem(receiver_cert), force)
    write_bytes(out / "tls" / "sender.key", private_key_pem(sender_key), force)
    write_bytes(out / "tls" / "sender.crt", cert_pem(sender_cert), force)


def generate_envelope(out: Path, force: bool) -> None:
    for label in ("sender", "receiver"):
        key = ed25519.Ed25519PrivateKey.generate()
        write_bytes(out / "envelope" / f"{label}_ed25519_private.pem", private_key_pem(key), force)
        write_bytes(out / "envelope" / f"{label}_ed25519_public.pem", public_key_pem(key), force)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("secrets"))
    parser.add_argument("--force", action="store_true", help="replace existing keys")
    args = parser.parse_args()

    generate_tls(args.out, args.force)
    generate_envelope(args.out, args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
