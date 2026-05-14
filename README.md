# CMPE 272 Security Engineering Assessment

This repository contains two distinct Python implementations for securely transferring a large file over an untrusted TCP network.

- `approach-a-tls-mtls/`: mutual TLS streaming.
- `approach-b-envelope/`: signed application-layer encrypted envelope over plain TCP.

Both implementations stream fixed-size chunks and write received bytes to a temporary `.part` file. The final output name is created only after the expected byte count and SHA-256 hash verify.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python tools/gen_keys.py --force
```

The generated `secrets/` directory is intentionally ignored by Git.

## Generate Test Files

Small smoke-test file:

```powershell
python tools/make_test_file.py --output test_small.bin --size 1MB
```

Required 4GB assessment file:

```powershell
python tools/make_test_file.py --output test_4gb.bin --size 4GB
```

Use `--random` if you want random bytes instead of zeros. The writer streams in chunks and does not allocate the full file in memory.

## Approach A: mTLS Streaming

Terminal 1:

```powershell
python approach-a-tls-mtls/receiver.py --output-dir received/tls
```

Terminal 2:

```powershell
python approach-a-tls-mtls/sender.py test_4gb.bin
```

The sender verifies the receiver certificate against `secrets/tls/ca.crt`. The receiver requires and verifies the sender client certificate.

## Approach B: Encrypted Envelope

Terminal 1:

```powershell
python approach-b-envelope/receiver.py --output-dir received/envelope
```

Terminal 2:

```powershell
python approach-b-envelope/sender.py test_4gb.bin
```

The receiver signs a hello with its Ed25519 identity key. The sender verifies it against the pinned receiver public key, then sends a signed manifest. Both sides derive a fresh AES-256-GCM key using ephemeral X25519 and HKDF-SHA256.

## Verify Hashes

```powershell
Get-FileHash test_4gb.bin -Algorithm SHA256
Get-FileHash received/tls/test_4gb.bin -Algorithm SHA256
Get-FileHash received/envelope/test_4gb.bin -Algorithm SHA256
```

All three hashes should match.

## Failure Demonstrations

Wrong identity:

```powershell
python tools/gen_keys.py --out bad-secrets --force
python approach-a-tls-mtls/sender.py test_small.bin --secrets bad-secrets
```

The mTLS handshake fails because the receiver does not trust the bad client certificate.

```powershell
python approach-b-envelope/sender.py test_small.bin --receiver-public bad-secrets/envelope/receiver_ed25519_public.pem
```

The envelope sender rejects the receiver hello because the signature does not match the pinned receiver public key.

Connection drop:

1. Start either receiver.
2. Start the matching sender with `test_4gb.bin`.
3. Stop the sender process before it finishes.
4. Confirm no final file exists; only a `.part` file remains.

Tamper behavior:

- Approach A relies on TLS 1.3 AEAD record authentication plus the final plaintext SHA-256 check.
- Approach B authenticates every chunk with AES-256-GCM and authenticated associated data. Any ciphertext/header modification aborts before final rename.

## Verification Already Run

Both implementations were smoke-tested with a 1MB file. Source, mTLS output, and envelope output all produced:

```text
30E14955EBF1352266DC2FF8067E68104607E750ABB9D3B36582B8AF909FCB58
```

Both implementations were also run end-to-end with the required 4GB zero-byte file. Source, mTLS output, and envelope output all produced:

```text
8479e43911dc45e89f934fe48d01297e16f51d17aa561d4d1c216b1ae0fcddca
```

Observed 4GB loopback throughput on this machine:

- mTLS: sender `452.04 MB/s`, receiver `452.12 MB/s`.
- Envelope: sender `472.51 MB/s`, receiver `450.91 MB/s`.

The sender and receiver numbers are not always identical because they time slightly different work. The sender mostly measures reading the input file, encrypting or wrapping bytes, and handing them to the OS. The receiver also decrypts/verifies chunks, hashes plaintext, writes the output file, and flushes it before accepting the transfer. The envelope approach has a slightly larger gap because the receiver checks each signed setup message and every AES-GCM chunk before finalizing the file.

Negative identity checks were also run:

- mTLS with a different generated CA failed the TLS handshake with `CERTIFICATE_VERIFY_FAILED` / `unknown ca`.
- Envelope with the wrong pinned receiver public key failed with `receiver-hello signature verification failed`.
