# Design

## Approach A: Mutual TLS Streaming

Architecture:

```text
sender.py --TLS 1.3 mTLS--> receiver.py
   |                            |
sender cert                 receiver cert
trusted CA                  trusted CA
```

The receiver listens on TCP `127.0.0.1:9443` and requires a client certificate signed by the generated local CA. The sender validates the receiver certificate against the same CA and checks the `localhost` server name. Certificate verification is never disabled.

The sender first computes the plaintext SHA-256 and sends framed metadata containing file name, file size, chunk size, and digest. It then streams the file bytes over the TLS connection in `1 MiB` chunks. TLS 1.3 provides authenticated encryption for the channel. The receiver writes bytes to `received/tls/<name>.part`, computes SHA-256 while streaming, checks the expected size and digest, then atomically renames to the final path.

Algorithms and parameters:

- Transport: TCP.
- Secure channel: Python `ssl`, TLS 1.3 minimum.
- Authentication: local RSA-3072 CA signs RSA-3072 sender and receiver certs.
- Confidentiality/integrity on wire: TLS 1.3 AEAD cipher suite selected by OpenSSL.
- End-to-end file check: SHA-256 over plaintext.
- Chunk size: `1 MiB`.

CIAA mapping:

| Property | Mechanism |
| --- | --- |
| Confidentiality | TLS 1.3 encrypts all file bytes before they cross TCP. |
| Integrity | TLS AEAD detects record modification; receiver also verifies plaintext SHA-256. |
| Authenticity | Receiver requires client cert; sender verifies receiver cert and hostname. |
| Availability | TCP retransmission plus streaming temp-file writes; dropped transfers never become final files. |

Threat model:

| Threat | Response |
| --- | --- |
| Passive eavesdropper records stream | Only TLS ciphertext is visible; private keys and plaintext file bytes are not sent unencrypted. |
| Active MITM modifies bytes | TLS record authentication fails or final SHA-256 fails; output remains non-final. |
| Attacker spoofs sender or receiver | Wrong certificates fail the TLS handshake because both sides verify against the local CA. |
| Replay of earlier valid transfer | TLS 1.3 uses fresh handshakes and nonces; replayed TCP bytes do not authenticate in a new session. |
| Connection drops at 80% | Receiver raises an error and keeps only `.part`; no final file is published. |
| Untrusted intermediary | No broker is used in this approach. |

## Approach B: Signed Encrypted Envelope

Architecture:

```text
sender.py --plain TCP frames--> receiver.py
   |                                |
Ed25519 sender key              Ed25519 receiver key
ephemeral X25519                ephemeral X25519
AES-256-GCM chunks              AES-256-GCM chunks
```

This approach does not rely on TLS. The receiver signs a hello containing its identity fingerprint, receiver nonce, and ephemeral X25519 public key. The sender verifies that signature against the pinned receiver public key. The sender then signs a manifest containing file metadata, both nonces, both ephemeral public keys, identity fingerprints, timestamp, transfer ID, chunk count, chunk size, and plaintext SHA-256. The receiver verifies the manifest against the pinned sender public key.

Both sides compute an X25519 shared secret and derive a 256-bit AES-GCM key with HKDF-SHA256. Each chunk is encrypted independently. The 96-bit AES-GCM nonce is a 4-byte prefix derived from both nonces and the transfer ID, followed by the 8-byte chunk index. Associated data binds transfer ID, chunk index, offset, plaintext length, and final-chunk flag.

Algorithms and parameters:

- Transport: TCP with length-prefixed JSON/binary frames.
- Identity signatures: Ed25519.
- Ephemeral key exchange: X25519.
- KDF: HKDF-SHA256, 32-byte output.
- AEAD: AES-256-GCM from `cryptography`.
- Replay bound: signed timestamp accepted within a 300-second window.
- End-to-end file check: SHA-256 over plaintext.
- Chunk size: `1 MiB`.

CIAA mapping:

| Property | Mechanism |
| --- | --- |
| Confidentiality | AES-256-GCM encrypts every chunk with a fresh session key derived from ephemeral X25519. |
| Integrity | AES-GCM tags authenticate chunk ciphertext and AAD; final SHA-256 detects truncation or reordered plaintext. |
| Authenticity | Ed25519 signatures bind receiver hello and sender manifest to pinned public keys. |
| Availability | TCP retransmission plus fixed chunk framing; interrupted transfers never reach final rename. |

Threat model:

| Threat | Response |
| --- | --- |
| Passive eavesdropper records stream | File bytes are AES-GCM ciphertext; the session key is derived from X25519 and never sent. |
| Active MITM modifies bytes | Modified hello/manifest signatures fail, or modified chunks fail AES-GCM authentication. |
| Attacker spoofs sender or receiver | Receiver and sender verify Ed25519 signatures against pinned public keys. |
| Replay of earlier valid transfer | The signed manifest includes timestamp, transfer ID, both nonces, and both ephemeral keys; stale timestamps are rejected. |
| Connection drops at 80% | Receiver fails while reading expected chunks and keeps only `.part`; no final file appears. |
| Untrusted intermediary | A storage/broker tier would see only signed metadata and ciphertext, not plaintext or long-lived private keys. |

## Shared Fail-Closed Behavior

Both receivers write to a temporary `.part` file. The final filename is created only after the expected byte count and plaintext SHA-256 match. Mid-stream failures keep data quarantined under `.part`; completed-but-invalid payloads are renamed to `.failed`. Neither case ever produces a trusted final file.
