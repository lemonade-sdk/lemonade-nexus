# Security

## Table of Contents
- [Identity and Cryptography](#identity-and-cryptography)
- [Transport Security](#transport-security)
- [Authentication](#authentication)
- [Binary Attestation](#binary-attestation)
- [TEE Attestation](#tee-attestation)
- [Two-Tier Trust](#two-tier-trust)
- [Credential Distribution](#credential-distribution)
- [Rate Limiting and Replay Protection](#rate-limiting-and-replay-protection)

## Identity and Cryptography

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Identity keys | Ed25519 | Server and client identity, signing |
| WireGuard keys | X25519 (Curve25519) | Tunnel encryption (derived from Ed25519) |
| Symmetric AEAD | XChaCha20-Poly1305 / AES-256-GCM | Credential encryption, at-rest encryption |
| Key derivation | HKDF-SHA256 | Derive encryption keys from shared secrets |
| Password hashing | PBKDF2-SHA256 (100k iterations) | Derive Ed25519 seed from username+password |
| Hashing | SHA-256 | Binary attestation, deduplication |
| Fast hashing | xxHash | Gossip deduplication |
| TLS | OpenSSL 3.3.2 | HTTPS for public and private APIs |

All cryptography via **libsodium** (identity, signing, DH, AEAD) and **OpenSSL** (TLS, ACME).

## Transport Security

- **Public API:** HTTPS with ACME auto-provisioned TLS certificates (ZeroSSL/Let's Encrypt)
- **Private API:** HTTPS over WireGuard tunnel (double encryption)
- **Gossip:** Ed25519 signed messages, optionally with attestation tokens
- **WireGuard:** Curve25519 key exchange, ChaCha20-Poly1305 encryption, 5-second keepalive

## Authentication

Four authentication methods:

1. **Ed25519 challenge-response** (primary) — server sends nonce, client signs with Ed25519 key
2. **Passkey / FIDO2** (backup) — P-256 in Secure Enclave (macOS), Touch ID biometric
3. **Password + 2FA** — PBKDF2 seed derivation + optional TOTP
4. **Token-link** — one-time login links

## Binary Attestation

Proves a server is running an unmodified, officially released binary:

1. **Build time:** GitHub Actions computes SHA-256 of binary, signs release manifest with Ed25519
2. **Runtime:** Server computes SHA-256 of its own executable (`/proc/self/exe` on Linux)
3. **Verification:** Other servers compare the hash against signed release manifests
4. **Enforcement:** Only verified binaries can receive distributed credentials (DDNS, etc.)

## TEE Attestation

Hardware-backed proof of execution environment:

| Platform | Backend | Hardware |
|----------|---------|----------|
| Intel SGX | DCAP device access | SGX-capable CPUs |
| Intel TDX | `/dev/tdx-guest` ioctl | TDX-capable VMs |
| AMD SEV-SNP | `/dev/sev-guest` ioctl | Confidential VMs |
| Apple Secure Enclave | CoreFoundation C APIs | M1+/T2 Macs |

## Two-Tier Trust

```
┌─────────────────────────────────────────┐
│ Tier 1: TEE + Cert + Binary + 90% Uptime│
│                                         │
│ • Full mesh participation               │
│ • Shamir root key shares                │
│ • Governance voting                     │
│ • Enrollment voting                     │
│ • Authoritative DNS                     │
└─────────────────────────────────────────┘
           ↑ TEE challenge-response
┌─────────────────────────────────────────┐
│ Tier 2: Certificate only                │
│                                         │
│ • Hole punching                         │
│ • Basic gossip participation            │
│ • Client serving                        │
└─────────────────────────────────────────┘
```

**Promotion:** Tier 2 → Tier 1 requires:
1. Valid server certificate
2. TEE attestation report
3. Binary hash in approved manifests
4. 90% uptime over 100+ health checks

**Demotion:** 3 consecutive verification failures → Tier 1 → Tier 2 → Untrusted

## Credential Distribution

Sensitive credentials (DDNS passwords) are distributed via encrypted channel:

1. Server sends: certificate + binary hash + X25519 public key + signature
2. Root verifies: certificate (Ed25519), binary hash (against manifests), signature
3. Encryption: X25519 DH → HKDF → AES-256-GCM
4. At-rest: re-encrypted with server's own identity-derived key

## Rate Limiting and Replay Protection

- **Token bucket:** per-client rate limiting (default 120 RPM, burst 20)
- **Timestamp freshness:** requests must be within 5min age, 1min future
- **Replay cache:** SHA-256 of request body, 10min eviction window
- **Gossip dedup:** `delta_id` UUID deduplication set per message type
