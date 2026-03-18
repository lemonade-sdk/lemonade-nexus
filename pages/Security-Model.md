# Security Model

## Layers of Security

```
┌─────────────────────────────────────────────┐
│ Layer 5: Democratic Governance              │
│ Servers vote on changes, no single root     │
├─────────────────────────────────────────────┤
│ Layer 4: TEE + Binary Attestation           │
│ Hardware proof of execution environment     │
├─────────────────────────────────────────────┤
│ Layer 3: Two-Tier Zero Trust                │
│ Every message authenticated + authorized    │
├─────────────────────────────────────────────┤
│ Layer 2: WireGuard Tunnel                   │
│ All data encrypted in transit               │
├─────────────────────────────────────────────┤
│ Layer 1: Ed25519 Identity                   │
│ Cryptographic identity for every entity     │
└─────────────────────────────────────────────┘
```

## Identity (Ed25519)

Every server and client has an Ed25519 keypair. Keys are:
- **Derived** from username+password via PBKDF2 (100k rounds, SHA256) — deterministic, same creds = same key
- **Generated** randomly for servers on first boot
- **Stored** encrypted at rest (AES-256-GCM with HKDF-derived key)

The Ed25519 key is the root of all trust. From it, we derive:
- **X25519** keys for WireGuard tunnel (Curve25519 key exchange)
- **Signatures** on all tree deltas, gossip messages, credentials
- **JWT tokens** for API session authentication

## Transport (WireGuard)

All tunnel traffic uses WireGuard:
- **Key exchange:** Curve25519 (Noise_IK handshake)
- **Encryption:** ChaCha20-Poly1305
- **Keepalive:** 5-second persistent keepalive for liveness detection
- **Offline detection:** No WG handshake for 15 seconds = peer offline

Two tunnel planes:
1. **Client tunnel** (10.64.0.0/10) — between clients and servers
2. **Server backbone** (172.16.0.0/22) — between servers only

## Authentication Methods

| Method | Mechanism | Use Case |
|--------|-----------|----------|
| **Ed25519** | Challenge-response (server nonce → client signs) | Primary, all platforms |
| **Passkey/FIDO2** | P-256 in Secure Enclave, Touch ID biometric | macOS backup auth |
| **Password + 2FA** | PBKDF2 seed + optional TOTP | Fallback |
| **Token-link** | One-time JWT in URL | Email/SMS login |

## Authorization (Permission Tree)

Permissions are stored in a hierarchical tree:
```
root
├── customer-alice
│   ├── alice-laptop (Endpoint)
│   └── alice-phone (Endpoint)
└── customer-bob
    └── bob-server (Endpoint)
```

Each node has:
- **Assignments:** which pubkeys have which permissions (read, write, add_child, delete, admin)
- **Signed deltas:** all changes are Ed25519-signed and gossiped to all servers
- **ACL database:** fine-grained access control (SQLite, gossip-synced)

## Binary Attestation

```
GitHub Actions builds binary
    → SHA-256(binary) → Release Manifest
    → Ed25519 sign(manifest, release_signing_key)
    → Publish with GitHub Release

Server starts:
    → SHA-256(own executable) → compare against signed manifests
    → Include hash in ServerHello gossip
    → Other servers verify: cert ✓ + binary hash ✓ → trusted
```

## TEE Attestation

Hardware Trusted Execution Environments prove the server is running in an isolated, tamper-resistant enclave:

| Platform | Hardware | API |
|----------|----------|-----|
| Intel SGX | SGX-capable CPUs | DCAP device access |
| Intel TDX | TDX-capable VMs | `/dev/tdx-guest` ioctl |
| AMD SEV-SNP | Confidential VMs | `/dev/sev-guest` ioctl |
| Apple Secure Enclave | M1+/T2 Macs | CoreFoundation C APIs |

## Credential Distribution

Sensitive secrets (DDNS passwords) are distributed via encrypted channel:

```
Server → Root:  certificate + binary_hash + X25519_pubkey + signature
Root verifies:  cert ✓, binary_hash in manifests ✓, signature ✓
Root encrypts:  X25519 DH → HKDF → AES-256-GCM(credentials)
Server stores:  re-encrypt at rest with own identity key
```

## Rate Limiting

- **Token bucket:** 120 requests/minute, burst 20
- **Timestamp freshness:** ±5 minutes (rejects old/future requests)
- **Replay cache:** SHA-256 of request body, 10-minute eviction
- **Gossip dedup:** UUID-based deduplication per message type
