# Why Use Lemonade-Nexus?

## Self-Hosted, Self-Sovereign
You own every server, every key, every byte of data. No SaaS dependency, no vendor lock-in, no monthly bill that scales with users.

## Democratic Governance
No single root authority. Servers are equal peers that vote on protocol changes, enrollment decisions, and key rotations. Governance proposals propagate via gossip and require quorum approval.

## Zero-Trust by Default
Every gossip message carries cryptographic proof. TEE hardware attestation (Intel SGX, AMD SEV-SNP, Apple Secure Enclave) proves servers are running in trusted execution environments. Binary attestation verifies the exact code running on each server.

## Encrypted Everything
- **WireGuard** tunnel for all data (Curve25519 + ChaCha20-Poly1305)
- **Ed25519** identity for all signing and authentication
- **HTTPS** with auto-provisioned ACME certificates (even the private API over the tunnel)
- **AES-256-GCM** for credential encryption at rest

## Auto-Discovery
Clients find the best server automatically via DNS. No manual IP configuration. Region-aware selection picks the lowest-latency, lowest-load server. If your region has no servers, it falls back to the next closest.

## Federated Relay Servers
Community relay servers forward encrypted WireGuard traffic when direct P2P fails. Relay operators see only ciphertext — they can't read, modify, or log your traffic.

## No Database
All state is stored as signed JSON files on disk. Easy to backup, inspect, migrate, and version control. No PostgreSQL, no migrations, no schema drift.

## Cross-Platform
- **Server:** Linux, macOS, Windows
- **Client:** macOS (native SwiftUI with system tray), Linux, Windows, iOS, Android
- **SDK:** C++ and C APIs for embedding in any application

## Scalable
Designed for hundreds of community servers across regions. Server backbone mesh (172.16.0.0/22) supports up to 1,022 servers. Client address space (10.64.0.0/10) supports millions of endpoints.

## 5-Second Liveness
WireGuard persistent keepalive at 5 seconds gives near-instant peer online/offline detection. Server determines liveness from WireGuard handshake timestamps — no extra protocol overhead.
