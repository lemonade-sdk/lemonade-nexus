# Frequently Asked Questions

## What is Lemonade-Nexus?

A self-hosted, cryptographically secure WireGuard mesh VPN. Think of it as a decentralized alternative to Tailscale or ZeroTier that you fully own and control. All servers are equal peers — no central authority.

## How is it different from Tailscale / ZeroTier / Nebula?

| | Lemonade-Nexus | Tailscale | ZeroTier | Nebula |
|--|---------------|-----------|----------|--------|
| **Self-hosted** | Yes, fully | Coordination server is SaaS | Controllers are SaaS | Yes |
| **Governance** | Democratic (server voting) | Company-controlled | Company-controlled | N/A |
| **TEE attestation** | Yes (SGX, TDX, SEV-SNP, Secure Enclave) | No | No | No |
| **Database** | None (signed JSON files) | PostgreSQL | SQLite | None |
| **DNS** | Built-in authoritative DNS | MagicDNS (SaaS) | None | None |
| **Binary attestation** | Yes (SHA-256 + Ed25519 manifests) | No | No | No |
| **ACME TLS** | Auto-provisioned (ZeroSSL/Let's Encrypt) | Managed | N/A | N/A |
| **Protocol** | WireGuard | WireGuard | Custom (ZT) | Custom (Nebula) |

## Do I need to run my own server?

Yes, at least one server. But it's simple — just run the binary and it auto-configures: generates identity, detects region, allocates IPs, obtains TLS certificates, and starts serving.

## How many servers can I have?

Up to ~1,000 on the server backbone (172.16.0.0/22). The first 9 servers also serve as authoritative DNS nameservers (ns1–ns9). All servers are equal peers with democratic governance.

## Is it free / open source?

Yes. See the repository license.

## What platforms are supported?

- **Server:** Linux (primary), macOS, Windows
- **Client:** macOS (native SwiftUI app), Linux, Windows, iOS (config), Android (config)

## How does NAT traversal work?

1. STUN service discovers each client's public IP and port
2. Hole punch service (port 51941) coordinates port-mapping exchange between clients
3. Both clients send WireGuard handshake packets to each other's discovered endpoints
4. NAT mappings are "punched" and a direct P2P tunnel is established
5. If direct fails, traffic falls back through a relay server

## Can I use it without TEE hardware?

Yes. Without TEE, servers operate as Tier 2 (certificate-only). They can serve clients and participate in gossip, but won't hold Shamir root key shares or vote on governance.

## How are IP addresses allocated?

- **Clients:** Sequential allocation from 10.64.0.0/10, starting at .10 (first 10 reserved)
- **Servers:** Pubkey-hash-based allocation from 172.16.0.0/22 (deterministic, collision-resistant)
- **Conflict resolution:** If two servers allocate the same IP, the higher pubkey wins (democratic, no root authority)

## What happens if a server goes down?

- Clients connected to that server lose their tunnel
- The client SDK automatically discovers and switches to the next best server (latency + load scoring)
- Other servers continue operating independently
- The downed server's backbone IP is reclaimed after 72 hours of no contact

## Can two servers accidentally give out the same client IP?

Currently, IPAM is local to each server. If two servers allocate simultaneously, they could assign the same IP. The server backbone mesh (172.16.0.0/22) uses gossip to sync backbone allocations. Full client IPAM gossip sync is planned.

## How do I add a new server?

```bash
lemonade-nexus --seed-peer <existing-server-ip>:9102 --region eu-west
```

The new server will:
1. Gossip with the seed peer to discover the mesh
2. Self-allocate a backbone IP (172.16.0.x)
3. Claim an NS slot if available (ns1–ns9)
4. Register SEIP DNS records for client discovery
5. Start serving clients
