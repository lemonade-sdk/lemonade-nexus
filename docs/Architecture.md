---
layout: default
title: Architecture
---

# Architecture

## Table of Contents
- [Design Philosophy](#design-philosophy)
- [CRTP-Only Architecture](#crtp-only-architecture)
- [Network Topology](#network-topology)
- [Service Architecture](#service-architecture)
- [Data Storage](#data-storage)
- [Dual HTTP Server](#dual-http-server)

## Design Philosophy

- **No virtual functions** — all polymorphism via CRTP (Curiously Recurring Template Pattern)
- **No database** — all state stored as signed JSON files on disk
- **Democratic governance** — no single root authority, servers vote on changes
- **Zero-trust** — every message carries cryptographic proof of identity and integrity
- **Federated** — community relay servers see only ciphertext

## CRTP-Only Architecture

Every service interface uses CRTP instead of virtual dispatch:

```cpp
template <typename Derived>
class IService {
public:
    void start() { self().on_start(); }
    void stop()  { self().on_stop(); }
protected:
    ~IService() = default;
private:
    Derived& self() { return static_cast<Derived&>(*this); }
};

class MyService : public IService<MyService> {
    friend class IService<MyService>;
    void on_start() { /* ... */ }
    void on_stop()  { /* ... */ }
};
```

Benefits: zero-overhead dispatch, compile-time type safety, no vtable pointer per object.

## Network Topology

```
                        Internet
                           |
        ┌──────────────────┼──────────────────┐
        |                  |                  |
   [Server 1]        [Server 2]        [Server 3]
   us-west            eu-west           ap-south
   ns1                ns2               ns3
   Pub: 67.x.x.x     Pub: 185.x.x.x   Pub: 103.x.x.x
   Tun: 10.64.0.1    Tun: 10.64.0.1    Tun: 10.64.0.1
   BB:  172.16.0.66   BB:  172.16.0.120  BB:  172.16.0.45
        |                  |                  |
        └───── WG Backbone (172.16.0.0/22) ───┘
        |                  |                  |
   [Clients]          [Clients]          [Clients]
   10.64.0.10+        10.64.0.10+        10.64.0.10+
```

**Three network planes:**
1. **Public Internet** — gossip (9102/udp), STUN (3478/udp), public HTTPS API (9100/tcp)
2. **Client tunnel** (10.64.0.0/10) — WireGuard between client and server, private HTTPS API
3. **Server backbone** (172.16.0.0/22) — WireGuard between servers, backend communication

## Service Architecture

All services start in dependency order:

```
SodiumCryptoService → FileStorageService → KeyWrappingService
    → BinaryAttestationService → TeeAttestationService → TrustPolicyService
    → PermissionTreeService → IPAMService → RootKeyChainService
    → GovernanceService → GossipService → DdnsService
    → StunService → RelayService → RelayDiscoveryService
    → AcmeService → DnsService → AuthService → ACLService
    → WireGuardService → HttpServer(s) → HolePunchService
```

## Data Storage

All state in `data/` directory as signed JSON:

```
data/
├── identity/          # Server keypair, JWT secret, region, hostname
│   ├── keypair.pub    # Ed25519 public key (hex)
│   ├── keypair.enc    # Encrypted private key
│   ├── jwt_secret.hex # Auto-generated JWT secret
│   └── region         # Persisted region code
├── tree/
│   ├── nodes/         # Permission tree nodes (JSON per node)
│   └── deltas/        # Signed tree deltas (append-only log)
├── ipam/
│   └── allocations.json  # All IP allocations (SignedEnvelope)
├── certs/             # ACME TLS certificates per domain
├── identity/peers.json   # Known gossip peers
└── acl.db             # SQLite ACL database
```

## Dual HTTP Server

| Server | Bind Address | Protocol | Purpose |
|--------|-------------|----------|---------|
| Public | `0.0.0.0:9100` | HTTPS | Bootstrap: auth, join, health, discovery |
| Private | `<tunnel_ip>:9101` | HTTPS | Tree, IPAM, mesh, certs, governance |

The private server only starts after WireGuard allocates a tunnel IP. It serves HTTPS using an ACME certificate for `private.<id>.<region>.seip.<domain>`.
