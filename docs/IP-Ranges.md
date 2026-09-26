---
layout: default
title: IP Ranges and IPAM
---

# IP Ranges and IPAM

## Table of Contents
- [Address Ranges](#address-ranges)
- [Reserved Addresses](#reserved-addresses)
- [Client Tunnel IPs](#client-tunnel-ips)
- [Private and Shared Blocks](#private-and-shared-blocks)
- [Backbone Allocation](#backbone-allocation)
- [Multi-Server Coordination](#multi-server-coordination)
- [Staleness and Reclamation](#staleness-and-reclamation)

## Address Ranges

| Range | CIDR | Size | Purpose |
|-------|------|------|---------|
| **Client tunnel** | `10.64.0.0/10` | 4,194,304 | Encrypted mesh between clients and servers |
| **Server backbone** | `172.16.0.0/22` | 1,024 | Server-to-server mesh |
| **Private subnets** | `10.128.0.0/9` | 8,388,608 | Per-customer private addressing |
| **Shared blocks** | `172.20.0.0/14` | 262,144 | Shared address space |

These ranges are address *capacity*, not population targets. The Tier 1
target-population table in [Security — Compiled Rules](Security#compiled-rules)
is a separate selection goal.

## Reserved Addresses

The first ten addresses (`.0` through `.9`) of each allocating subnet are
reserved for system use:

| Address | Purpose |
|---------|---------|
| `.0` | Network address |
| `.1` | Server gateway (tunnel plane) |
| `.2`–`.9` | Reserved for system services |
| `.10`+ | Allocated endpoints |

## Client Tunnel IPs (10.64.0.0/10)

- Sequential allocation starting at offset 10.
- Each client gets a `/32`; tunnel allocations cannot be expanded.
- Allocated during `/api/join` and persisted to `data/ipam/`.
- Allocations are DHCP-style leases: the lease timeout scales with how full
  the pool is (168 hours at half-full or less, shrinking linearly to zero at
  full).

## Private and Shared Blocks

- **Private subnets** (`10.128.0.0/9`): per customer, default `/30`,
  expandable.
- **Shared blocks** (`172.20.0.0/14`): default `/30`, expandable.

## Backbone Allocation (172.16.0.0/22)

Server backbone IPs are allocated **deterministically from the server
identity**:

1. Hash the server's base64 Ed25519 gossip public key with a
   multiply-by-31 rolling hash over the first 16 bytes
   (`hash = hash * 31 + byte`).
2. `preferred_offset = (hash % 1014) + 10` — offsets `10` through `1023`
   (the first ten addresses are reserved).
3. If the preferred offset is taken, probe forward linearly, wrapping from
   `1023` back to `10`.

The result is the same preferred address for the same identity on every
server, so an offline holder's slot is reproducible.

### Conflict Resolution

When two servers claim the same backbone IP, the **higher pubkey wins**
(lexicographic comparison of the base64 keys); the loser re-probes to the next
free slot. A backbone claim is only applied when it is signed by the named
server itself (origin-verified) and that server holds a root-signed
certificate — third parties evict nobody. Deterministic, no clock
dependency, no central authority.

## Multi-Server Coordination

Backbone allocations sync via gossip:

- **Message type:** `BackboneIpamSync` (0x13).
- Ingress is certificate-gated (root-signed, non-revoked peer).
- Deltas are deduplicated by `delta_id`; new allocations are forwarded to all
  peers.
- Late joiners receive the allocation table through anti-entropy sync.

Client tunnel, private, and shared allocations are currently managed per
server; full cross-server IPAM sync for those pools is not implemented. Two
servers could assign the same client IP if they allocate simultaneously — a
known limitation, not a conflict-resolved guarantee.

## Staleness and Reclamation

- Tunnel and backbone allocations record `last_seen`, refreshed by
  heartbeats and gossip ticks.
- The code contains a tunnel-lease sweep and a stale-backbone collector, but
  **neither is wired to a periodic pass in the current revision**. A departed
  node's backbone IP is therefore not automatically reclaimed today, and
  lease expiry does not run on a timer.

This is an implementation gap, documented here so operators do not rely on
automatic reclamation.
