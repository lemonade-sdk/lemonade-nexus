---
layout: default
title: IP Ranges and IPAM
---

# IP Ranges and IPAM

## Table of Contents
- [Address Ranges](#address-ranges)
- [Reserved Addresses](#reserved-addresses)
- [IPAM Allocation](#ipam-allocation)
- [Backbone Allocation](#backbone-allocation)
- [Multi-Server Coordination](#multi-server-coordination)

## Address Ranges

| Range | CIDR | Size | Purpose |
|-------|------|------|---------|
| **Client tunnel** | `10.64.0.0/10` | 4,194,304 | WireGuard tunnel between clients and servers |
| **Server backbone** | `172.16.0.0/22` | 1,024 | Server-to-server encrypted WireGuard mesh |
| **Private subnets** | `10.128.0.0/9` | 8,388,608 | Per-customer private addressing |
| **Shared blocks** | `172.20.0.0/14` | 262,144 | Shared address space |

## Reserved Addresses

The first 10 addresses (.0 through .9) in each subnet are reserved:

| Address | Purpose |
|---------|---------|
| `.0` | Network address |
| `.1` | Server gateway (genesis server always gets .1) |
| `.2`–`.9` | Reserved for future system services (DNS, relay, monitoring) |
| `.10`+ | Client endpoints |

## IPAM Allocation

### Client Tunnel IPs (10.64.0.0/10)
- Sequential allocation starting at offset 10
- Each client gets a `/32` (single IP)
- Allocated during `/api/join` — the server picks the next free IP
- Persisted to `data/ipam/allocations.json`

### Private Subnets (10.128.0.0/9)
- Per-customer, default `/30` (4 addresses)
- Expandable via `do_expand_allocation()`

### Shared Blocks (172.20.0.0/14)
- Shared address space, default `/30`
- Expandable

## Backbone Allocation (172.16.0.0/22)

Server backbone IPs are allocated using **pubkey-hash selection**:

1. Hash the server's Ed25519 public key
2. `preferred_offset = hash % 1012 + 10` (offsets 10–1021)
3. If preferred offset is taken, linear-probe forward (wrap at 1022 back to 10)
4. Result: deterministic, evenly distributed allocation

### Conflict Resolution (Democratic)
When two servers claim the same backbone IP:
- **Higher pubkey wins** (lexicographic comparison of base64 Ed25519 keys)
- Loser re-probes to the next free slot
- Deterministic — no clock dependency, no root authority

### Staleness and Reclamation
- Each backbone allocation tracks `last_seen` timestamp
- Servers update `last_seen` during gossip ticks
- After 72 hours without contact, the allocation is released via gossip
- Freed IPs can be claimed by new servers

## Multi-Server Coordination

IPAM allocations are synced via gossip:
- **Message type:** `BackboneIpamSync` (0x13)
- **Epidemic gossip:** allocations forwarded to all peers, deduped by `delta_id`
- **Conflict resolution:** higher pubkey wins (deterministic tiebreak)
- **Late joiners:** receive full backbone allocation table during anti-entropy sync
