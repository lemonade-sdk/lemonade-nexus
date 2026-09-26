---
layout: default
title: DNS Discovery
---

# DNS Discovery

## Table of Contents
- [Subdomain Hierarchy](#subdomain-hierarchy)
- [SEIP — Server Endpoint IP](#seip--server-endpoint-ip)
- [EP — Client Endpoints](#ep--client-endpoints)
- [NS Bootstrap](#ns-bootstrap)
- [Tier Records](#tier-records)
- [Client Discovery Flow](#client-discovery-flow)
- [Config TXT Format](#config-txt-format)
- [Region Codes](#region-codes)

All records are served by the servers' authoritative DNS (UDP+TCP on `5335`;
public `53` where NAT-mapped) and kept consistent across servers by gossip.
DNS provides reachability. Trust comes from pinned keys, verified
certificates, and finalized security state.

## Subdomain Hierarchy

Base domain: `dns_base_domain` (default `lemonade-nexus.io`).

```text
<base>
├── ns1..ns9.<base>                     bootstrap nameservers
├── <region>.seip.<base>                regional server list (discovery)
│   ├── <id>.<region>.seip.<base>       per-server SEIP records
│   ├── tier1.<region>.seip.<base>     onboarding / seed discovery
│   └── tier2.<region>.seip.<base>     onboarding / seed discovery
└── <node_id>.ep.<base>                 client endpoints
```

## SEIP — Server Endpoint IP

```text
<id>.<region>.seip.<domain>              A   -> public IP
_config.<id>.<region>.seip.<domain>      TXT -> ports + region + load [+ host]
private.<id>.<region>.seip.<domain>      A   -> tunnel IP (10.64.0.x)
backend.<id>.<region>.seip.<domain>      A   -> backbone IP (172.16.0.x)
```

The `private.` record is what clients and joining servers use to reach the
server's private API and onboarding endpoints by FQDN. The `backend.` record
identifies the server's backbone address.

## EP — Client Endpoints

```text
private.<node_id>.ep.<domain>    A -> client tunnel IP (10.64.0.x)
```

Registered by the server when a client joins via `/api/join`.

## NS Bootstrap

The first servers to claim slots become the bootstrap nameservers `ns1`
through `ns9`:

- A server claims the **lowest available slot** by gossip, or a pinned slot
  when its `dns_ns_hostname` names one (the registrar's glue points that
  name at that server, so it holds exactly that slot or none).
- The claim is Ed25519-signed. The receiving server verifies the signature
  and requires the **claimant** to hold a root-signed, non-revoked peer
  certificate before applying it. Claims travel epidemically, so the gate
  binds to the claimant, not the forwarder.
- Claims survive restarts (persisted). When a holder is gone and another
  server takes the slot, the old assignment is superseded by the new signed
  claim.

The base domain's NS records and glue must be set at your registrar to point
at the claimed nameservers. (Optional DDNS keeps the base domain's records
current when the server's public IP changes.)

## Tier Records

```text
tier1.<region>.seip.<domain>    A -> server(s) currently serving that tier
tier2.<region>.seip.<domain>    A -> ...
```

The onboarding client uses these to discover a target when no
`--onboard-server` FQDN is given, and startup seed discovery
(`dns_seed_discovery`) uses them to find gossip peers automatically.

## Client Discovery Flow

```text
1. Determine own region
   - geo lookup (ip-api.com) mapped to the nearest configured region label
   - fallback: system locale

2. Bootstrap DNS
   - resolve <base> -> NS records with glue (ns1..ns9)

3. Query regional servers
   - <region>.seip.<base> -> server public IPs
   - _config TXT per server -> ports, region, load, host FQDN

4. Health probe + latency
   - HTTPS GET /api/health on each candidate

5. Score and sort
   - score = latency_ms + (load * 10); pick the lowest

6. Region fallback
   - no servers in own region -> nearest regions by geographic distance
```

## Config TXT Format

```text
v=sp1 http=9100 udp=51940 gossip=9102 stun=3478 relay=9103 dns=53 private_http=9101 region=us-west load=5 host=<server-fqdn>
```

| Field | Description |
|-------|-------------|
| `v=sp1` | Protocol version |
| `http=` | Public HTTPS API port |
| `udp=` | Mesh port (mesh and hole punching share it) |
| `gossip=` | Gossip + security protocol port |
| `stun=` | STUN port |
| `relay=` | Relay port |
| `dns=` | Authoritative DNS port advertised to clients (NAT-mapped to the local listener) |
| `private_http=` | Private API port (over the mesh) |
| `region=` | Server's region label |
| `load=` | Connected client count |
| `host=` | Server's TLS certificate FQDN (present when configured) |

## Region Codes

A region is a **lowercase DNS label** configured per server
(`--region` / `SP_REGION` / JSON `region`), auto-detected from the public IP
when omitted. There is no fixed global list: each deployment chooses its
labels (for example `us-west`, `eu-central`), and discovery queries use them
verbatim. The geo lookup maps a client's location to the nearest label the
deployment actually uses.
