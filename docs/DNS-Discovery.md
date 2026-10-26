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
│   ├── tier1.<region>.seip.<base>     onboarding / seed discovery (A + TXT)
│   └── tier2.<region>.seip.<base>     onboarding / seed discovery (A + TXT)
├── <node_id>.ep.<base>                 client endpoints
└── <device>.<group-label>.lo.<base>    group loopback names (127.0.0.1)
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

## Group Loopback Names

```text
<device>.<group-label>.lo.<domain>   A -> 127.0.0.1
```

Every name under `<group-label>.lo.<domain>` resolves to `127.0.0.1`. On
each computer the name reaches the local `lemond`, which routes by name to
the device that the name belongs to.

- `<group-label>` is `g` and 20 hex characters of a domain-separated
  SHA-256 of the group id (`network::group_loopback_label`). It does not
  change when the group is renamed, and another group cannot claim it by
  name. A label that matches more than one group gets no answer.
- `<device>` is any one DNS label. The server does not check it against the
  tree; `lemond` does the routing.
- The answer comes from the replicated tree, so every Tier 1 server gives
  the same answer. The names stop resolving when the group is deleted.
- The server answers only A queries. Other query types for these names get
  NXDOMAIN, like every other tree name.

### Group wildcard certificate

Each group has one Let's Encrypt certificate for
`*.<group-label>.lo.<domain>`. A device requests it through
`POST /api/certs/issue` with `"scope": "group_loopback"`
(`ln_cert_request_group`, or `ln_cert_renew_if_needed` with
`LN_CERT_GROUP_LOOPBACK`). The server issues it with DNS-01 on
`_acme-challenge.<group-label>.lo.<domain>` and returns the key encrypted to
the caller's own key. The caller must be a joined endpoint of the group.

Tradeoffs:

- Every device of the group holds the same private key. A device that
  leaves the group can no longer fetch the certificate or its renewals, but
  it keeps the key it already has until that certificate expires. The
  server does not issue again when membership changes: a new certificate
  does not revoke the old one, and repeated orders would reach the Let's
  Encrypt duplicate-certificate limit.
- The names resolve only to loopback. To use a leaked key against a device,
  an attacker must also answer for the name on that device (local code or a
  forged DNS answer).
- Device and group certificates are issued again when less than one third
  of their lifetime remains: by the server's daily renewal monitor and at
  the next request, and by the SDK, which checks in the mesh loop and calls
  the renewal callback (`ln_set_cert_renewed_callback`).

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
tier1.<region>.seip.<domain>    A   -> server(s) currently serving that tier
tier2.<region>.seip.<domain>    A   -> ...
tier1.<region>.seip.<domain>    TXT -> "v=sp1 host=<id1>.<region>.seip.<domain> host=<id2>..."
tier2.<region>.seip.<domain>    TXT -> ...
```

The `A` record aggregates the public IPs of the servers currently serving
that tier; startup seed discovery (always on) uses it to find
gossip peers automatically. The `TXT` record lists each member's SEIP FQDN
(`<id>.<region>.seip.<domain>`). A tier with no members returns NXDOMAIN for
both types.

The onboarding client uses these to discover a target when no
`--onboard-server` FQDN is given. It reads the TXT record and probes the
member FQDNs, not the tier name: the server's ACME certificate covers the
member FQDN, so a probe of the tier FQDN would fail hostname verification.
Onboarding is a per-region, single-server operation, so the TXT record lists
members, not IPs.

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

Onboarding discovery (no `--onboard-server` given) follows the same region
resolution, then:

```text
1. Query the tier member list
   - TXT tier1.<region>.seip.<base> -> "v=sp1 host=<id>.<region>.seip.<base> ..."
   - NXDOMAIN or an empty member list falls back to tier2, then to the tier
     FQDNs themselves

2. Verified HTTPS probe of each member FQDN
   - GET /api/onboard/info over TLS, certificate verified against the member
     FQDN (never against a bare IP; --onboard-addr can still pin the
     connect IP)
   - the member's own A record supplies the IP

3. First target that reports accepts_onboarding wins; the onboarding flow
   (challenge, signed request, poll) continues against it
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
