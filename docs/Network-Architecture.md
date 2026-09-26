---
layout: default
title: Network Architecture
---

# Network Architecture

## Table of Contents
- [Topology](#topology)
- [Traffic Planes](#traffic-planes)
- [Userspace Dataplane](#userspace-dataplane)
- [Client Connection Flow](#client-connection-flow)
- [Private API Delivery](#private-api-delivery)
- [Server-to-Server Traffic](#server-to-server-traffic)
- [Security Transport](#security-transport)
- [DNS Discovery](#dns-discovery)
- [NAT Traversal](#nat-traversal)
- [SDK Client](#sdk-client)

## Topology

```text
                             Internet
                                |
             ┌──────────────────┼──────────────────┐
             |                  |                  |
        [Server A]         [Server B]         [Server C]
        us-west            eu-west            ap-south
        pub: <ip-a>        pub: <ip-b>        pub: <ip-c>
        tun: 10.64.0.1     tun: 10.64.0.1     tun: 10.64.0.1
        bb:  172.16.0.x    bb:  172.16.0.x    bb:  172.16.0.x
             |                  |                  |
             └──── Server backbone (172.16.0.0/22) ────┘
             |                  |                  |
        [clients]          [clients]          [clients]
        client plane (10.64.0.0/10)
```

Both the client plane and the server backbone are **virtual addresses that
exist only inside each daemon** (userspace netstack). There is no kernel
WireGuard interface and no TUN device on the server.

## Traffic Planes

### Public internet

| Traffic | Port | Purpose |
|---------|------|---------|
| Public HTTPS API | TCP `9100` | Discovery, health, auth, join, onboarding. HTTPS or withheld — never plaintext. |
| Mesh + hole punching (BoringTun) | UDP `51940` | Client tunnels, server backbone, and NAT traversal — one shared socket |
| Gossip + security protocol | UDP `9102` | Signed server messages; state sync; security envelopes |
| STUN | UDP `3478` | External address discovery |
| Relay | UDP `9103` | Fallback mesh forwarding when direct P2P fails |
| DNS | UDP+TCP `5335` local / `53` advertised | Authoritative SEIP zone (DNS-serving nodes; `53` is NAT-mapped) |

### Over the mesh (client plane `10.64.x.x`)

| Traffic | Port | Purpose |
|---------|------|---------|
| Private HTTPS API | TCP `9101` | Tree, IPAM, mesh, routing, relay, certs, onboarding administration — via the in-process netstack to a loopback bridge |

### Server backbone (`172.16.x.x`)

| Traffic | Purpose |
|---------|---------|
| Private API (server-to-server) | Cross-server operations on the same virtual `9101` |
| Mesh data | Encrypted server-to-server traffic over the same UDP socket |

All public services listen on the wildcard address. The private API listens
on loopback plus the virtual tunnel/backbone addresses only.

## Userspace Dataplane

The server terminates WireGuard **entirely in userspace**: BoringTun Noise
sessions plus an in-process smoltcp netstack. Consequences:

- The daemon needs **no root and no capabilities**. Every port it binds is
  unprivileged (9100, 9101, 51940, 9102, 3478, 9103, 5335). Public `53` and
  `443` are reached by firewall/NAT mapping, not by binding.
- Tunnel keys and decrypted plaintext never leave the process.
- Traffic addressed to the virtual addresses is delivered to in-process
  listeners; traffic for other peers is re-encrypted and forwarded in
  userspace.

## Client Connection Flow

```text
1. DNS discovery
   Client -> system DNS -> ns1..ns9 glue -> <region>.seip.<domain>
   A record -> server public IP
   _config TXT -> ports, region, load, host FQDN

2. Public API (TCP 9100, verified HTTPS)
   POST /api/auth/challenge -> Ed25519 nonce
   POST /api/auth           -> identity authentication
   POST /api/join           -> node creation, tunnel IP, mesh config, session JWT

3. Mesh tunnel (UDP 51940)
   BoringTun handshake -> client 10.64.0.x <-> server 10.64.0.1

4. Private API (TCP 9101, via the mesh)
   Tree, mesh, IPAM, routing, relay, certs
```

`POST /api/join` is the composite bootstrap: its response carries the session
JWT, `node_id`, `tunnel_ip`, the server tunnel IP, the mesh server public key,
the mesh endpoint, the private API port, the mesh FQDNs, and the mesh DNS
servers.

The client selects the best server client-side after a health probe of each
discovered candidate (latency plus load scoring), with region fallback.

## Private API Delivery

The delivery pattern (server side):

1. httplib binds a real socket on `127.0.0.1:9101` only.
2. The netstack adds TCP forwards so virtual connections to
   `<tunnel_ip>:9101` (client plane) or the backbone IP are bridged into that
   loopback listener.
3. Every private route is JWT-gated. The private listener uses the
   `private.<id>.<region>.seip.<domain>` certificate.

If a server has **no tunnel address**, no private listener is created and the
private routes are registered on the public server instead. The server logs a
security warning; authentication still applies, network isolation does not.

## Server-to-Server Traffic

```text
Server A (us-west)                    Server B (eu-west)
172.16.0.x                            172.16.0.x
    |                                      |
    |---- Gossip (UDP 9102, public) ----->|
    |     ServerHello: signed certificate |
    |     (with mesh pubkey), advertised  |
    |     endpoint cross-checked against  |
    |     the observed UDP source         |
    |     security envelopes (0x16)       |
    |                                      |
    |---- Mesh backbone (UDP 51940) ----->|
    |     same socket as the client mesh; |
    |     the backbone IP is a second     |
    |     virtual address on the same     |
    |     dataplane                       |
```

Gossip messages are Ed25519-signed. State-mutating gossip ingress requires
the sender to hold a root-signed, non-revoked peer certificate; the
authentication binds to the **signer**, never to the NAT-able endpoint.

Gossip and security envelopes are sent to the peer's mesh endpoint
(advertised `public_ip:gossip_port` when confirmed against the observed
source, otherwise the observed source). They are not routed through the
backbone.

## Security Transport

Security-protocol messages (attestation challenge/evidence, HotStuff
proposal/vote/timeout, DKG broadcast/pairwise, FROST commitment/signature
share, epoch announcements, sync, and genesis/founding records) travel in a
single gossip wire type, `SecurityEnvelope` (0x16):

- Authenticated (signature) and size-bounded **before any parse**; never
  relayed.
- The router applies per-peer message budgets, deduplication, ruleset and
  network checks, and epoch-window validation, then hands the envelope to the
  one security service.
- Sensitive pairwise DKG round-2 payloads are additionally **sealed to the
  recipient identity** (X25519 sealed box) inside the envelope.
- Wire types `0x07`–`0x10` are retired and reserved forever; `0x15` is a
  logged refusal.

Security messages are not all carried inside WireGuard: the gossip plane on
`9102` is a signed UDP transport with its own authentication and bounds.

## DNS Discovery

See [DNS Discovery](DNS-Discovery) for the full record layout. In short:

```text
<id>.<region>.seip.<domain>            A   -> public IP
_config.<id>.<region>.seip.<domain>    TXT -> v=sp1 http= udp= gossip= stun= relay= dns= private_http= region= load= [host=]
private.<id>.<region>.seip.<domain>    A   -> tunnel IP
backend.<id>.<region>.seip.<domain>    A   -> backbone IP
tier1|tier2.<region>.seip.<domain>     A   -> onboarding/seed discovery
ns1..ns9.<domain>                      A   -> bootstrap nameservers
private.<node_id>.ep.<domain>          A   -> client tunnel IP
```

## NAT Traversal

Hole punching **shares the mesh UDP port `51940`** — there is no separate
signaling port. Coordination runs over the private routing API
(`/api/routing/*`), with the server as rendezvous coordinator:

```text
Client A (NAT)          Server (coordinator)          Client B (NAT)
    |                          |                            |
    |-- routing/request ------>|                            |
    |   (B's identifier +      |<--- endpoint/register ----|
    |    A's candidates)       |                            |
    |                          | candidates marked "verified"
    |                          | when they match the observed
    |                          | control-connection source
    |<-- directive: B -------|- directive: A -->|
    |     punch_at = now+1s   |     punch_at = now+1s       |
    |                          |                            |
    |=== simultaneous handshake on UDP 51940 ===============>|
    |<=== direct P2P encrypted mesh tunnel =================>|
```

Path selection is `DirectP2P` when both sides offered a usable candidate;
otherwise the coordinator issues a relay ticket (UDP `9103`). STUN (`3478`)
supplies reflexive candidates.

## SDK Client

`LemonadeNexusSDK` mirrors the server's userspace design on the client:

- `join_network` authenticates (Ed25519 challenge-response with the client
  identity; password is a deprecated fallback stub), calls `/api/join`, and
  brings the BoringTun dataplane up **in-process** — no TUN device, no admin
  rights. The mesh keypair is derived from the authenticated identity.
- Private-API calls ride an egress bridge: the netstack binds an ephemeral
  `127.0.0.1` listener and bridges accepted connections to a virtual TCP
  stream toward the server's `<tunnel_ip>:9101`.
- A background orchestrator refreshes peers, sends heartbeats, and tracks
  liveness.
- **Local service publishing is now exposed:** `expose_service(vport, target)`
  publishes a local service to mesh peers (the daemon bridges
  `our-mesh-IP:vport` to, e.g., `tcp:127.0.0.1:PORT`), and
  `open_egress(dst_ip, dst_port)` opens a loopback bridge to a mesh peer's
  service. Both exist in the C++ API and the C ABI
  (`ln_mesh_expose_service`, `ln_mesh_open_egress`).
- Session tokens are per-server JWTs; surviving a dead server means fresh DNS
  discovery plus re-join with the preserved identity.
