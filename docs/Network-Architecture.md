---
layout: default
title: Network Architecture
---

# Network Architecture

## Network Topology

```
                           Internet
                              |
         ┌────────────────────┼────────────────────┐
         |                    |                    |
    [Server 1]           [Server 2]          [Server 3]
    us-west               eu-west             ap-south
    ns1                   ns2                 ns3
    67.204.56.242         185.x.x.x           103.x.x.x
    Tunnel: 10.64.0.1    Tunnel: 10.64.0.1   Tunnel: 10.64.0.1
    BB: 172.16.0.66      BB: 172.16.0.120    BB: 172.16.0.45
         |                    |                    |
         └──── WG Backbone (172.16.0.0/22) ────────┘
              Encrypted server-to-server mesh
         |                    |                    |
    ┌────┴────┐          ┌───┴────┐          ┌───┴────┐
    |         |          |        |          |        |
  [Mac]    [Linux]    [Phone]  [PC]       [IoT]   [Laptop]
  .10       .11        .10      .11        .10      .11
         Client Tunnels (10.64.0.0/10)
           Per-server IP allocation
```

## Connection Flow: Client → Server

```
1. DNS Discovery
   Client ──getaddrinfo──> System DNS ──NS──> ns1.lemonade-nexus.io
   Client ──A query──> us-west.seip.lemonade-nexus.io → 67.204.56.242
   Client ──TXT query──> _config... → ports + region + load

2. Public API (TCP :9100 — plain HTTP on first boot, HTTPS once ACME issues)
   Client ──POST /api/auth/challenge──> Server  (one-time Ed25519 nonce)
   Client ──POST /api/join──> Server  (signed challenge; creates tree node,
                                       allocates tunnel IP, returns mesh config)

3. Mesh Tunnel (UDP :51940)
   Client ──WG handshake──> Server
   Client <──WG keepalive (5s)──> Server
   Tunnel established: client 10.64.0.10 ↔ server 10.64.0.1

4. Private API (TCP :9101, reachable only through the tunnel)
   Client ──GET /api/tree/children/root──> Server (via tunnel)
   Client ──POST /api/mesh/heartbeat──> Server (via tunnel)
```

`POST /api/join` is the whole bootstrap in one call. Its response carries the
session JWT, `node_id`, `tunnel_ip` + `tunnel_subnet` (10.64.0.0/10),
`server_tunnel_ip`, `wg_server_pubkey`, `wg_endpoint`, `private_api_port`,
the server/client mesh FQDNs and the mesh DNS servers
(`TreeApiHandler.cpp`).

Besides join/auth, the public API serves only liveness and discovery reads
(`GET /api/health`, `/api/stats`, `/api/servers`, `/api/tls/status`) and the
`/api/onboard/*` server-admission flow. Everything a member does after joining
— tree sync, heartbeats, IPAM, routing, relay tickets, certs, governance —
moves to the private API over the tunnel.

## Server-to-Server Backbone

```
Server A (us-west)                    Server B (eu-west)
172.16.0.66                           172.16.0.120
    |                                      |
    │──── Gossip (UDP :9102) ──────────────│  (public internet)
    │     ServerHello exchange: signed     │
    │     server certificate (incl. WG     │
    │     pubkey) + advertised endpoint;   │
    │     mutual TEE challenge follows     │
    │                                      │
    │──── WG Backbone (UDP :51940) ────────│  (same socket as the client
    │     172.16.0.66 ↔ 172.16.0.120      │   mesh — the backbone IP is a
    │     Private API, gossip preferred    │   second virtual address on
    │                                      │   the same dataplane)
    │──── IPAM Sync (via gossip) ──────────│
    │     BackboneIpamSync (0x13)          │
    │     NsSlotClaim (0x14)              │
```

Sensitive server-to-server payloads are dedicated gossip message types:
Shamir root-key shares (`ShamirShareOffer`/`Submit`, 0x0C/0x0D) and TEE
attestation challenges (`TeeChallenge`/`Response`, 0x07/0x08). Gossip prefers
the encrypted backbone once it is up.

## DNS Discovery (SEIP)

```
                   lemonade-nexus.io
                         |
                    NS Records
                   /     |     \
              ns1        ns2       ns3     (first nine servers claim
           us-west    eu-west   ap-south    ns1–ns9 via NsSlotClaim)
                |
           SEIP Records
          /            \
   A: server-xxx.     _config.server-xxx.
   us-west.seip.      us-west.seip.
   lemonade-nexus.io  lemonade-nexus.io
   → 67.204.56.242    → v=sp1 http=9100 ...
                          region=us-west load=5
```

The `_config` TXT record carries every advertised port plus placement data:

```
v=sp1 http=9100 udp=51940 gossip=9102 stun=3478 relay=9103 dns=53
private_http=9101 region=us-west load=5
```

**Client selects best server** (scored client-side during discovery, after a
health probe of each candidate):

```
Score = latency_ms + (load × 10)

Server A: 30ms latency, 5 clients  → score = 80
Server B: 90ms latency, 2 clients  → score = 110
Server C: 25ms latency, 20 clients → score = 225

Winner: Server A (lowest score)
```

## NAT Traversal (Hole Punch)

Hole punching shares the mesh UDP port (:51940) — there is no separate
signaling port. Coordination runs over the private routing API
(`/api/routing/*`), with the server acting as rendezvous coordinator:

```
Client A (behind NAT)         Server (coordinator)       Client B (behind NAT)
    |                               |                             |
    │── POST /api/routing/request ─>│                             │
    │   (B's identifier + A's       │<── /api/routing/endpoint/   │
    │    candidates: local +        │    register (B's candidates │
    │    STUN-witnessed reflexive)  │    + reflexive address)     │
    │                               │                             │
    │                     candidates are marked "verified"        │
    │                     when they match the observed            │
    │                     control-connection source               │
    │                               │                             │
    │<── directive: B's candidates ─│─ directive: A's candidates >│
    │    punch_at = now + 1s        │    punch_at = now + 1s      │
    │                               │                             │
    │──────── simultaneous WG handshake on UDP :51940 ──────────>│
    │<────────────────────────────────────────────────────────────│
    │                                                             │
    │<═══════════ Direct P2P encrypted mesh tunnel ══════════════>│
    │              No server in the middle                        │
```

Path selection is `DirectP2P` when both sides offered a usable candidate,
otherwise the coordinator issues a relay ticket (UDP :9103). Between servers,
each ServerHello carries an *advertised* `public_ip:gossip_port`; third-party
peer exchange shares that advertised endpoint rather than the observed UDP
source, while direct replies still use the observed source.

## Userspace dataplane

The server terminates WireGuard **entirely in userspace** (boringtun Noise
sessions + an in-process smoltcp netstack). There is no kernel WireGuard
interface and no TUN device on the server, so:

- The daemon needs **no root and no `CAP_NET_ADMIN`** — only `CAP_NET_BIND_SERVICE`
  to bind privileged ports (HTTP/DNS).
- Tunnel keys and decrypted plaintext never leave the process; host-level tools
  (`wg show`, `tcpdump` on an interface) cannot observe mesh traffic.
- Both the client plane (`10.64.0.0/10`) and the server backbone
  (`172.16.0.0/22`) are virtual addresses that exist only inside the daemon.
  Traffic addressed to them is delivered to in-process listeners; traffic for
  other peers is re-encrypted and forwarded in userspace.

The private API shows the delivery pattern: httplib binds a real socket on
`127.0.0.1:9101` only, and the netstack adds TCP forwards so virtual
connections to `10.64.0.1:9101` (tunnel) or the backbone IP are bridged into
that loopback listener (`main.cpp` / `VirtualNetService::add_tcp_forward`).
Every private route is JWT-gated. If a server has no tunnel address, private
routes fall back onto the public server — logged as a security warning.

Clients are unaffected on the wire — same WireGuard protocol, same UDP :51940,
same `/api/join` contract.

## The SDK client (LemonadeNexusSDK)

The client side mirrors the server's userspace design. `LemonadeNexusSDK`
(C ABI, `ln_*` functions, driven by the desktop/mobile app over FFI) is a
consumer-only mesh client:

- `ln_join_network` authenticates (Ed25519 challenge-response, or
  password/passkey/token), calls `/api/join`, and brings the boringtun tunnel
  up **in-process** — no TUN device, no admin rights. Fresh Curve25519 mesh
  keys are generated on every join; only the Ed25519 identity
  (`identity.json`) and session token persist.
- Private-API calls ride an egress bridge: the netstack binds an ephemeral
  `127.0.0.1` listener and bridges accepted connections to a virtual TCP
  stream toward `<server_tunnel_ip>:9101` (`BoringtunMesh::tcp_egress`).
- A background `MeshOrchestrator` refreshes peers (`GET /api/mesh/peers`),
  sends heartbeats and tracks liveness; host apps poll `ln_mesh_status`.
- Session tokens are per-server JWTs, so surviving a dead server means fresh
  DNS discovery + re-join with the preserved identity (the app's recovery
  loop does exactly this on health-probe failure).
- The netstack's ingress primitive (`ns_add_tcp_forward` — the same call the
  server uses to publish its private API on the tunnel IP) is **not yet
  surfaced through the SDK**; exposing a local service to mesh peers requires
  wiring it into `BoringtunMesh` and the C ABI.

## Traffic Planes

### Public Internet
| Traffic | Port | Purpose |
|---------|------|---------|
| Public HTTP(S) API | TCP :9100 | Bootstrap, auth, join, discovery; HTTP until ACME issues, then HTTPS |
| Mesh + hole punch (boringtun) | UDP :51940 | Client tunnels, server backbone and NAT traversal — one shared socket |
| Gossip | UDP :9102 | Server state sync, ServerHello, TEE challenges, Shamir shares |
| STUN | UDP :3478 | External IP discovery |
| Relay | UDP :9103 (binds `[::]`) | Fallback mesh forwarding |
| DNS | UDP :5335 listen / :53 advertised | Authoritative SEIP zone (UDP only; 53 is NAT-mapped externally) |

### Over Mesh Tunnel (10.64.x.x)
| Traffic | Port | Purpose |
|---------|------|---------|
| Private HTTPS API | TCP :9101 | Tree, IPAM, mesh, routing, relay, certs, governance — via in-process netstack → loopback bridge |

### Server Backbone (172.16.0.x)
| Traffic | Purpose |
|---------|---------|
| Private API (server-to-server) | Cross-server brokering/admin on the same :9101 virtual listener |
| Gossip (preferred) | State sync over the encrypted backbone |

All public services listen on the wildcard address; the private API listens
on loopback plus the virtual tunnel/backbone addresses only.
