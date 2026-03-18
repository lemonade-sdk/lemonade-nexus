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

2. Public API (HTTPS :9100)
   Client ──POST /api/auth──> Server  (Ed25519 challenge-response)
   Client ──POST /api/join──> Server  (allocate IP, get WG config)

3. WireGuard Tunnel (UDP :51940)
   Client ──WG handshake──> Server
   Client <──WG keepalive (5s)──> Server
   Tunnel established: client 10.64.0.10 ↔ server 10.64.0.1

4. Private API (HTTPS :9101 over WG tunnel)
   Client ──GET /api/tree/children/root──> Server (via tunnel)
   Client ──POST /api/mesh/heartbeat──> Server (via tunnel)
```

## Server-to-Server Backbone

```
Server A (us-west)                    Server B (eu-west)
172.16.0.66                           172.16.0.120
    |                                      |
    │──── Gossip (UDP :9102) ──────────────│  (public internet)
    │     ServerHello exchange              │
    │     Share WG pubkeys + backbone IPs   │
    │                                      │
    │──── WG Backbone (UDP :51940) ────────│  (encrypted tunnel)
    │     172.16.0.66 ↔ 172.16.0.120      │
    │     Backend API, gossip preferred    │
    │                                      │
    │──── IPAM Sync (via gossip) ──────────│
    │     BackboneIpamSync (0x13)          │
    │     NsSlotClaim (0x14)              │
```

## DNS Discovery (SEIP)

```
                   lemonade-nexus.io
                         |
                    NS Records
                   /     |     \
              ns1        ns2       ns3
           us-west    eu-west   ap-south
                |
           SEIP Records
          /            \
   A: server-xxx.     _config.server-xxx.
   us-west.seip.      us-west.seip.
   lemonade-nexus.io  lemonade-nexus.io
   → 67.204.56.242    → v=sp1 http=9100 ...
                          region=us-west load=5
```

**Client selects best server:**
```
Score = latency_ms + (load × 10)

Server A: 30ms latency, 5 clients  → score = 80
Server B: 90ms latency, 2 clients  → score = 110
Server C: 25ms latency, 20 clients → score = 225

Winner: Server A (lowest score)
```

## NAT Traversal (Hole Punch)

```
Client A (behind NAT)              Server              Client B (behind NAT)
    |                                 |                      |
    │── Connect to :51941 ──────────>│                      │
    │   Server sees: 1.2.3.4:54321   │                      │
    │                                 │<── Connect to :51941 │
    │                                 │   Server sees: 5.6.7.8:12345
    │                                 │                      │
    │<── "Client B is at             │── "Client A is at   >│
    │     5.6.7.8:12345"             │    1.2.3.4:54321"    │
    │                                 │                      │
    │────── WG handshake (direct) ────────────────────────>│
    │<─────────────────────────────── WG handshake ────────│
    │                                                       │
    │<═══════════ Direct P2P WireGuard Tunnel ════════════>│
    │           No server in the middle                     │
```

## Traffic Planes

### Public Internet
| Traffic | Port | Purpose |
|---------|------|---------|
| Public HTTPS API | TCP :9100 | Bootstrap, auth, join, discovery |
| WireGuard | UDP :51940 | Encrypted tunnel establishment + data |
| Hole Punch | UDP :51941 | NAT traversal signaling |
| Gossip | UDP :9102 | Server state sync |
| STUN | UDP :3478 | External IP discovery |
| Relay | UDP :9103 | Fallback WG forwarding |
| DNS | UDP :53/5353 | Authoritative zone |

### Over WireGuard Tunnel (10.64.x.x)
| Traffic | Port | Purpose |
|---------|------|---------|
| Private HTTPS API | TCP :9101 | Tree, IPAM, mesh, certs, governance |
| Shamir key shares | Via gossip | Root key distribution |
| TEE challenges | Via gossip | Mutual hardware attestation |

### Server Backbone (172.16.0.x)
| Traffic | Purpose |
|---------|---------|
| Backend HTTPS | Server-to-server API calls |
| Gossip (preferred) | State sync over encrypted backbone |
