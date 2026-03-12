# Lemonade-Nexus

A self-hosted, cryptographically secure WireGuard mesh VPN with zero-trust architecture, federated relay servers, and democratic governance.

## Features

- **Zero-trust two-tier security** — TEE hardware attestation (SGX/TDX/SEV-SNP/Secure Enclave) for Tier 1 authority; certificate-based Tier 2 for all servers
- **Ed25519 identity** — every server and client has a unique keypair; all gossip messages and deltas are signed
- **Root key rotation** — automatic weekly rotation with chain-of-trust endorsement
- **Shamir's Secret Sharing** — root private key distributed to 100% of Tier 1 peers; 75% quorum can reconstruct (25% fault tolerance)
- **Peer health gating** — only servers with >= 90% uptime qualify for Tier 1 authority
- **Democratic governance** — protocol parameters (rotation interval, quorum ratio, uptime threshold) can only change via Tier 1 majority vote
- **Quorum-based enrollment** — new servers need root certificate + Tier 1 peer votes
- **Binary attestation** — signed release manifests verify server binary integrity; auto-fetched from GitHub releases
- **UDP gossip protocol** — epidemic-style state sync, peer exchange, health reporting
- **WireGuard mesh** — automatic tunnel establishment with STUN hole-punching and relay fallback
- **Federated relay servers** — community relays see only ciphertext; geo-aware selection
- **IPAM** — automatic /10 tunnel IP allocation, private subnets, shared blocks
- **ACME certificates** — automatic TLS via Let's Encrypt or ZeroSSL; server issues certs for clients
- **Distributed authoritative DNS** — every Tier 1 peer serves the same DNS zone via gossip-synced records; ACME DNS-01 challenges served locally
- **Dynamic DNS** — automatic Namecheap DDNS updates for enrolled servers
- **Permission tree** — hierarchical ACL with signed deltas and gossip propagation
- **WebAuthn passkeys** — passwordless authentication for management
- **Dual HTTP server** — public API for bootstrap, private VPN-only API for sensitive operations
- **Client SDK** — C++ and C APIs for joining the mesh, with WireGuard tunnel management and latency-based auto-switching
- **No database** — all state stored as signed JSON files on disk

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Lemonade-Nexus Server                     │
├───────────────────┬──────────────────────────────────────┤
│ Public API :9100  │  Private API :<tunnel_ip>:9101       │
│ (bootstrap)       │  (VPN-only, auto-enabled)            │
├───────────────────┴──────────────────────────────────────┤
│  Auth  ACL  Tree  IPAM  ACME  Relay  DDNS  DNS           │
├──────────────────────────────────────────────────────────┤
│  Trust Policy  TEE Attestation  Binary Attestation        │
├──────────────────────────────────────────────────────────┤
│  Root Key Chain  Governance  Shamir SSS  Enrollment       │
├──────────────────────────────────────────────────────────┤
│  Gossip (:9102) STUN (:3478) WG+HolePunch (:51940) Relay │
├──────────────────────────────────────────────────────────┤
│  Crypto (libsodium + OpenSSL)    Storage (file-based)     │
└──────────────────────────────────────────────────────────┘
```

All services use **CRTP** (Curiously Recurring Template Pattern) — zero virtual dispatch overhead.

### Dual HTTP Server

The server runs two HTTP listeners:

- **Public API** (`0.0.0.0:9100`) — available before VPN is established. Handles health checks, authentication, server discovery, and the initial `/api/join` bootstrap.
- **Private API** (`<tunnel_ip>:9101`) — only accessible over the WireGuard VPN tunnel. Handles all sensitive operations: tree mutations, IPAM, relay, certificates, governance.

The private API activates automatically once the server receives a tunnel IP — no configuration required. The first server in the mesh (genesis) self-allocates; joining servers receive their IP from an existing peer during the gossip ServerHello exchange.

## Network Requirements

### Ports

Open the following ports on each server's firewall/security group/ACL:

| Port | TCP/UDP | Direction | Source | Service | Required |
|------|---------|-----------|--------|---------|----------|
| 9100 | **TCP** | Inbound | Any (servers + clients) | Public HTTP API (bootstrap, health, join) | Yes |
| 9102 | **UDP** | Inbound | Mesh servers only | Gossip protocol (peer sync, state replication) | Yes |
| 3478 | **UDP** | Inbound | Mesh servers only | STUN (NAT traversal, external IP discovery) | Yes |
| 51940 | **UDP** | Inbound | Mesh servers + clients | WireGuard tunnel + UDP hole-punching | Yes |
| 9103 | **UDP** | Inbound | Mesh servers | Relay (forwarded WireGuard traffic) | Only if relay server |
| 53 | **UDP** | Inbound | Internet / mesh | Authoritative DNS (Tier 1 servers only) | Optional |

> **Note on port 9101**: The Private HTTP API (TCP :9101) binds to the **WireGuard tunnel IP** (10.64.x.x), not the external interface. It does **not** need a firewall rule — it is only reachable over the encrypted WireGuard tunnel.

**Firewall rule summary (minimum required):**
```
# Required on every server
ALLOW TCP  9100  IN   FROM any             # Public API (client bootstrap)
ALLOW UDP  9102  IN   FROM <mesh-servers>   # Gossip protocol
ALLOW UDP  3478  IN   FROM <mesh-servers>   # STUN NAT traversal
ALLOW UDP 51940  IN   FROM any             # WireGuard tunnels

# Optional
ALLOW UDP  9103  IN   FROM <mesh-servers>   # Relay (only if acting as relay)
ALLOW UDP    53  IN   FROM any             # DNS (only Tier 1 servers)
```

> Port **9100/tcp** and **51940/udp** should allow `any` source since clients may connect from unknown IPs. Gossip (**9102/udp**) and STUN (**3478/udp**) can be restricted to known mesh server IPs if desired.

### IP Addresses

Lemonade-Nexus uses three types of addresses:

| Address | How it's determined | Purpose |
|---------|-------------------|---------|
| **External (public) IP** | Auto-detected via STUN reflexive address and DDNS `detect_public_ip()` | Gossip seed peers, STUN, client connections |
| **Bind address** | `--bind-address` / `SP_BIND_ADDRESS` (default: `0.0.0.0`) | What interfaces the server listens on |
| **Tunnel IP** | Auto-allocated by IPAM from `10.64.0.0/10` | WireGuard mesh traffic, private API binding |

- **No manual external IP config needed** — the server discovers its public IP automatically via STUN and HTTP-based detection.
- **Seed peers** use the external IP: `--seed-peer <public-ip>:9102`
- **Private API** binds to the tunnel IP automatically once IPAM assigns one.
- **Clients** connect to the server's public IP on port 9100 to bootstrap, then switch to the WireGuard tunnel for all subsequent traffic.

### Traffic Flow: Public Internet vs WireGuard Tunnel

The system separates traffic into two planes:

**Over the public internet (external IPs):**

| Traffic | Protocol | Who | Purpose |
|---------|----------|-----|---------|
| Gossip | UDP :9102 | Server ↔ Server | Peer discovery, state sync, health, enrollment |
| STUN | UDP :3478 | Server ↔ Server | NAT traversal, external IP discovery |
| WireGuard handshake | UDP :51940 | Server ↔ Server, Client ↔ Server | Encrypted tunnel establishment |
| Public HTTP API | TCP :9100 | Client → Server | Bootstrap: auth, join, health, server list |
| Relay forwarding | UDP :9103 | Server ↔ Relay | Encrypted WireGuard packets when direct fails |
| DDNS updates | HTTPS outbound | Server → Namecheap | Dynamic DNS registration |

**Over the WireGuard tunnel (10.64.x.x mesh):**

| Traffic | Protocol | Who | Purpose |
|---------|----------|-----|---------|
| Private HTTP API | TCP :9101 | Server ↔ Server, Client → Server | Tree mutations, IPAM, certs, governance, relay tickets |
| Shamir key shares | Via gossip | Server ↔ Server (Tier 1) | Root key distribution and reconstruction |
| TEE attestation challenges | Via gossip | Server ↔ Server | Mutual hardware attestation verification |
| DNS zone sync | Via gossip | Server ↔ Server (Tier 1) | Authoritative DNS record replication |
| Application traffic | Any | Client ↔ Client, Client ↔ Server | User application data |

> **Key principle**: Only bootstrap and peer discovery happen over the public internet. All sensitive operations (tree changes, IP allocation, certificate issuance, governance votes, key shares) happen exclusively over the encrypted WireGuard tunnel.

### Servers vs Endpoints (Clients)

| | Servers | Endpoints (Clients) |
|---|---------|-------------------|
| **Role** | Infrastructure — run the mesh | Devices/apps that use the mesh |
| **Ports needed** | All inbound ports listed above | No inbound ports (outbound only) |
| **Identity** | Server certificate signed by root key | Ed25519 keypair + node in permission tree |
| **Gossip** | Full participant (send + receive) | Does not participate |
| **IPAM** | Allocates IPs to peers and clients | Receives a tunnel IP during join |
| **Trust tier** | Tier 1 (TEE+attestation) or Tier 2 (cert-only) | N/A — not part of trust hierarchy |
| **WireGuard** | Mesh tunnels to all peers + client tunnels | Single tunnel to one server (auto-switches) |
| **Private API** | Serves it and calls other servers' | Calls server's private API over tunnel |
| **Built with** | `LemonadeNexus` (server binary) | `LemonadeNexusSDK` (C++/C library) |

### Connectivity Diagram

```
              Public Internet (external IPs)
                         │
     ┌───────────────────┼───────────────────┐
     │                   │                   │
┌────▼────┐        ┌─────▼─────┐       ┌─────▼─────┐
│Server A │◄──────►│ Server B  │◄─────►│ Server C  │
│ Tier 1  │gossip  │  Tier 1   │gossip │  Tier 2   │
│         │:9102   │           │:9102  │           │
└────┬────┘        └─────┬─────┘       └─────┬─────┘
     │                   │                   │
     └──────┬────────────┼────────────┬──────┘
            │  WireGuard mesh (10.64.x.x)    │
            │  Private API :9101 over tunnel │
            │                                │
     ┌──────▼──────┐               ┌─────────▼──┐
     │  Client 1   │               │  Client 2   │
     │ (laptop)    │               │ (phone)     │
     │ joins :9100 │               │ joins :9100 │
     │ then tunnel │               │ then tunnel │
     └─────────────┘               └─────────────┘
```

1. **Server-to-server**: All servers must reach each other on ports 9102/udp (gossip) and 51940/udp (WireGuard). STUN hole-punching handles NAT traversal automatically.
2. **Client-to-server**: Clients connect to any server's public IP on port 9100/tcp to bootstrap (authenticate, get tunnel IP, receive WireGuard config), then all subsequent communication goes over the encrypted WireGuard tunnel.
3. **NAT traversal**: Servers behind NAT use the built-in STUN service (port 3478) to discover their external address and UDP hole-punching to establish direct WireGuard tunnels. If direct connection fails, traffic falls back through a relay server.
4. **Endpoints need no open ports**: Clients only make outbound connections — they initiate the WireGuard handshake and the tunnel handles the rest.

## Quick Start

### Prerequisites

- C++20 compiler (GCC 12+ or Clang 15+)
- CMake 3.25.1+
- Ninja (recommended)
- OpenSSL 3.0+

### Build

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Test

```bash
ctest --test-dir build --output-on-failure
# 277 tests across 14+ test suites
```

### Generate Root Keypair

```bash
python3 scripts/generate_root_keypair.py
# Outputs hex public key for --root-pubkey
```

### Run the Genesis Server

The first server in the mesh needs a root keypair:

```bash
./build/projects/LemonadeNexus/lemonade-nexus \
    --root-pubkey <hex-pubkey> \
    --data-root ./data
```

On startup it will:
1. Generate an Ed25519 identity
2. Self-allocate a tunnel IP from IPAM (e.g. `10.64.0.0`)
3. Start the public API on `:9100` and private API on `<tunnel_ip>:9101`
4. Begin listening for gossip peers

### Enroll and Join a Server

```bash
# 1. On the root server: generate a certificate for the new server
./build/projects/LemonadeNexus/lemonade-nexus \
    --enroll-server <new-server-hex-pubkey> <server-id>

# 2. Copy data/identity/server_cert.json to the new server's data/identity/

# 3. Start the new server with the root server as a seed peer
./build/projects/LemonadeNexus/lemonade-nexus \
    --root-pubkey <hex-pubkey> \
    --seed-peer <root-ip>:9102 \
    --data-root ./data
```

The joining server will:
1. Connect to the seed peer via gossip
2. Exchange ServerHello with its certificate
3. Receive a tunnel IP allocation from the existing peer
4. Automatically start the private API on the assigned IP
5. Sync tree state, IPAM, and peer information via gossip

## Client SDK

The **LemonadeNexusSDK** provides a C++ and C API for endpoints (devices/applications) to join and participate in the mesh.

### C++ API

```cpp
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/WireGuardTunnel.hpp>

// Connect to a server
lnsdk::ServerConfig config;
config.host = "server.example.com";
config.port = 9100;
lnsdk::LemonadeNexusClient client(config);

// Generate and set an identity
lnsdk::Identity identity;
identity.generate();
client.set_identity(identity);

// Join the network (authenticates, creates node, allocates tunnel IP)
auto result = client.join_network("username", "password");
if (result) {
    // WireGuard tunnel is automatically configured and brought up
    std::cout << "Node ID: " << result->node_id << "\n";
    std::cout << "Tunnel IP: " << result->tunnel_ip << "\n";
}

// All subsequent API calls go over the VPN tunnel automatically
auto node = client.get_tree_node(result->node_id);
auto health = client.check_health();

// Enable latency-based auto-switching (optional)
client.enable_auto_switching(); // 200ms threshold, 30% hysteresis, 60s cooldown

// Request a TLS certificate for this client
auto cert = client.request_certificate("my-laptop");
if (cert) {
    auto decrypted = client.decrypt_certificate(*cert);
    // decrypted->fullchain_pem, decrypted->privkey_pem
}

// Leave the network
client.leave_network();
```

### C API (FFI)

The C API enables bindings from Python, Go, Rust, Swift, and other languages:

```c
#include <lemonade_nexus.h>

// Create client and identity
ln_client_t* client = ln_create("server.example.com", 9100);
ln_identity_t* identity = ln_identity_generate();
ln_set_identity(client, identity);

// Join the network
char* join_json = NULL;
ln_error_t err = ln_join_network(client, "user", "pass", &join_json);
if (err == LN_OK) {
    printf("Joined: %s\n", join_json);
    ln_free(join_json);
}

// Bring up WireGuard tunnel
char* tunnel_json = NULL;
ln_tunnel_up(client, &tunnel_json);
ln_free(tunnel_json);

// Enable auto-switching
ln_enable_auto_switching(client, 200.0, 0.3, 60);

// Use the API
char* health_json = NULL;
ln_health(client, &health_json);
printf("Health: %s\n", health_json);
ln_free(health_json);

// Check latency
double latency = ln_current_latency_ms(client);
printf("Current latency: %.1f ms\n", latency);

// Cleanup
ln_tunnel_down(client);
ln_identity_destroy(identity);
ln_destroy(client);
```

### WireGuard Tunnel

The SDK includes cross-platform WireGuard tunnel management:

| Platform | Implementation |
|----------|---------------|
| Linux | `wg-quick` / kernel WireGuard |
| macOS | `wireguard-go` via utun |
| Windows | `wireguard.exe` / `wireguard-nt` |
| iOS | Config-only — app uses `NETunnelProviderManager` |
| Android | Config-only — app uses `VpnService` |

On mobile platforms (iOS/Android), the SDK generates the WireGuard config string and the host app manages the VPN lifecycle through the OS APIs.

### Latency-Based Auto-Switching

The SDK monitors server latency and automatically switches to a faster server:

- **EMA smoothing** — alpha=0.3 exponential moving average on RTT
- **200ms threshold** — triggers switch evaluation when exceeded
- **30% hysteresis** — new server must be at least 30% faster
- **60s cooldown** — minimum time between switches
- **Background probing** — periodically checks all known servers

### Client TLS Certificates

Clients can request TLS certificates for their hostname (e.g., `my-laptop.capi.lemonade-nexus.io`):

1. Client calls `request_certificate("my-laptop")`
2. Server obtains the cert from Let's Encrypt/ZeroSSL via ACME DNS-01
3. Server encrypts the private key using X25519 DH + HKDF + AES-256-GCM with the client's Ed25519 public key
4. Client decrypts with `decrypt_certificate()` to get the PEM files

## Configuration

Configuration priority: **environment variables > CLI args > config file > compiled defaults**

Use `--config <path>` to specify a JSON config file (default: `lemonade-nexus.json`). Every option below can be set via CLI flag, environment variable, or JSON key.

### Network Ports

All ports are fully configurable at runtime — no recompilation needed.

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--http-port <N>` | `SP_HTTP_PORT` | `http_port` | `9100` | Public HTTP API (TCP) |
| `--udp-port <N>` | `SP_UDP_PORT` | `udp_port` | `51940` | WireGuard tunnel + UDP hole-punching |
| `--gossip-port <N>` | `SP_GOSSIP_PORT` | `gossip_port` | `9102` | Gossip protocol (UDP) |
| `--stun-port <N>` | `SP_STUN_PORT` | `stun_port` | `3478` | STUN NAT traversal (UDP) |
| `--relay-port <N>` | `SP_RELAY_PORT` | `relay_port` | `9103` | Relay forwarding (UDP) |
| `--dns-port <N>` | `SP_DNS_PORT` | `dns_port` | `53` | Authoritative DNS (UDP) |
| `--private-http-port <N>` | `SP_PRIVATE_HTTP_PORT` | `private_http_port` | `9101` | Private API, binds to tunnel IP (TCP) |
| `--bind-address <addr>` | `SP_BIND_ADDRESS` | `bind_address` | `0.0.0.0` | Listen address for all services |

> All 7 ports must be unique and non-zero. The private HTTP port binds to the WireGuard tunnel IP, not the external interface.

**Example — change ports via CLI:**
```bash
lemonade-nexus --http-port 8443 --udp-port 41820 --gossip-port 8102 --relay-port 8103
```

**Example — change ports via environment:**
```bash
SP_HTTP_PORT=8443 SP_UDP_PORT=41820 SP_GOSSIP_PORT=8102 lemonade-nexus
```

**Example — change ports via JSON config (`lemonade-nexus.json`):**
```json
{
  "http_port": 8443,
  "udp_port": 41820,
  "gossip_port": 8102,
  "stun_port": 3478,
  "relay_port": 8103,
  "dns_port": 5353,
  "private_http_port": 9101
}
```

### Server Identity & Auth

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--root-pubkey <hex>` | `SP_ROOT_PUBKEY` | `root_pubkey` | | Root Ed25519 public key (hex) |
| `--rp-id <domain>` | `SP_RP_ID` | `rp_id` | `lemonade-nexus.local` | Relying Party ID for WebAuthn passkeys |
| | `SP_JWT_SECRET` | `jwt_secret` | (auto-generated) | JWT signing secret |

### Storage & Logging

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--data-root <path>` | `SP_DATA_ROOT` | `data_root` | `data` | Data directory for all state files |
| `--log-level <level>` | `SP_LOG_LEVEL` | `log_level` | `info` | Log level: `trace` / `debug` / `info` / `warn` / `error` |
| `--config <path>` | | | `lemonade-nexus.json` | JSON config file path |

### Gossip & Peer Discovery

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--seed-peer <host:port>` | `SP_SEED_PEERS` | `seed_peers` | | Gossip seed peers (CLI: repeatable; env: comma-separated) |
| | | `gossip_interval_sec` | `5` | Seconds between gossip rounds |
| | | `rate_limit_rpm` | `120` | API rate limit: requests per minute |
| | | `rate_limit_burst` | `20` | API rate limit: burst size |

### TLS & ACME Certificates

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| | | `tls_cert_path` | | Path to TLS certificate file |
| | | `tls_key_path` | | Path to TLS private key file |
| | `SP_ACME_PROVIDER` | `acme_provider` | `letsencrypt` | ACME provider: `letsencrypt` / `letsencrypt_staging` / `zerossl` |
| | `ACME_EMAIL` | | | Contact email for ACME registration |
| | `ZEROSSL_EAB_KID` | | | ZeroSSL External Account Binding key ID |
| | `ZEROSSL_EAB_HMAC_KEY` | | | ZeroSSL EAB HMAC key |
| | `CLOUDFLARE_API_TOKEN` | | | Cloudflare API token (for DNS-01 challenges) |

### DNS Configuration

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--dns-base-domain <dom>` | `SP_DNS_BASE_DOMAIN` | `dns_base_domain` | `lemonade-nexus.io` | DNS zone suffix for network records |
| `--dns-ns-hostname <fqdn>` | `SP_DNS_NS_HOSTNAME` | `dns_ns_hostname` | | This server's NS hostname (e.g. `ns1.example.com`) |
| `--dns-provider <name>` | `SP_DNS_PROVIDER` | `dns_provider` | `local` | DNS provider: `local` (self-hosted) or `cloudflare` |

### Dynamic DNS (DDNS)

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--ddns-domain <domain>` | `SP_DDNS_DOMAIN` | `ddns_domain` | | Base domain for DDNS (e.g. `example.com`) |
| `--ddns-password <pass>` | `SP_DDNS_PASSWORD` | `ddns_password` | | Namecheap DDNS password (root server only) |
| `--ddns-enabled` | `SP_DDNS_ENABLED` | `ddns_enabled` | `false` | Enable dynamic DNS updates |
| | | `ddns_update_interval_sec` | `300` | DDNS update interval (seconds) |

### Binary Attestation

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--release-signing-pubkey <b64>` | `SP_RELEASE_SIGNING_PUBKEY` | `release_signing_pubkey` | | Base64 Ed25519 pubkey for release manifest verification |
| `--require-attestation` | `SP_REQUIRE_ATTESTATION` | `require_binary_attestation` | `false` | Require matching manifest for credential distribution |
| `--github-releases-url <url>` | `SP_GITHUB_RELEASES_URL` | `github_releases_url` | | GitHub API URL for fetching release manifests |
| `--manifest-fetch-interval <sec>` | `SP_MANIFEST_FETCH_INTERVAL` | `manifest_fetch_interval_sec` | `3600` | How often to check GitHub (seconds) |
| `--minimum-version <semver>` | `SP_MINIMUM_VERSION` | `minimum_version` | | Minimum binary version allowed (e.g. `1.2.0`) |
| | `SP_GITHUB_TOKEN` | | | GitHub API token for higher rate limits |

### TEE Attestation & Trust

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--require-tee` | `SP_REQUIRE_TEE` | `require_tee_attestation` | `false` | Require TEE hardware attestation for Tier 1 |
| `--tee-platform <name>` | `SP_TEE_PLATFORM` | `tee_platform_override` | (auto-detect) | Force TEE platform: `sgx` / `tdx` / `sev-snp` / `secure-enclave` |
| | | `tee_attestation_validity_sec` | `3600` | TEE report validity period (seconds) |

### Quorum-Based Enrollment

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--require-peer-confirmation` | `SP_REQUIRE_PEER_CONFIRMATION` | `require_peer_confirmation` | `false` | Require Tier 1 peer votes before full admission |
| `--enrollment-quorum <ratio>` | `SP_ENROLLMENT_QUORUM` | `enrollment_quorum_ratio` | `0.5` | Fraction of Tier 1 peers needed (50%) |
| | | `enrollment_vote_timeout_sec` | `60` | Vote collection window (seconds) |
| | | `enrollment_max_retries` | `3` | Retries before permanent rejection |

### CLI-Only Commands (non-server modes)

| CLI Flag | Description |
|----------|-------------|
| `--enroll-server <hex> <id>` | Sign a certificate for a new server's pubkey |
| `--revoke-server <hex>` | Revoke a server by its pubkey |
| `--add-manifest <path>` | Import a signed release manifest JSON |
| `--help`, `-h` | Show usage |

### Protocol Constants (governed by Tier 1 vote)

These cannot be set via config — they can only change through democratic governance:

| Parameter | Default | Range |
|-----------|---------|-------|
| Root key rotation interval | 7 days | 1-90 days |
| Shamir quorum ratio | 75% | 51-100% |
| Min Tier 1 uptime | 90% | 50-99.9% |

## API Endpoints

### Public API (pre-VPN bootstrap)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | No | Health check |
| GET | `/api/stats` | No | Server statistics |
| GET | `/api/servers` | No | List known servers |
| POST | `/api/auth` | No | Authenticate (password, passkey, or token) |
| POST | `/api/auth/register` | No | Register a passkey credential |
| POST | `/api/join` | No | Bootstrap: authenticate + create node + allocate IP + return WireGuard config |

### Private API (VPN-only, JWT required)

All private endpoints require `Authorization: Bearer <token>` header.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/tree/node/:id` | Get permission tree node |
| GET | `/api/tree/children/:id` | Get child nodes |
| POST | `/api/tree/delta` | Submit a signed tree delta |
| POST | `/api/ipam/allocate` | Allocate tunnel/private/shared IP block |
| GET | `/api/relay/list` | List all relays |
| GET | `/api/relay/nearest` | Find nearest relays by region |
| POST | `/api/relay/register` | Register a community relay |
| POST | `/api/relay/ticket` | Generate relay session ticket |
| GET | `/api/certs/:domain` | Check certificate status |
| POST | `/api/certs/issue` | Request a TLS certificate |
| GET | `/api/attestation/manifests` | List signed release manifests |
| POST | `/api/attestation/fetch` | Trigger GitHub manifest fetch |
| GET | `/api/trust/status` | Trust tier status for all peers |
| GET | `/api/trust/peer/:pubkey` | Detailed trust state for a peer |
| GET | `/api/enrollment/status` | Pending enrollment ballots |
| GET | `/api/governance/params` | Current protocol parameters |
| GET | `/api/governance/proposals` | All governance proposals |
| POST | `/api/governance/propose` | Create a parameter change proposal |

## Security Model

### Trust Tiers

| Tier | Requirements | Capabilities |
|------|-------------|--------------|
| **Tier 1** | Valid certificate + TEE attestation + binary attestation + 90% uptime | Full mesh participation, root key shares, governance voting, enrollment voting |
| **Tier 2** | Valid certificate | Basic gossip, tree sync, relay usage |
| **Untrusted** | None | Rejected from mesh |

### Defense Layers

1. **Root certificate** — every server must have a cert signed by a root key in the chain
2. **Revocation list** — compromised servers can be revoked immediately
3. **Certificate expiry** — time-limited trust
4. **TEE hardware attestation** — proves code runs in a secure enclave
5. **Binary attestation** — proves the server binary matches a signed release manifest
6. **Per-message attestation tokens** — every gossip message carries a trust proof
7. **Trust expiration** — peers must re-attest periodically (default: 1 hour)
8. **Uptime gating** — unreliable servers cannot hold root key shares
9. **Enrollment quorum** — new servers need peer votes, not just root signature
10. **Democratic governance** — protocol parameters require majority Tier 1 vote
11. **JWT authentication** — all private API endpoints require valid session tokens
12. **VPN-only private API** — sensitive endpoints are unreachable from the public internet

### Shamir's Secret Sharing

The root Ed25519 private key is split using Shamir's Secret Sharing over GF(2^8):

- **N** = all eligible Tier 1 peers (100% distribution)
- **K** = ceil(75% of N), minimum 2 (reconstruction threshold)
- Shares are encrypted per-peer using X25519 Diffie-Hellman + HKDF + AES-256-GCM
- If the root server goes offline, any K Tier 1 peers can reconstruct the key

## Building from Source

### macOS

```bash
brew install cmake ninja openssl@3
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Ubuntu/Debian

```bash
sudo apt install cmake ninja-build g++ libssl-dev
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Fedora

```bash
sudo dnf install cmake ninja-build gcc-c++ openssl-devel
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Arch Linux

```bash
sudo pacman -S cmake ninja gcc openssl
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Windows

```bash
choco install cmake ninja
vcpkg install openssl:x64-windows
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_TOOLCHAIN_FILE=%VCPKG_INSTALLATION_ROOT%/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

## Packaging

Packages are built with CMake/CPack. After building:

```bash
# Debian/Ubuntu .deb
cpack --config build/CPackConfig.cmake -G DEB -B build/packages

# Fedora/RHEL .rpm
cpack --config build/CPackConfig.cmake -G RPM -B build/packages

# macOS .pkg
cpack --config build/CPackConfig.cmake -G productbuild -B build/packages

# Windows .exe installer
cpack --config build/CPackConfig.cmake -G NSIS -B build/packages

# Portable tarball
cpack --config build/CPackConfig.cmake -G TGZ -B build/packages
```

### What's in the package

| Platform | Binary | Service |
|----------|--------|---------|
| Linux | `/usr/bin/lemonade-nexus` | systemd (`lemonade-nexus.service`) |
| macOS | `/usr/local/bin/lemonade-nexus` | launchd (`io.lemonade-nexus.plist`) |
| Windows | `C:\Program Files\lemonade-nexus\bin\lemonade-nexus.exe` | — |

### Install from packages

**Debian/Ubuntu**
```bash
sudo dpkg -i lemonade-nexus-*.deb
sudo vi /etc/lemonade-nexus/lemonade-nexus.env
sudo systemctl start lemonade-nexus
```

**macOS**
```bash
sudo installer -pkg lemonade-nexus-*.pkg -target /
sudo launchctl load /Library/LaunchDaemons/io.lemonade-nexus.plist
```

### systemd (Linux)

```bash
sudo systemctl enable lemonade-nexus
sudo systemctl start lemonade-nexus
sudo journalctl -u lemonade-nexus -f
```

## Project Structure

```
lemonade-nexus/
├── projects/
│   ├── LemonadeNexus/              # Server application
│   │   ├── include/LemonadeNexus/
│   │   │   ├── ACL/                # Access control
│   │   │   ├── Acme/               # ACME certificate management
│   │   │   ├── Auth/               # Authentication + JWT middleware
│   │   │   ├── Core/               # Coordinator, config, trust, governance
│   │   │   ├── Crypto/             # Ed25519, X25519, Shamir, key wrapping
│   │   │   ├── Gossip/             # UDP gossip protocol
│   │   │   ├── IPAM/               # IP address management
│   │   │   ├── Network/            # HTTP, STUN, DNS, DDNS, API types
│   │   │   ├── Relay/              # WireGuard relay + geo discovery
│   │   │   ├── Storage/            # File-based signed JSON storage
│   │   │   ├── Tree/               # Permission tree with signed deltas
│   │   │   └── WireGuard/          # WireGuard tunnel management
│   │   └── src/                    # Implementation files
│   └── LemonadeNexusSDK/           # Client SDK
│       ├── include/LemonadeNexusSDK/
│       │   ├── LemonadeNexusClient.hpp  # C++ client API
│       │   ├── WireGuardTunnel.hpp      # Cross-platform WireGuard
│       │   ├── LatencyMonitor.hpp       # Auto-switching monitor
│       │   ├── Identity.hpp             # Ed25519 identity management
│       │   ├── Types.hpp                # Request/response types
│       │   ├── Error.hpp                # Error types
│       │   └── lemonade_nexus.h         # C API (FFI)
│       └── src/                         # Implementation files
├── tests/                          # 277 test cases across 14+ suites
├── scripts/                        # Key generation utilities
├── packaging/                      # Debian, macOS, systemd configs
├── cmake/                          # Build system + dependency management
├── .github/workflows/              # CI/CD (build + release)
└── .env.example                    # Environment variable reference
```

## Dependencies

All dependencies are fetched automatically via CMake FetchContent:

| Library | Version | Purpose |
|---------|---------|---------|
| libsodium | latest | Ed25519, X25519, AES-GCM, Shamir |
| nlohmann_json | 3.12.0 | JSON serialization |
| spdlog | 1.16.0 | Logging |
| asio | 1.34.2 | Async I/O (UDP, timers) |
| cpp-httplib | 0.18.3 | HTTP server/client |
| jwt-cpp | 0.7.0 | JWT token generation/validation |
| magic_enum | 0.9.7 | Enum reflection |
| xxHash | 0.8.3 | Fast hashing |
| c-ares | latest | DNS packet parsing |
| sqlite3 | latest | Embedded database |
| OpenSSL | 3.0+ (system) | TLS, ACME |

## License

See repository license file for details.
