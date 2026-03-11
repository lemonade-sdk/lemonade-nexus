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

Configuration priority: **CLI args > environment variables > config file > defaults**

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--http-port` | `SP_HTTP_PORT` | 9100 | Public HTTP API port |
| `--private-http-port` | `SP_PRIVATE_HTTP_PORT` | 9101 | Private (VPN-only) HTTP API port |
| `--data-root` | `SP_DATA_ROOT` | data | Data directory |
| `--root-pubkey` | `SP_ROOT_PUBKEY` | | Root Ed25519 public key (hex) |
| `--seed-peer` | `SP_SEED_PEERS` | | Gossip seed peers (comma-separated) |
| `--log-level` | `SP_LOG_LEVEL` | info | Log level: trace/debug/info/warn/error |
| `--require-tee` | `SP_REQUIRE_TEE` | off | Require TEE for Tier 1 |
| `--require-attestation` | `SP_REQUIRE_ATTESTATION` | off | Require binary attestation |
| `--require-peer-confirmation` | `SP_REQUIRE_PEER_CONFIRMATION` | off | Require enrollment quorum |
| `--ddns-domain` | `SP_DDNS_DOMAIN` | | Base domain for DDNS |
| `--ddns-enabled` | `SP_DDNS_ENABLED` | off | Enable dynamic DNS updates |
| `--config` | | lemonade-nexus.json | JSON config file path |

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
