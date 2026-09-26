# 🍋 Lemonade Nexus

**Your network. Your infrastructure.**

A self-hosted userspace mesh VPN with encrypted peer-to-peer connections, cryptographic identity, and an attestation-based security protocol. This repository brings together the server, C++/C SDK, sidecar, and Flutter desktop client.

📖 [Explore the docs](https://lemonade-sdk.github.io/lemonade-nexus/) · 🚀 [Quick start](#-quick-start) · 🧩 [Client SDK](#-client-sdk) · 🤝 [Contribute](#-contributing)

> **Development status:** The Tier 1/Tier 2 security overhaul is merged. The protocol and evidence-collection code are present, but the shipped attestation profile still lacks the approved measurements needed to qualify a Tier 1 node. See [current limitations](#current-limitations) before planning a deployment. The documentation set is being refreshed to match this implementation.

## ✨ Features

- **Self-hosted mesh networking** — userspace WireGuard transport through BoringTun, with NAT traversal and relay support.
- **Cryptographic identity** — Ed25519 identities, network-bound server certificates, and signed gossip messages.
- **Two-tier security** — authenticated Tier 2 servers provide mesh services; eligible servers earn epoch-scoped Tier 1 authority through the security protocol.
- **Consensus and threshold authority** — chained HotStuff finalizes security state; fresh dealerless FROST key generation establishes each epoch's authority key.
- **Hardware evidence verification** — an AMD SEV-SNP/HCL/vTPM verification path, IMA runtime measurements, and a separate `nexus-attestd` evidence helper.
- **Discovery and addressing** — regional DNS discovery, IP address management, authoritative DNS, and optional dynamic DNS.
- **Certificates and access control** — ACME TLS certificates, identity authentication, WebAuthn passkeys, and a permission tree.
- **Applications and integrations** — a Flutter desktop client, C++ SDK, C ABI, and sidecar integration.

The [security model](#-security-model) explains which operations derive authority from consensus and which application paths still need further work.

## 🏗️ Architecture

The server separates mesh transport, application services, and the security protocol. A transport connection or valid certificate does not grant Tier 1 authority.

| Component | Purpose |
|---|---|
| Public API | HTTPS discovery, authentication, client join, and server onboarding |
| Private API | Authenticated application operations, reached through the userspace mesh in the normal dual-listener configuration |
| BoringTun + virtual netstack | Encrypted UDP transport and userspace TCP/IP forwarding, without a kernel TUN device |
| Gossip + security transport | Signed server messages, record transfer, attestation exchanges, consensus, and epoch transitions |
| Security runtime | Eligibility, HotStuff finality, Genesis bootstrap, epoch membership, and FROST authority |
| `nexus-attestd` | Collects platform evidence through a bounded local socket protocol |
| Storage | File-backed records and durable security state, plus SQLite-backed application storage |

### Public and private APIs

The public API uses port **9100**. In the normal mesh configuration, the private API uses virtual mesh addresses on port **9101**, forwarded internally to a loopback listener by the userspace netstack. Server startup withholds HTTPS listeners until usable certificates are available.

**Current fallback:** If no private listener is created, the server registers private routes on the public listener. Route authentication still applies, but network isolation does not. Check startup logs and listener configuration before exposing a server.

## 🌐 Network Requirements

### Default ports

| Port | Transport | Purpose | Exposure |
|---|---|---|---|
| `9100` | TCP | Public HTTPS API | Clients and joining servers |
| `51940` | UDP | Mesh transport **and hole punching** | Mesh servers and clients |
| `9102` | UDP | Gossip and security protocol | Mesh servers |
| `3478` | UDP | STUN | Peers using NAT discovery |
| `9103` | UDP | Relay | Peers using the relay service |
| `9101` | TCP | Private API | Virtual mesh addresses, forwarded to loopback in dual-listener mode |
| `5335` | UDP + TCP | Local authoritative DNS listener | According to the DNS deployment |
| `53` | UDP + TCP | Public authoritative DNS | Map to `5335` on DNS-serving nodes |

Hole punching shares `51940`; a separate `51941` rule is not required by the current server. Configure source restrictions for your mesh and expose public DNS only where it is served. Mapping port `53` to `5335` does not replace the rest of your firewall policy.

### Addressing and discovery

| Range | Purpose |
|---|---|
| `10.64.0.0/10` | Client mesh addresses |
| `172.16.0.0/22` | Server backbone addresses |
| `10.128.0.0/9` | Private subnet allocation |
| `172.20.0.0/14` | Shared address blocks |

Servers publish region-aware discovery records under the configured DNS base domain. Public endpoints use `<id>.<region>.seip.<domain>`; `private.` and `backend.` records identify virtual mesh endpoints. DNS helps peers find each other. Pinned keys, verified certificates, and finalized security state establish trust.

Security messages travel over the signed gossip transport on `9102`; they are not all carried inside WireGuard. Sensitive pairwise DKG payloads have their own encryption.

## 🚀 Quick Start

### 1. Build the server

Install the [build prerequisites](#-building-from-source), then run:

```bash
git clone https://github.com/lemonade-sdk/lemonade-nexus.git
cd lemonade-nexus

cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The server executable is `build/projects/LemonadeNexus/lemonade-nexus`. Hardware-dependent tests may skip when their required environment is absent; skipped tests do not establish hardware qualification.

### 2. Install a Debian/Ubuntu package

For a systemd deployment, packaging installs the service accounts, units, evidence helper, and bootstrap command together:

```bash
cpack --config build/CPackConfig.cmake -G DEB -B build/packages
sudo apt install ./build/packages/lemonade-nexus-*.deb
```

Use the package produced by your build. The install enables the services without starting them.

### 3. Initialize a new Genesis server

Genesis starts a **new network**. Use `nexus-bootstrap` for the packaged Linux setup:

```bash
sudo nexus-bootstrap \
  --release-signing-pubkey 'YOUR_RELEASE_SIGNING_PUBLIC_KEY'
```

Replace the quoted value with the Ed25519 public key that verifies your release manifests, encoded as 64 hex characters or base64 for 32 bytes. Bootstrap creates the node identities, pins the root and Genesis public keys, and writes:

- Configuration: `/var/lib/lemonade-nexus/lemonade-nexus.json`
- Runtime state: `/var/lib/lemonade-nexus/data`

If this host serves public authoritative DNS, add `--install-dns-nat` to the bootstrap command to map UDP/TCP `53` to `5335` with nftables. This option requires `nft` and `ip`; `--wan-interface` can select the external interface. You can also configure the mapping on your router.

For a disposable development network, `sudo nexus-bootstrap --test-release-key` uses the node identity as a test release key. It does not bypass attestation requirements or enable Tier 1 qualification.

```bash
sudo systemctl start lemonade-nexus.service
systemctl status lemonade-nexus.service nexus-attestd.service
sudo journalctl -u lemonade-nexus.service -u nexus-attestd.service -f
```

The server unit also requests `nexus-attestd`. A successful bootstrap or daemon start does **not** mean that Epoch 1 has formed. The current profile prevents Tier 1 qualification, and application-root initialization remains incomplete; see [current limitations](#current-limitations).

### Joining an existing network

Use server onboarding instead of initializing another Genesis. The candidate contacts a server by its certificate FQDN over verified HTTPS, proves possession of its identity, and validates the returned network-bound certificate against pinned trust anchors.

```bash
lemonade-nexus --help
nexus-bootstrap --help
```

The relevant candidate command is `--onboard-server`; normal daemon startup also requires the root, Genesis, and release-signing public keys described below. Admission currently uses root-gated approval or enrollment tokens. Admission grants a server identity, not Tier 1 membership. The application-root limitation also affects fresh-network administrative approval flows.

## 🧩 Client SDK

`LemonadeNexusSDK` exposes C++ and C interfaces for identity, authentication, mesh connections, tree operations, certificates, and latency-based server switching. The Flutter desktop client uses the C ABI through Dart FFI.

For example, query a server with a valid HTTPS certificate:

```cpp
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <iostream>

int main() {
    lnsdk::ServerConfig config{"server.example.com", 9100};
    lnsdk::LemonadeNexusClient client{config};

    const auto health = client.check_health();
    if (!health.ok) {
        std::cerr << health.error << '\n';
        return 1;
    }
    std::cout << health.value.status << '\n';
}
```

Build the shared SDK with:

```bash
cmake --build build --target LemonadeNexusSDKShared --parallel
```

- [C++ interface](projects/LemonadeNexusSDK/include/LemonadeNexusSDK/LemonadeNexusClient.hpp)
- [C ABI](projects/LemonadeNexusSDK/include/LemonadeNexusSDK/lemonade_nexus.h)
- [Flutter desktop client](apps/LemonadeNexusClient/README.md)

The current authentication paths use Ed25519 challenge-response and WebAuthn. Password authentication is a deprecated server stub. Legacy trust, enrollment-status, and governance C functions remain for ABI compatibility and return `LN_ERR_UNSUPPORTED`.

## ⚙️ Configuration

A normal daemon start requires three separate trust values:

| Setting | Purpose | Representation |
|---|---|---|
| `root_pubkey` | Verifies server admission certificates | Hex Ed25519 public key |
| `genesis_pubkey` | Pins the Genesis anchor used to derive network identity and verify the epoch authority chain | Base64 Ed25519 public key |
| `release_signing_pubkey` | Verifies signed release manifests | Ed25519 public key; packaged bootstrap accepts hex or base64 |

Keep these roles distinct. `nexus-bootstrap` writes the packaged configuration; `/etc/lemonade-nexus/lemonade-nexus.env` is for deliberate operator overrides.

Most settings follow **environment variables → CLI arguments → JSON configuration → defaults**, highest priority first. Explicit `--root-pubkey` and `--genesis-pubkey` arguments take precedence over their environment variables. Environment seed peers are appended to the configured list.

Ports, data paths, discovery, logging, and certificate settings are operational configuration. Tier 1 prerequisites, consensus rules, and authority thresholds are compiled protocol rules. There is no supported configuration switch to force Tier 1 or bypass required evidence.

See the [Configuration reference](docs/Configuration.md) and `lemonade-nexus --help` for the current options; the [`ServerConfig`](projects/LemonadeNexus/include/LemonadeNexus/Core/ServerConfig.hpp) struct is the source of truth.

## 🔌 API Endpoints

| API area | Examples |
|---|---|
| Public discovery and health | `/api/health`, `/api/servers` |
| Authentication | `/api/auth`, `/api/auth/challenge`, `/api/auth/register` |
| Server onboarding | `/api/onboard/info`, `/api/onboard/challenge`, `/api/onboard/request`, `/api/onboard/poll` |
| Authenticated application services | Tree, IPAM, relay, certificates, account data, and onboarding administration |

The [route handlers](projects/LemonadeNexus/src/Api) define the current methods and authorization checks. The old `/api/trust/*`, `/api/enrollment/status`, and `/api/governance/*` endpoints have been retired. Review the [private-listener fallback](#public-and-private-apis) when configuring exposure.

## 🔐 Security Model

### Server roles

| Role | What establishes it | Capabilities |
|---|---|---|
| **Tier 2** | A valid network-bound server certificate and authenticated mesh participation | Mesh services and non-authoritative synchronization; no Tier 1 authority share |
| **Pending member** | Selection in a finalized next-epoch plan | State synchronization and readiness preparation; no active Tier 1 authority |
| **Tier 1** | Verified evidence and mesh eligibility, followed by the protocol's finalized activation | HotStuff consensus, epoch transitions, dealerless DKG, and threshold authority signing |

Clients use the mesh under their application permissions; they do not become members of the server authority committee.

### Epoch authority

Tier 1 membership is scoped to an epoch. After Genesis, the current committee finalizes four transitions: **eligibility, the next-epoch plan, candidate readiness, and the epoch handoff**. A fresh dealerless distributed key generation (DKG) ceremony follows finalized readiness. The finalized handoff activates the new membership and key.

HotStuff uses individual Ed25519 vote signatures. FROST supplies threshold authority signatures; it is not the consensus voting mechanism. Old authority shares are discarded on epoch replacement, and the full FROST private key is not routinely reconstructed.

For a committee of `N` members, the compiled rules use:

- Maximum Byzantine faults: `f = floor((N - 1) / 3)`.
- Consensus quorum: `N - f`.
- Authority-signing threshold: `max(5, N - f)`.

These values are separate from the retired 75% Shamir reconstruction scheme. See the [compiled constants](projects/LemonadeNexus/include/LemonadeNexus/Security/Policy/SecurityConstants.hpp).

### Genesis and trust continuity

Genesis is a temporary bootstrap authority. The founding path requires five qualifying founders, agreement on the founding facts, and a fresh Epoch 1 DKG. Genesis signs the resulting bootstrap certificate; its unilateral **security-protocol authority ends when Epoch 1 activates**.

Later authority is verified from the pinned Genesis anchor through finalized epoch handoffs. Certificates, announcements, local configuration, and attestation results cannot independently create Tier 1 authority. Some admission and application operations still use root- or identity-gated authorization; those are separate from epoch authority and remain an integration gap.

### Attestation and key boundaries

The implemented provider verifies the AMD SEV-SNP/HCL/vTPM evidence chain and IMA measurements. Required facts include launch and runtime integrity, fresh challenge binding, identity binding, and the approved release profile.

`nexus-attestd` runs under a separate service identity with restricted TPM/IMA access, a scoped capability, and filesystem restrictions. It collects evidence without holding the server's Nexus identity key, consensus vote key, or FROST share.

Attestation depends on the approved platform and threat model. Confidential computing protects against the host/hypervisor; it is not a claim that privileged root inside the guest cannot inspect guest processes.

### Current limitations

- **Tier 1 qualification is blocked in the shipped profile.** Launch measurements, the TCB floor, IMA policy digest, and approved component hashes still need qualified release values. The running server reports `ProfileIncomplete` until those are supplied in an approved build.
- **Provider support is narrower than the design.** The SVSM-vTPM and direct-boot providers currently return `ProviderUnsupported`. SGX, TDX, and Secure Enclave are not implemented Tier 1 providers here.
- **Application authority is not fully integrated.** Admission and several replicated application stores still use root- or identity-gated paths. Receiving an author-signed record does not by itself authorize remote tree/ACL mutation. Public authentication does not initialize an application-root owner.
- **Recovery and freshness have limits.** The quorum-authorized incarnation-advance lifecycle is unfinished. A valid historical store or authority chain cannot, in isolation, prove it is the newest state.
- **IMA checkpoint/resume acceptance is not implemented.** The bounded evidence path must satisfy the current complete verification requirements.

These are implementation limits, not settings that an operator can disable to gain authority.

## 🛠️ Building from Source

The native build requires **C++20**, **CMake 3.25.1+**, **Ninja**, **Git**, and a **Rust/Cargo toolchain**. Rust builds the BoringTun, virtual-netstack, and FROST components.

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake ninja-build pkg-config git python3 \
  curl ca-certificates perl libssl-dev \
  libjson-c-dev libcurl4-openssl-dev uuid-dev
```

Install Rust/Cargo through your development environment and ensure `rustc` and `cargo` are on `PATH`. Confirm the installed CMake version meets the minimum, then use the [quick-start build commands](#1-build-the-server).

The normal Linux build compiles TPM2-TSS from source and needs the system json-c, libcurl, and UUID development packages. TPM device access, a suitable runtime TCTI, IMA policy, and the evidence-helper service are separate deployment requirements.

### Other platforms

macOS builds use the same CMake targets. For distributable macOS binaries, configure with `-DOPENSSL_FORCE_BUNDLED=ON` as in CI. Windows build and packaging definitions exist, but Windows entries are disabled in the reviewed native and Flutter CI matrices; their presence is not current build qualification.

Use [Building](docs/Building.md) and the [client guide](apps/LemonadeNexusClient/README.md) as navigation starting points, and check their examples against the current build files during the documentation refresh. Native platform support and Tier 1 attestation support are separate questions.

## 📦 Packaging

CPack generates packages after a successful native build:

| Platform / format | Command |
|---|---|
| Debian / Ubuntu | `cpack --config build/CPackConfig.cmake -G DEB -B build/packages` |
| Fedora / RPM | `cpack --config build/CPackConfig.cmake -G RPM -B build/packages` |
| macOS | `cpack --config build/CPackConfig.cmake -G productbuild -B build/packages` |
| Portable archive | `cpack --config build/CPackConfig.cmake -G TGZ -B build/packages` |

Use the generator and packaging tools for the target platform. The current DEB/RPM metadata targets x86-64; review the packaging definitions before building for another architecture. Windows also has NSIS/ZIP definitions, subject to the validation limitation above.

Linux packages include `lemonade-nexus`, `nexus-attestd`, systemd units, and `nexus-bootstrap`. Desktop-client packaging is maintained separately under [the Flutter app](apps/LemonadeNexusClient).

## 🗂️ Project Structure

| Path | Contents |
|---|---|
| [`projects/LemonadeNexus/`](projects/LemonadeNexus) | Server and mesh services |
| [`projects/LemonadeNexus/include/LemonadeNexus/Security/`](projects/LemonadeNexus/include/LemonadeNexus/Security) | Security protocol interfaces and compiled policy |
| [`projects/LemonadeNexusSDK/`](projects/LemonadeNexusSDK) | C++ SDK and C ABI |
| [`projects/LemonadeNexusAttestd/`](projects/LemonadeNexusAttestd) | Privilege-separated evidence helper |
| [`projects/LemonadeNexusSidecar/`](projects/LemonadeNexusSidecar) | Sidecar integration |
| [`apps/LemonadeNexusClient/`](apps/LemonadeNexusClient) | Flutter desktop client |
| [`crates/`](crates) | Rust networking and FROST integrations |
| [`tests/`](tests) | Unit, integration, lifecycle, and fuzzing coverage |
| [`scripts/`](scripts) | Bootstrap, host inspection, and development tooling |
| [`packaging/`](packaging) | Package and service configuration |
| [`docs/`](docs) | Guides and reference documentation |

## 🧱 Dependencies

The main components include libsodium and OpenSSL for cryptography; BoringTun and smoltcp for userspace networking; `frost-ed25519` for threshold signatures; TPM2-TSS for Linux TPM access; SQLite for application storage; and Asio, cpp-httplib, nlohmann/json, and spdlog for server infrastructure.

Dependencies use a mix of CMake FetchContent, external source builds, system packages, and Cargo. The [CMake library definitions](cmake/libraries) and [Rust manifests and lockfiles](crates) are the source of truth for versions.

## 📖 Documentation

[Browse the documentation site](https://lemonade-sdk.github.io/lemonade-nexus/) or start with the [documentation index](docs/index.md).

The guides have been refreshed after the security overhaul. Older governance, Shamir root-share, universal TEE-support, and separate `51941` instructions in pre-refresh material are obsolete; use this README, the [documentation index](docs/index.md), and the linked implementation files to resolve conflicts.

## 🤝 Contributing

Bug reports, documentation fixes, and focused pull requests are welcome. Include the commit you tested, your platform, and steps to reproduce the issue. Run the checks relevant to your change and report any skipped or unavailable validation.

[Open an issue](https://github.com/lemonade-sdk/lemonade-nexus/issues) or browse the [pull requests](https://github.com/lemonade-sdk/lemonade-nexus/pulls).

## 📄 License

Lemonade Nexus is released under the [MIT License](LICENSE).
