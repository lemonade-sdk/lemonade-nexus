# 🍋 Lemonade Nexus

**Your network. Your infrastructure.**

A self-hosted userspace mesh VPN with encrypted peer-to-peer connections, cryptographic identity, and an attestation-based security protocol. This repository brings together the server, release updater, C++/C SDK, Flutter plugin, sidecar, and Flutter desktop client.

📖 [Explore the docs](https://lemonade-sdk.github.io/lemonade-nexus/) · 🚀 [Quick start](#-quick-start) · 🧩 [Client SDK](#-client-sdk) · 🤝 [Contribute](#-contributing)

> **Development status:** The Tier 1/Tier 2 security protocol, permission-tree operations through Tier 1 consensus, threshold storage encryption, and in-place server updates are implemented. Tier 1 attestation uses AMD SEV-SNP with a COCONUT-SVSM vTPM, and only a server that runs a signed release for its network can qualify. See [current limitations](#current-limitations) before planning a deployment.

## ✨ Features

- **Self-hosted mesh networking** — an in-process userspace BoringTun dataplane, with STUN, hole punching, LAN-direct paths, and relay fallback.
- **Cryptographic identity** — Ed25519 identities, network-bound server certificates, and signed gossip messages.
- **Two-tier security** — authenticated Tier 2 servers proxy encrypted traffic; eligible servers earn epoch-scoped Tier 1 authority through the security protocol, and only Tier 1 servers hold the permission tree.
- **Consensus and threshold authority** — chained HotStuff finalizes security state and permission-tree operations; fresh dealerless FROST key generation establishes each epoch's authority key.
- **Encrypted storage** — each server encrypts its data files at rest under a data key. A threshold of storage-key holders must help to unlock it.
- **Hardware evidence verification** — AMD SEV-SNP with a COCONUT-SVSM vTPM, IMA runtime measurements, a sealed boot set, and a separate `nexus-attestd` evidence helper.
- **Signed releases and in-place updates** — one release workflow publishes date-versioned releases, and `nexus-updater` installs each release on the servers one at a time.
- **Discovery and addressing** — regional DNS discovery, IP address management, authoritative DNS, and optional dynamic DNS.
- **Certificates and access control** — ACME TLS certificates, identity authentication, WebAuthn passkeys, and a permission tree.
- **Applications and integrations** — a Flutter desktop client, a Flutter plugin with iOS and Android libraries, the C++ SDK, the C ABI, and a headless sidecar.

The [security model](#-security-model) explains which operations derive authority from consensus and which application paths still need further work.

## 🏗️ Architecture

The server separates mesh transport, application services, and the security protocol. A transport connection or valid certificate does not grant Tier 1 authority.

| Component | Purpose |
|---|---|
| Public API | HTTPS discovery, authentication, client join, and server onboarding |
| Private API | Authenticated application operations, reached through the userspace mesh in the normal dual-listener configuration |
| BoringTun dataplane + virtual netstack | Encrypted UDP transport and userspace TCP/IP forwarding, without a kernel TUN device |
| Gossip + security transport | Signed server messages, record transfer, attestation exchanges, consensus, and epoch transitions |
| Security runtime | Eligibility, HotStuff finality, Genesis bootstrap, epoch membership, FROST authority, and the threshold storage key |
| Tree consensus | Orders permission-tree operations in Tier 1 HotStuff blocks and applies only committed blocks |
| `nexus-attestd` | Collects platform evidence and seals the boot set through a bounded local socket protocol |
| `nexus-updater` | Installs signed releases in place when finalized upgrade records give this server its turn |
| Storage | Signed JSON records and durable security state on disk, a SQLite ACL store, and at-rest encryption of the covered data files under the data key |

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

Security messages travel over the signed gossip transport on `9102`; they are not all carried inside the BoringTun dataplane. Sensitive pairwise DKG payloads have their own encryption.

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

For a systemd deployment, packaging installs the service accounts, units, evidence helper, updater, and bootstrap command together:

```bash
cpack --config build/CPackConfig.cmake -G DEB -B build/packages
sudo apt install ./build/packages/lemonade-nexus-*.deb
```

Use the package produced by your build. The install enables the server, the evidence helper, and the updater timer and path units without starting them.

A package that you build yourself contains the unsigned example release approval from [`packaging/release/`](packaging/release). Its servers run, but they cannot reach Tier 1. The packages of a published release contain the signed approval.

### 3. Initialize a new Genesis server

Genesis starts a **new network**. Use `nexus-bootstrap` for the packaged Linux setup:

```bash
sudo nexus-bootstrap --install-dns-nat
```

Bootstrap creates the node identities, pins the root and Genesis public keys, and writes:

- Configuration: `/var/lib/lemonade-nexus/lemonade-nexus.json`
- Runtime state: `/var/lib/lemonade-nexus/data`

`--install-dns-nat` maps public UDP/TCP `53` to the local DNS port `5335` with nftables. Use it if this host serves public authoritative DNS. It requires `nft` and `ip`; `--wan-interface` can select the external interface. You can also configure the mapping on your router.

`--release-signing-pubkey` and `--test-release-key` fill a legacy configuration field only. They do not grant release authority and do not change attestation requirements.

```bash
sudo systemctl start lemonade-nexus.service
systemctl status lemonade-nexus.service nexus-attestd.service
sudo journalctl -u lemonade-nexus.service -u nexus-attestd.service -f
```

The server unit also requests `nexus-attestd`. A successful bootstrap or daemon start does **not** mean that Epoch 1 has formed. Epoch 1 needs five qualifying founders, and a founder qualifies only under a signed release approval for this network. Until Epoch 1 activates, no server holds the permission tree and no client can join; see [current limitations](#current-limitations).

### Joining an existing network

Use server onboarding instead of initializing another Genesis. The candidate contacts a server by its certificate FQDN over verified HTTPS, proves possession of its identity, and validates the returned network-bound certificate against pinned trust anchors.

```bash
lemonade-nexus --help
nexus-bootstrap --help
```

The relevant candidate command is `--onboard-server`; normal daemon startup also requires the root and Genesis public keys described below. Admission currently uses root-gated approval or enrollment tokens. Admission grants a server identity, not Tier 1 membership. The application-root limitation also affects fresh-network administrative approval flows.

## 🧩 Client SDK

`LemonadeNexusSDK` exposes C++ and C interfaces for identity, authentication, network join, mesh connections, local service exposure, tree operations, invites, certificates, and latency-based server switching. The SDK sends tree, session, and private-API requests only to Tier 1 servers that it verifies from the pinned Genesis key (`set_genesis_key`, or `discover_genesis_key` on first connect).

The Flutter plugin [`packages/lemonade_nexus_sdk`](packages/lemonade_nexus_sdk) wraps the C ABI through Dart FFI and ships the iOS and Android libraries. Those libraries are published as `mobile-sdk-v*` release archives. The Flutter desktop client uses the plugin.

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
- [Client SDK overview](docs/Client-SDK.md) and [SDK Guide](docs/SDK-Guide.md)
- [Flutter plugin native libraries](packages/lemonade_nexus_sdk/native/README.md)
- [Flutter desktop client](apps/LemonadeNexusClient/README.md)

The current authentication paths use Ed25519 challenge-response and WebAuthn. Password authentication is a deprecated server stub. Legacy trust, enrollment-status, and governance C functions remain for ABI compatibility and return `LN_ERR_UNSUPPORTED`.

## ⚙️ Configuration

A normal daemon start requires two separate trust anchors:

| Setting | Purpose | Representation |
|---|---|---|
| `root_pubkey` | Verifies server admission certificates | Hex Ed25519 public key |
| `genesis_pubkey` | Pins the Genesis anchor used to derive network identity and verify the epoch authority chain | Base64 Ed25519 public key |

Keep these roles distinct. Release authority is not a configuration value. Genesis delegates it to a release key in the signed release approval that each release installs at `/usr/lib/lemonade-nexus/release/release-approval.json`. The `release_signing_pubkey` setting is deprecated and parse-only.

`nexus-bootstrap` writes the packaged configuration. The packaged unit starts the server with `--tier1-authority-contract`: the server then reads only the fixed JSON file, ignores inherited `SP_*` variables and trust-key CLI overrides, and accepts only `SP_LOG_LEVEL` in `/etc/lemonade-nexus/lemonade-nexus.env`. Any other entry refuses startup.

Outside that contract, most settings follow **environment variables → CLI arguments → JSON configuration → defaults**, highest priority first. Explicit `--root-pubkey` and `--genesis-pubkey` arguments take precedence over their environment variables. Environment seed peers are appended to the configured list.

Ports, data paths, discovery, logging, and certificate settings are operational configuration. Tier 1 prerequisites, consensus rules, and authority thresholds are compiled protocol rules. There is no supported configuration switch to force Tier 1 or bypass required evidence.

See the [Configuration reference](docs/Configuration.md) and `lemonade-nexus --help` for the current options; the [`ServerConfig`](projects/LemonadeNexus/include/LemonadeNexus/Core/ServerConfig.hpp) struct is the source of truth.

## 🔌 API Endpoints

| API area | Examples |
|---|---|
| Public discovery and health | `/api/health`, `/api/stats`, `/api/servers`, `/api/tls/status` |
| Tier 1 membership | `/api/tier1/authority`, `/api/tier1/proof` |
| Authentication and join (Tier 1 only) | `/api/auth`, `/api/auth/challenge`, `/api/auth/register`, `/api/join` |
| Server onboarding | `/api/onboard/info`, `/api/onboard/challenge`, `/api/onboard/request`, `/api/onboard/poll`, `/api/onboard/ack` |
| Release rollout | `/api/upgrade/rollout-proof` |
| Authenticated application services | Tree, IPAM, mesh, routing, relay, certificates, account data, storage status, and onboarding administration |

`GET /api/stats` reports aggregate counts only. A current Tier 1 member adds network-wide device, group, and relay counts. `GET /api/tier1/authority` serves the epoch authority chain in pages of up to 32 handoffs (`max_links`), under its own per-address rate limit. Clients verify that chain against the pinned Genesis key. Every other public request spends a budget: a request with a valid session spends its node's budget (600 per minute, 60 in a burst, enough for a join or a resume), an unauthenticated request the per-address budget (`rate_limit_rpm`, `rate_limit_burst`; 120 per minute, 20 in a burst by default). Many devices share one address behind a carrier NAT, so the address budget guards only what has no session yet.

The [route handlers](projects/LemonadeNexus/src/Api) define the current methods and authorization checks. The old `/api/trust/*`, `/api/enrollment/status`, and `/api/governance/*` endpoints have been retired. Review the [private-listener fallback](#public-and-private-apis) when configuring exposure.

## 🔐 Security Model

### Server roles

| Role | What establishes it | Capabilities |
|---|---|---|
| **Tier 2** | A valid network-bound server certificate and authenticated mesh participation | A pure proxy of end-to-end encrypted data and connections: relay, STUN, discovery DNS, and the security transport. Holds no permission tree and serves no tree request or client session; no Tier 1 authority share |
| **Pending member** | Selection in a finalized next-epoch plan | State synchronization and readiness preparation; no active Tier 1 authority |
| **Tier 1** | Verified evidence and mesh eligibility, followed by the protocol's finalized activation | HotStuff consensus, epoch transitions, dealerless DKG, threshold authority signing, and the permission tree |

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

The Tier 1 profile is `snp-svsm-vtpm`: AMD SEV-SNP with a COCONUT-SVSM vTPM. The verifier checks the SNP report chain, the launch measurement, the TCB floor, the attestation key enrolled through TPM credential activation, PCR 8 and 9, a fresh quote bound to the challenge, and the IMA runtime measurements. The binary compiles the rules and a minimum TCB floor, which an approval can raise but not lower. The signed release approval supplies the release values: the launch measurements of the approved VM shapes, PCR 8 and 9, the kernel and IMA policy, and the approved binary hashes. No value comes from the host under test.

`nexus-attestd` runs under a separate service identity with restricted TPM/IMA access, a scoped capability, and filesystem restrictions. It collects evidence and seals the server's boot set to PCR 8 and 9 without holding the server's Nexus identity key, consensus vote key, or FROST share.

Attestation depends on the approved platform and threat model. Confidential computing protects against the host/hypervisor; it is not a claim that privileged root inside the guest cannot inspect guest processes.

### Current limitations

- **Tier 1 needs a signed release for its network.** Without a verified release approval, the attestation profile is incomplete, every attestation fails with `ProfileIncomplete`, and no node reaches Tier 1. An approval binds to one network ID, and a locally built package carries only the unsigned example. Only the VM shapes whose launch measurements an approval pins can qualify.
- **Provider support is narrow.** `snp-svsm-vtpm` is the only profile under which this binary issues Tier 1 challenges. The `snp-hcl-vtpm` verifier exists but is not the Tier 1 profile. The direct-boot provider returns `ProviderUnsupported`. SGX, TDX, and Secure Enclave are not implemented Tier 1 providers here.
- **Application authority is not fully integrated.** Permission-tree writes commit through Tier 1 consensus. Admission and several replicated application stores (ACL, DNS records, backbone IPAM, account group-key envelopes) still use root- or identity-gated paths. Receiving an author-signed record does not by itself authorize a remote mutation. Public authentication does not initialize an application-root owner.
- **No tree without Tier 1.** Before Epoch 1 activates, no server serves tree routes or client sessions, and no client can join.
- **Recovery and freshness have limits.** The quorum-authorized incarnation-advance lifecycle is unfinished. A valid historical store or authority chain cannot, in isolation, prove it is the newest state. A server whose files are encrypted refuses to start when the storage state that opens them is lost; the log names the files to restore.
- **NAT traversal is tested in software only.** Relay fallback, hole punching, and LAN-direct paths have unit and loopback tests. They are not tested across real NAT devices or under load, and the SDK does not detect symmetric NAT.

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

The normal Linux build compiles TPM2-TSS from source and needs the system json-c, libcurl, and UUID development packages. With `LEMONADE_NEXUS_STATIC_DEPS=ON` (the default), it links the static libraries of Ubuntu 24.04 `libssl-dev` (OpenSSL 3.0.13, the pinned version), libstdc++, and libgcc into the server executables; glibc stays a shared dependency. On another distribution, configure with `-DLEMONADE_NEXUS_STATIC_DEPS=OFF` to use the system OpenSSL. A client SDK build (`-DLEMONADE_NEXUS_SDK_ONLY=ON`) links the system OpenSSL 3 on Linux. TPM device access, a suitable runtime TCTI, IMA policy, and the evidence-helper service are separate deployment requirements.

### Other platforms

macOS builds use the same CMake targets. On macOS arm64 and Windows x64, CMake downloads a pinned static OpenSSL archive, checks its SHA-256, and links it; the build does not use Homebrew or vcpkg OpenSSL. Windows build and packaging definitions exist, but the Windows entries are disabled in the native CI matrix; CI builds only the Windows SDK DLL and Flutter client. This is not current Windows server build qualification.

`scripts/build-sdk-mobile.sh` builds the client SDK for iOS and Android against pinned mobile OpenSSL archives. The `Mobile SDK` workflow builds both and tests the Flutter plugin.

See [Building](docs/Building.md) and the [client guide](apps/LemonadeNexusClient/README.md) for platform details. Native platform support and Tier 1 attestation support are separate questions.

## 📦 Packaging

CPack generates packages after a successful native build:

| Platform / format | Command |
|---|---|
| Debian / Ubuntu | `cpack --config build/CPackConfig.cmake -G DEB -B build/packages` |
| Fedora / RPM | `cpack --config build/CPackConfig.cmake -G RPM -B build/packages` |
| macOS | `cpack --config build/CPackConfig.cmake -G productbuild -B build/packages` |
| Portable archive | `cpack --config build/CPackConfig.cmake -G TGZ -B build/packages` |

Use the generator and packaging tools for the target platform. The current DEB/RPM metadata targets x86-64; review the packaging definitions before building for another architecture. Windows also has NSIS/ZIP definitions, subject to the validation limitation above.

Linux packages include `lemonade-nexus`, `nexus-attestd`, `nexus-updater`, systemd units, `nexus-bootstrap`, `nexus-tree-migrate`, and the release approval. Desktop-client packaging is maintained separately under [the Flutter app](apps/LemonadeNexusClient).

### Releases and updates

Releases use date versions: `vYYYY.MM.DD` for the first release of a day, then `vYYYY.MM.DD.2`, `.3`, and so on. One manually dispatched workflow, [`release.yml`](.github/workflows/release.yml), builds, signs, and publishes every artifact from `main`. Do not push `v*` tags by hand.

Each server installs a release in place with `nexus-updater`. The updater verifies the signed manifest and the Sigstore provenance, waits until finalized upgrade records give this server its turn, runs a health gate, and rolls back on failure. Servers upgrade one at a time and keep their epoch chain, storage key share, and data. The normal path has no manual deploy and no re-found. Mobile SDK archives are published separately as `mobile-sdk-v*` releases.

See [Releasing](docs/Releasing.md), [Design: In-Place Auto-Update](docs/Design-Auto-Update.md), and [Upgrade Control](docs/Upgrade-Control.md) for the procedure and its current limits.

## 🗂️ Project Structure

| Path | Contents |
|---|---|
| [`projects/LemonadeNexus/`](projects/LemonadeNexus) | Server and mesh services |
| [`projects/LemonadeNexus/include/LemonadeNexus/Security/`](projects/LemonadeNexus/include/LemonadeNexus/Security) | Security protocol interfaces and compiled policy |
| [`projects/LemonadeNexusSDK/`](projects/LemonadeNexusSDK) | C++ SDK and C ABI |
| [`projects/LemonadeNexusAttestd/`](projects/LemonadeNexusAttestd) | Privilege-separated evidence helper |
| [`projects/LemonadeNexusUpdater/`](projects/LemonadeNexusUpdater) | `nexus-updater`, the in-place release installer |
| [`projects/LemonadeNexusSidecar/`](projects/LemonadeNexusSidecar) | Headless mesh client for embedding in a host application |
| [`packages/lemonade_nexus_sdk/`](packages/lemonade_nexus_sdk) | Flutter plugin over the C ABI, with the iOS and Android libraries |
| [`apps/LemonadeNexusClient/`](apps/LemonadeNexusClient) | Flutter desktop client (macOS, Windows, Linux) |
| [`crates/`](crates) | Rust BoringTun, virtual netstack, FROST, and threshold storage-key integrations |
| [`tests/`](tests) | Unit, integration, lifecycle, and fuzzing coverage |
| [`scripts/`](scripts) | Bootstrap, release, tree migration, mobile SDK builds, and development tooling |
| [`packaging/`](packaging) | Package and service configuration |
| [`release/`](release) | Reviewed release inputs: fleet profile, OS package lock, and release markers |
| [`docs/`](docs) | Guides and reference documentation |

## 🧱 Dependencies

The main components include libsodium and OpenSSL for cryptography; BoringTun and smoltcp for userspace networking; `frost-ed25519` for threshold authority signatures; `frost-ristretto255` and `elastic-elgamal` for the threshold storage key; TPM2-TSS for Linux TPM access; SQLite for the ACL store; and Asio, c-ares, cpp-httplib, jwt-cpp, nlohmann/json, and spdlog for server infrastructure.

Dependencies use a mix of CMake FetchContent, external source builds, system packages, and Cargo. The [CMake library definitions](cmake/libraries) and [Rust manifests and lockfiles](crates) are the source of truth for versions.

## 📖 Documentation

[Browse the documentation site](https://lemonade-sdk.github.io/lemonade-nexus/) or start with the [documentation index](docs/index.md).

Some guides lag behind the code. Older governance, Shamir root-share, universal TEE-support, separate `51941`, configured release-key, and manual re-found deployment instructions are obsolete. Use the linked implementation files to resolve conflicts.

## 🤝 Contributing

Bug reports, documentation fixes, and focused pull requests are welcome. Include the commit you tested, your platform, and steps to reproduce the issue. Run the checks relevant to your change and report any skipped or unavailable validation.

[Open an issue](https://github.com/lemonade-sdk/lemonade-nexus/issues) or browse the [pull requests](https://github.com/lemonade-sdk/lemonade-nexus/pulls).

## 📄 License

Lemonade Nexus is released under the [MIT License](LICENSE).
