---
layout: default
title: Building from Source
---

# Building from Source

## Table of Contents
- [Prerequisites](#prerequisites)
- [Linux Build](#linux-build)
- [macOS Build](#macos-build)
- [Windows Status](#windows-status)
- [Flutter Client App](#flutter-client-app)
- [Running Tests](#running-tests)
- [Dependencies](#dependencies)

## Prerequisites

- **C++20** compiler (GCC 12+, Clang 15+)
- **CMake** 3.25.1 or newer
- **Ninja** build system
- **Rust/Cargo** toolchain (`rustc` and `cargo` on `PATH`) — Rust builds the
  BoringTun FFI wrapper, the virtual netstack, and the FROST integration
- **Git**

On Debian/Ubuntu, the additional system packages are:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake ninja-build pkg-config git python3 \
  curl ca-certificates perl libssl-dev \
  libjson-c-dev libcurl4-openssl-dev uuid-dev
```

`libjson-c-dev`, `libcurl4-openssl-dev`, and `uuid-dev` are the development
packages the TPM2-TSS source build links against. They are the only required
system libraries beyond the toolchain: the normal Linux build compiles
TPM2-TSS 4.1.3 from source.

Dependencies are **not** all fetched automatically. They use a mix of CMake
FetchContent (most C/C++ libraries), source builds (TPM2-TSS, OpenSSL as a
fallback), system packages (json-c, libcurl, UUID), and Cargo (the Rust
crates). See [Dependencies](#dependencies) and the
[CMake library definitions](https://github.com/lemonade-sdk/lemonade-nexus/tree/main/cmake/libraries)
for the actual sourcing and versions.

## Linux Build

```bash
git clone https://github.com/lemonade-sdk/lemonade-nexus.git
cd lemonade-nexus
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON
cmake --build build --parallel
```

The server binary is at `build/projects/LemonadeNexus/lemonade-nexus`.

### Install

On Debian/Ubuntu, build and install the package so the service user,
bootstrap command, evidence helper, and systemd units install together:

```bash
cpack --config build/CPackConfig.cmake -G DEB -B build/packages
sudo apt install ./build/packages/lemonade-nexus-*.deb
```

The package enables the services without starting them. Follow
[Getting Started](Getting-Started) to bootstrap the protected configuration
and configure public DNS before starting.

Other generators: `cpack --config build/CPackConfig.cmake -G RPM -B build/packages`
(Fedora/RPM), `-G productbuild` (macOS), `-G TGZ` (portable archive). The
current DEB/RPM metadata targets x86-64; review the packaging definitions
before building for another architecture.

## macOS Build

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON
cmake --build build --parallel
```

For distributable binaries, configure with `-DOPENSSL_FORCE_BUNDLED=ON` (as
CI does) so OpenSSL is statically bundled instead of linking Homebrew's copy.

macOS builds run in CI on every push.

## Windows Status

Windows build and packaging definitions exist in the tree (MSVC + vcpkg
OpenSSL in CI, NSIS/ZIP in CPack, a Windows durable-write path in the security
stores), but the Windows jobs are **disabled in the current CI matrices**:

- The native `ci.yml` matrix comments out both `windows-2022` entries.
- The Flutter client workflow sets the Windows job `if: false`.

Their presence is not current build qualification. Treat Windows as
unsupported until those jobs are re-enabled and passing.

## Flutter Client App

The desktop client (`apps/LemonadeNexusClient`) is a Flutter app that talks to
the C SDK over FFI. Build the SDK **shared** library first, then run Flutter.

### macOS

```bash
# 1. Build the SDK dylib from the repo root. OPENSSL_FORCE_BUNDLED=ON statically
#    bundles OpenSSL so the dylib is self-contained — without it the dylib links
#    Homebrew's OpenSSL and the app fails at runtime. This matches the CI build.
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_FORCE_BUNDLED=ON
cmake --build build --target LemonadeNexusSDKShared --parallel

# 2. Run / build the app — the Xcode "Embed Lemonade Nexus SDK" build phase
#    copies and codesigns the dylib into the .app automatically
cd apps/LemonadeNexusClient
flutter pub get
flutter run -d macos              # development (hot reload)
flutter build macos --release     # release build
```

Output: `build/macos/Build/Products/Release/nexus-client.app`.
Set `LN_DEBUG=1` to surface verbose SDK and mesh diagnostics in the console.

### Windows

See the [Windows packaging guide](../apps/LemonadeNexusClient/windows/packaging/PACKAGING.md).
The SDK DLL must be staged next to the runner before `flutter build windows`.
Windows CI is currently disabled; validate locally.

CI builds and sanity-checks the macOS client on every push — see
[`.github/workflows/flutter-clients.yml`](../.github/workflows/flutter-clients.yml).

## Running Tests

```bash
ctest --test-dir build --output-on-failure --parallel
```

Or, from the build directory: `ctest --output-on-failure -j$(nproc)`.

CTest discovers GoogleTest case names; use the names from `ctest -N` with
`ctest -R` to select focused tests. Hardware-dependent tests (TPM, real
SEV-SNP evidence, loopback-timing-sensitive cases) skip when their environment
is absent. A skipped hardware test is not production qualification evidence.
Do not quote a fixed test count — the suite size changes between revisions.

Useful scoped checks:

```bash
ctest --test-dir build -N
cmake --build build --target LemonadeNexusSDKShared --parallel
```

For Rust-only changes, run the relevant crate's checks from its manifest path
(`crates/boringtun-ffi`, `crates/virtual-netstack`, `crates/frost-ffi`) and
preserve the lockfile.

## Dependencies

Sourcing is mixed; the CMake library definitions and Cargo manifests are the
source of truth for versions.

| Component | Sourcing | Purpose |
|-----------|----------|---------|
| libsodium | FetchContent (1.0.20) | Ed25519, X25519, AEAD, HKDF, random |
| OpenSSL | System package preferred, source build (3.3.2) as fallback | TLS, ACME client |
| TPM2-TSS (FAPI) | Source build (4.1.3), Linux | TPM access for the evidence helper |
| asio | FetchContent (1.34.2) | Async I/O (UDP, timers) |
| cpp-httplib | FetchContent (0.18.3) | HTTP/HTTPS server and client |
| c-ares | FetchContent (1.34.6) | Async DNS resolution |
| nlohmann/json | FetchContent (3.12.0) | JSON parsing |
| spdlog | FetchContent (1.16.0) | Structured logging |
| jwt-cpp | FetchContent (0.7.0) | JWT session tokens |
| magic_enum | FetchContent (0.9.7) | Enum reflection |
| xxHash | FetchContent (0.8.3) | Non-cryptographic hashing (dedup caches) |
| SQLite | FetchContent amalgamation (3.46.1) | Application storage (ACL store) |
| BoringTun | Rust crate via Corrosion (`crates/boringtun-ffi`) | Userspace WireGuard |
| virtual netstack | Rust crate (`crates/virtual-netstack`) | Userspace TCP/IP (smoltcp) |
| FROST | Rust crate (`crates/frost-ffi`, `frost-ed25519 = 2.2.0`) | Threshold authority signatures |
| json-c, libcurl, UUID | System packages (Linux) | TPM2-TSS build dependencies |
