---
layout: default
title: Frameworks and Libraries
---

# Frameworks and Libraries

## Core Language: C++20

The server and SDK are written in C++20. Service interfaces use CRTP
instead of virtual dispatch: zero-overhead polymorphism, compile-time type
safety, and inlinability, at the cost of more verbose templates.

Rust builds the parts that need it: the BoringTun FFI wrapper, the virtual
netstack (smoltcp), and the FROST integration (`crates/`).

## Build System: CMake 3.25.1+ and Ninja

Dependencies use a **mix** of sourcing mechanisms, not all FetchContent:

- **FetchContent** — most C/C++ libraries (libsodium, asio, httplib,
  nlohmann/json, spdlog, jwt-cpp, magic_enum, xxHash, SQLite amalgamation).
- **Source builds** — TPM2-TSS 4.1.3 (Linux) and OpenSSL 3.3.2 as a fallback
  when no suitable system copy is found (or `-DOPENSSL_FORCE_BUNDLED=ON`).
- **System packages (Linux)** — `libjson-c-dev`, `libcurl4-openssl-dev`,
  `uuid-dev` for the TPM2-TSS build.
- **Cargo** — the three Rust crates, with `frost-ed25519 = 2.2.0` for
  threshold signatures.

The CMake library definitions under `cmake/libraries/` and the Cargo
manifests under `crates/` are the source of truth for versions.

## Cryptography

| Library | Version | Purpose |
|---------|---------|---------|
| **libsodium** | 1.0.20 | Ed25519, X25519, XChaCha20-Poly1305, HKDF, randomness |
| **OpenSSL** | 3.3.2 (system preferred) | TLS for HTTPS, ACME client, X.509 |
| **frost-ed25519** (via `crates/frost-ffi`) | 2.2.0 | FROST threshold authority signatures |
| **TPM2-TSS (FAPI)** | 4.1.3 (source build, Linux) | TPM access for the `nexus-attestd` helper |

Application AEAD is XChaCha20-Poly1305-IETF only, in one versioned
`EncryptedBlob` format chosen at compile time, so ciphertexts are portable
across all supported machines.

## Networking

| Component | Purpose |
|-----------|---------|
| **asio** (1.34.2) | Async I/O: UDP sockets, timers, signals |
| **cpp-httplib** (0.18.3) | HTTP/HTTPS server and client |
| **BoringTun** (Rust crate via Corrosion) | Userspace WireGuard implementation |
| **virtual-netstack / smoltcp** (Rust crate) | Userspace TCP/IP: delivers virtual addresses to in-process listeners |

## Data and Infrastructure

| Library | Version | Purpose |
|---------|---------|---------|
| **nlohmann/json** | 3.12.0 | JSON parsing and serialization |
| **spdlog** | 1.16.0 | Structured logging |
| **jwt-cpp** | 0.7.0 | JWT session tokens |
| **magic_enum** | 0.9.7 | Enum reflection |
| **xxHash** | 0.8.3 | Non-cryptographic hashing (dedup caches) |
| **SQLite** | 3.46.1 (amalgamation) | Application ACL store |

## Desktop Client: Flutter

The desktop client (`apps/LemonadeNexusClient`) is a **Flutter/Dart**
application:

- Dart FFI over the C ABI (`lemonade_nexus.h`); the C++ SDK is not used
  directly from Dart.
- Riverpod for state management.
- WebAuthn passkeys via the platform security UIs; the client never handles
  the server's keys.
- macOS builds are CI-verified; Windows build definitions exist with CI
  disabled.

## Evidence Helper: nexus-attestd

A small separate C++ daemon (`projects/LemonadeNexusAttestd/`) that produces
platform evidence over one local socket. It runs under a dedicated service
identity with one capability (`CAP_DAC_READ_SEARCH`), one device
(`/dev/tpmrm0`), and filesystem isolation, and it holds no Nexus keys. See
[Attestation](Attestation).

## Why No Boost?

Boost is large and pulls many transitive dependencies. asio standalone
provides the async I/O the server needs.
