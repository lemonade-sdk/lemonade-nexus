# Frameworks and Libraries

## Core Language: C++20

The entire server and SDK are written in C++20 with a **CRTP-only architecture** — no virtual functions anywhere. This eliminates vtable overhead and enables compile-time polymorphism.

## Build System: CMake 3.25 + Ninja

All dependencies are fetched automatically via CMake `FetchContent`. No system packages to install beyond a C++20 compiler and Rust toolchain.

## Cryptography

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| **libsodium** | 1.0.20 | Ed25519, X25519, XChaCha20-Poly1305, AES-256-GCM, HKDF, random | Battle-tested, misuse-resistant API, constant-time operations |
| **OpenSSL** | 3.3.2 | TLS for HTTPS, ACME client, X.509 certificates | Industry standard TLS, built from source (no Homebrew dependency) |

## Networking

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| **asio** | 1.34.2 | Async I/O: UDP sockets, timers, signal handling | Lightweight, no Boost dependency (standalone mode) |
| **cpp-httplib** | 0.18.3 | HTTP/HTTPS server and client | Header-only, supports TLS, simple API |
| **BoringTun** | Rust crate | Userspace WireGuard implementation | Cross-platform, no kernel module required, embeddable |

## Data

| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| **nlohmann/json** | 3.12.0 | JSON parsing and serialization | De facto C++ JSON standard, intuitive API |
| **spdlog** | 1.16.0 | Structured logging | Fast, fmt-based, compile-time format checks |
| **jwt-cpp** | 0.7.0 | JWT token generation and validation | Lightweight, header-only |
| **magic_enum** | 0.9.7 | Enum-to-string reflection | Zero overhead, compile-time |
| **xxHash** | 0.8.3 | Fast non-cryptographic hashing | Deduplication in gossip delta caches |

## Client (macOS)

| Framework | Purpose |
|-----------|---------|
| **Swift 5.9+ / SwiftUI** | Native macOS app with system tray |
| **Security.framework** | Keychain storage, Secure Enclave passkeys |
| **Network.framework** | UDP DNS queries |
| **LocalAuthentication** | Touch ID biometric for passkey signing |
| **CoreFoundation** | Apple Secure Enclave TEE backend (pure C APIs) |

## Why No Boost?

Boost is large and pulls in many transitive dependencies. asio standalone provides everything we need for async I/O. Every other dependency is either header-only or fetched via FetchContent with minimal footprint.

## Why No Virtual Functions?

CRTP (Curiously Recurring Template Pattern) gives us:
- **Zero-overhead polymorphism** — no vtable pointer per object, no indirect calls
- **Compile-time type safety** — template errors at compile time, not runtime crashes
- **Inlinability** — compiler can inline through CRTP dispatch, impossible with virtual
- **Concepts** — C++20 concepts constrain CRTP implementations at the interface level

The tradeoff is more verbose template code, but for a security-critical system, the performance and safety guarantees are worth it.
