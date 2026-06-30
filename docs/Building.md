---
layout: default
title: Building from Source
---

# Building from Source

## Table of Contents
- [Prerequisites](#prerequisites)
- [Linux Build](#linux-build)
- [macOS Build](#macos-build)
- [Windows Build](#windows-build)
- [macOS Client App](#macos-client-app)
- [Running Tests](#running-tests)

## Prerequisites

- **C++20** compiler (GCC 12+, Clang 15+, MSVC 2022+)
- **CMake** 3.25.1+
- **Ninja** build system
- **Rust** toolchain (for BoringTun)
- **Git**

All C++ dependencies are fetched automatically via CMake FetchContent.

## Linux Build

```bash
git clone https://github.com/lemonade-sdk/lemonade-nexus.git
cd lemonade-nexus
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

The server binary is at `build/projects/LemonadeNexus/lemonade-nexus`.

### Install

```bash
sudo cp build/projects/LemonadeNexus/lemonade-nexus /usr/local/bin/
sudo mkdir -p /var/lib/lemonade-nexus
```

### systemd Service

```ini
[Unit]
Description=Lemonade-Nexus Mesh VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/lib/lemonade-nexus
ExecStart=/usr/local/bin/lemonade-nexus --dns-port 5353
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## macOS Build

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(sysctl -n hw.ncpu)
```

## Windows Build

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Requires Visual Studio 2022 Build Tools with C++ workload.

## Flutter Client App

The desktop client (`apps/LemonadeNexus`) is a Flutter app that talks to the C
SDK over FFI. Build the SDK **shared** library first, then run Flutter.

### macOS

```bash
# 1. Build the SDK dylib from the repo root
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target LemonadeNexusSDKShared

# 2. Run / build the app — the Xcode "Embed Lemonade Nexus SDK" build phase
#    copies and codesigns the dylib into the .app automatically (no manual copy)
cd apps/LemonadeNexus
flutter pub get
flutter run -d macos              # development (hot reload)
flutter build macos --release     # release build
```

Output: `apps/LemonadeNexus/build/macos/Build/Products/Release/lemonade_nexus.app`.
Set `LN_DEBUG=1` to surface verbose SDK + mesh diagnostics in the console.

### Windows

See [`apps/LemonadeNexus/README.md`](../apps/LemonadeNexus/README.md) — the
Windows runner needs the SDK DLL staged into `apps/LemonadeNexus/windows/` before
`flutter build windows`.

CI builds both desktop targets on every push — see
[`.github/workflows/flutter-clients.yml`](../.github/workflows/flutter-clients.yml).

## Running Tests

```bash
cd build
ctest --output-on-failure -j$(nproc)
```

Expected: 309 tests pass (4 ACME staging tests disabled).

## Dependencies (auto-fetched)

| Library | Version | Purpose |
|---------|---------|---------|
| libsodium | 1.0.20 | Ed25519, X25519, AEAD, HKDF |
| OpenSSL | 3.3.2 | TLS, ACME client |
| asio | 1.34.2 | Async I/O (UDP, timers) |
| cpp-httplib | 0.18.3 | HTTP/HTTPS server+client |
| nlohmann/json | 3.12.0 | JSON parsing |
| spdlog | 1.16.0 | Structured logging |
| jwt-cpp | 0.7.0 | JWT tokens |
| magic_enum | 0.9.7 | Enum reflection |
| xxHash | 0.8.3 | Fast hashing |
| BoringTun | (Rust crate) | Userspace WireGuard |
