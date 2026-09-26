# Lemonade Nexus — Flutter Desktop Client

Desktop client (macOS + Windows) for the Lemonade Nexus userspace mesh, built
with Flutter/Dart. It uses FFI bindings to communicate with the C SDK
(`lemonade_nexus.h`).

## Overview

The client is a consumer of the C ABI over Dart FFI: identity and
authentication (Ed25519 challenge-response, WebAuthn passkeys), join, tree
operations, P2P mesh, certificates, and the admin console. The mesh dataplane
is the SDK's in-process userspace BoringTun — no TUN device, no admin
rights.

Authentication note: password login is a **deprecated server stub** (always
fails). The supported paths are the Ed25519 identity and passkeys; the login
UI's password field exists only for compatibility.

## Architecture

```
lib/
├── main.dart              # App entry point
├── src/
│   ├── api/               # REST/SSE client for the admin endpoint
│   ├── platform/          # Paths, secure store, platform integration
│   ├── sdk/               # FFI bindings to the C SDK
│   │   ├── ffi_bindings.dart
│   │   ├── lemonade_nexus_sdk.dart
│   │   └── models.dart (+ generated models.g.dart)
│   ├── services/          # dns_discovery.dart, passkey_manager.dart
│   ├── state/             # Riverpod state (app_state, cluster keyring, providers)
│   ├── views/             # UI views (see below)
│   └── windows/           # Windows integration: system tray, autostart, service
└── theme/                 # app_theme.dart, components.dart
```

Views: `login_view`, `main_navigation`, `dashboard_view`, `peers_view`,
`network_monitor_view`, `tree_browser_view`, `node_detail_view`,
`servers_view`, `certificates_view`, `settings_view`, `account_view`, and the
`admin_console/` widget group (dashboard, backends, logs, models, system
info).

## Prerequisites

- Flutter SDK 3.x+ (Dart 3.x+)
- CMake + Ninja, plus a C/C++ toolchain: Xcode (macOS) or Visual Studio
  Build Tools (Windows)
- The native SDK shared library, built from the repo root
  (`liblemonade_nexus_sdk.dylib` on macOS, `lemonade_nexus_sdk.dll` on
  Windows)

## Setup

1. Check the toolchain:
   ```bash
   flutter doctor
   ```

2. Enable desktop:
   ```bash
   flutter config --enable-macos-desktop    # or --enable-windows-desktop
   ```

3. Install dependencies:
   ```bash
   flutter pub get
   ```

4. Build the native SDK shared library (from the repo root).
   `OPENSSL_FORCE_BUNDLED=ON` statically bundles OpenSSL so the dylib/DLL is
   self-contained — without it the macOS dylib links Homebrew's OpenSSL and
   the app fails to load it at runtime:
   ```bash
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_FORCE_BUNDLED=ON
   cmake --build build --target LemonadeNexusSDKShared --parallel
   ```

5. **Windows only** — stage the SDK DLL next to the runner (macOS
   auto-embeds the dylib via the Xcode "Embed Lemonade Nexus SDK" build
   phase):
   ```bat
   copy build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll windows\
   ```

## Development

```bash
flutter run -d macos      # or: flutter run -d windows
```

Hot reload during development: `r` (hot reload), `R` (hot restart), `q`
(quit).

## Building for Release

```bash
flutter build macos --release      # or: flutter build windows --release
```

Output:
- macOS: `build/macos/Build/Products/Release/nexus-client.app`
- Windows: `build/windows/x64/runner/Release/nexus-client.exe`

## Packaging

MSIX via the `msix` plugin (configuration in `pubspec.yaml`):

```bash
flutter pub run msix:create
```

See the [Windows packaging guide](windows/packaging/PACKAGING.md) for MSIX,
MSI, and portable builds, signing, and distribution.

## Testing

```bash
flutter test
```

## CI Status

The macOS client job in
[`.github/workflows/flutter-clients.yml`](../../.github/workflows/flutter-clients.yml)
runs on every push (analyze, test, release build, and SDK-embedding checks).
The Windows job is currently disabled (`if: false`); validate Windows builds
locally.

## License

[MIT](../../LICENSE) — the same license as the rest of the repository.
