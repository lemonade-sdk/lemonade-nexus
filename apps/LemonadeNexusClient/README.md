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

## Device identity

The client is its own mesh node and has one Ed25519 device identity per
signed-in OS user. The SDK owns it: the per-user identity store
(`ln_identity_user_*`, see [SDK Guide: Identity Storage](../../docs/SDK-Guide.md#identity-storage))
wraps the seed under a key held by the OS keystore (macOS login Keychain,
Windows DPAPI, Secret Service on Linux) and keeps the wrapped file in the
user's own directory. The app never generates a key of its own and keeps no
seed in `flutter_secure_storage`.

- On start, and before any register, join, connect, or passkey flow, the app
  loads the stored identity (`lib/src/state/app_state.dart`,
  `prepareDeviceIdentity`); when none is stored it creates one.
- There is no fallback. When no keystore is usable, the keystore is locked,
  or the store directory cannot be written, the identity is unavailable, the
  action fails with the reason, and Settings > Identity shows the key store,
  the store state, the directory, and a Retry button.
- One-time migration: a legacy per-Cluster seed in the keyring or an
  `identity.json` in the app support directory is imported into the store
  (most recently used first), the store's public key is checked against it,
  and the legacy copy is deleted. When the store already holds a different
  identity the legacy copy is kept, reported in the activity log, and never
  used; such a Cluster card refuses to connect until it is forgotten and
  joined again with an invitation.
- `flutter_secure_storage` still holds the session token and user metadata
  (`lib/src/platform/secure_store.dart`) and the Cluster keyring: group keys,
  membership metadata, and server addresses (`lib/src/state/cluster_keyring.dart`).
- After a confirmed account deletion the server has revoked the key, so the
  app removes the stored identity and creates a new one.

The decision logic lives in `lib/src/state/device_identity.dart` and is unit
tested without the native library.

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

4. Build the native SDK shared library (from the repo root). CMake
   downloads the pinned static OpenSSL archive and links it, so the dylib/DLL
   loads no Homebrew or system OpenSSL:
   ```bash
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
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
