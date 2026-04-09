# Lemonade Nexus - Flutter Windows Client

VPN mesh network client for Windows built with Flutter/Dart.

## Overview

This Flutter application provides a Windows-native client for the Lemonade Nexus WireGuard mesh VPN network. It uses FFI bindings to communicate with the C SDK (`lemonade_nexus.h`).

## Architecture

```
lib/
├── main.dart              # App entry point
├── src/
│   ├── sdk/               # FFI bindings to C SDK
│   │   ├── lemonade_nexus_sdk.dart
│   │   └── ffi_bindings.dart
│   ├── services/          # Business logic layer
│   │   ├── tunnel_service.dart
│   │   ├── auth_service.dart
│   │   └── dns_discovery.dart
│   ├── state/             # Riverpod state management
│   │   ├── app_state.dart
│   │   └── providers.dart
│   └── views/             # UI views (12 total)
│       ├── login_view.dart
│       ├── dashboard_view.dart
│       ├── tunnel_control_view.dart
│       ├── peers_view.dart
│       ├── network_monitor_view.dart
│       ├── tree_browser_view.dart
│       ├── servers_view.dart
│       ├── certificates_view.dart
│       └── settings_view.dart
└── theme/
    └── app_theme.dart
```

## Prerequisites

- Flutter SDK 3.x+
- Dart SDK 3.x+
- Visual Studio Build Tools (Windows)
- C SDK library (`lemonade_nexus_sdk.dll`)

## Setup

1. Install Flutter:
   ```bash
   flutter doctor
   ```

2. Enable Windows desktop:
   ```bash
   flutter config --enable-windows-desktop
   ```

3. Install dependencies:
   ```bash
   flutter pub get
   ```

4. Build C SDK (from root):
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   cmake --build build --target LemonadeNexusSDK
   ```

5. Copy SDK DLL:
   ```bash
   copy build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll windows\
   ```

## Development

Run the app:
```bash
flutter run -d windows
```

Hot reload during development:
- Press `r` to hot reload
- Press `R` to hot restart
- Press `q` to quit

## Building for Release

```bash
flutter build windows --release
```

Output: `build/windows/runner/Release/lemonade_nexus.exe`

## Packaging

Create MSIX package:
```bash
flutter pub run msix:create
```

## Testing

Run all tests:
```bash
flutter test
```

Run integration tests:
```bash
flutter test integration_test/
```

## UI Views (Matching macOS App)

All 12 Flutter views have been implemented with full parity to macOS SwiftUI views:

| View | macOS Equivalent | Status |
|------|------------------|--------|
| LoginView | LoginView.swift | Implemented |
| ContentView | ContentView.swift | Implemented |
| DashboardView | DashboardView.swift | Implemented |
| TunnelControlView | TunnelControlView.swift | Implemented |
| PeersView | PeersListView.swift | Implemented |
| NetworkMonitorView | NetworkMonitorView.swift | Implemented |
| TreeBrowserView | TreeBrowserView.swift | Implemented |
| NodeDetailView | NodeDetailView.swift | Implemented |
| ServersView | ServersView.swift | Implemented |
| CertificatesView | CertificatesView.swift | Implemented |
| SettingsView | SettingsView.swift | Implemented |
| VPNMenuView | VPNMenuView.swift | Implemented |

## Agent Ecosystem

This project is built by a team of specialized subagents:

| Agent | Responsibility |
|-------|---------------|
| @ffi-bindings-agent | FFI wrappers for C SDK |
| @ui-components-agent | Flutter UI views |
| @state-management-agent | Riverpod state |
| @windows-integration-agent | Windows native APIs |
| @testing-agent | Test suite |
| @packaging-agent | MSIX packaging |

## License

Proprietary - Lemonade Nexus
