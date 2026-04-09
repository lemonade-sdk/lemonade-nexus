# Flutter Windows Client Documentation

**Version:** 1.0.0
**Last Updated:** 2026-04-09
**Status:** Complete - Production Ready

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [FFI Bindings](#ffi-bindings)
- [UI Component Structure](#ui-component-structure)
- [State Management Guide](#state-management-guide)
- [Windows-Specific Features](#windows-specific-features)
- [Testing](#testing)
- [Packaging](#packaging)
- [Troubleshooting](#troubleshooting)

---

## Overview

The Lemonade Nexus Flutter Windows Client is a cross-platform VPN client application built with Flutter/Dart. It provides a native Windows experience while sharing codebase with macOS and Linux platforms.

### Key Features

| Feature | Description |
|---------|-------------|
| **FFI Integration** | 69 C SDK functions wrapped with Dart FFI |
| **UI Views** | 12 views matching macOS SwiftUI application |
| **State Management** | Riverpod-based immutable state |
| **Windows Integration** | System tray, auto-start, Windows Service |
| **Testing** | 700+ tests covering all functionality |
| **Packaging** | MSIX, MSI, and portable EXE options |

### Application Structure

```
apps/LemonadeNexus/
├── lib/
│   ├── main.dart                 # App entry point
│   ├── theme/
│   │   └── app_theme.dart        # Theme configuration
│   └── src/
│       ├── sdk/                  # FFI bindings to C SDK
│       │   ├── ffi_bindings.dart     # Low-level FFI (1,400 lines)
│       │   ├── lemonade_nexus_sdk.dart # High-level SDK (1,100 lines)
│       │   ├── models.dart           # Data models (700 lines)
│       │   ├── models.g.dart         # JSON serialization (600 lines)
│       │   └── sdk.dart              # Barrel exports
│       ├── services/             # Business logic layer
│       │   ├── auth_service.dart
│       │   ├── tunnel_service.dart
│       │   ├── discovery_service.dart
│       │   └── tree_service.dart
│       ├── state/                # Riverpod state management
│       │   ├── app_state.dart        # AppNotifier, AppState
│       │   └── providers.dart        # All providers
│       ├── views/                # UI views (12 total)
│       │   ├── login_view.dart
│       │   ├── content_view.dart
│       │   ├── dashboard_view.dart
│       │   ├── tunnel_control_view.dart
│       │   ├── peers_view.dart
│       │   ├── network_monitor_view.dart
│       │   ├── tree_browser_view.dart
│       │   ├── node_detail_view.dart
│       │   ├── servers_view.dart
│       │   ├── certificates_view.dart
│       │   ├── settings_view.dart
│       │   └── vpn_menu_view.dart
│       └── windows/              # Windows-specific integration
│           ├── system_tray.dart
│           ├── auto_start.dart
│           ├── windows_service.dart
│           ├── windows_paths.dart
│           ├── windows_integration.dart
│           ├── tunnel_service.dart
│           ├── icon_helper.dart
│           └── windows_exports.dart
├── windows/
│   ├── runner/
│   │   ├── win32_window.h        # Native Windows declarations
│   │   ├── win32_window.cpp      # Native Windows implementation
│   │   └── main.cpp              # Windows app entry point
│   └── packaging/
│       ├── PACKAGING.md          # Packaging documentation
│       └── build.ps1             # Build scripts
├── test/
│   ├── ffi/                      # FFI binding tests
│   ├── unit/                     # Unit tests
│   ├── widget/                   # Widget tests
│   └── integration/              # Integration tests
└── pubspec.yaml                  # Dependencies
```

---

## Architecture

### Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      UI Layer                                │
│  (12 Flutter Views - ConsumerWidget/ConsumerStatefulWidget) │
├─────────────────────────────────────────────────────────────┤
│                       │                                      │
│                 ref.watch()                                  │
│                 ref.read()                                   │
├───────────────────────▼──────────────────────────────────────┤
│                    Providers                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ appNotifier  │  │ sdkProvider  │  │ themeProvider│       │
│  └──────┬───────┘  └──────────────┘  └──────────────┘       │
│         │                                                    │
│  ┌──────▼───────────────────────────────────────────┐       │
│  │           AppNotifier (StateNotifier)             │       │
│  │   - signIn/signOut                                │       │
│  │   - connectTunnel/disconnectTunnel                │       │
│  │   - enableMesh/disableMesh                        │       │
│  │   - refreshServers/refreshPeers                   │       │
│  └──────┬────────────────────────────────────────────┘       │
│         │                                                    │
│  ┌──────▼───────────────────────────────────────────┐       │
│  │              AppState (Immutable)                 │       │
│  └───────────────────────────────────────────────────┘       │
├──────────────────────────────────────────────────────────────┤
│                    Services Layer                             │
│  AuthService | TunnelService | DiscoveryService | TreeService│
├──────────────────────────────────────────────────────────────┤
│                    SDK Layer (FFI)                            │
│              LemonadeNexusSdk (Dart wrapper)                  │
├──────────────────────────────────────────────────────────────┤
│                    C SDK Layer                                │
│         lemonade_nexus_sdk.dll (69 C functions)               │
└──────────────────────────────────────────────────────────────┘
```

### Data Flow

```
User Action (UI)
      │
      ▼
┌─────────────┐
│   View      │  ref.read(notifier).action()
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ AppNotifier │  Business logic
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Service   │  Service-specific logic
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Lemonade    │  FFI marshalling
│ NexusSdk    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  C SDK      │  Native implementation
│  (DLL)      │
└─────────────┘
```

---

## FFI Bindings

### Overview

The Flutter client uses Dart FFI (Foreign Function Interface) to call the C SDK directly. All 69 functions from `lemonade_nexus.h` are wrapped.

### FFI Binding Structure

```dart
// ffi_bindings.dart - Low-level bindings

// Type definitions for C function signatures
typedef LnCreateNative = Pointer<Void> Function(
    Pointer<Utf8> host, Uint16 port);
typedef LnCreate = Pointer<Void> Function(String host, int port);

typedef LnHealthNative = Int32 Function(
    Pointer<Void> client, Pointer<Pointer<CChar>> outJson);
typedef LnHealth = int Function(
    Pointer<Void> client, Pointer<Pointer<CChar>> outJson);

// FFI class that loads and binds all functions
class LemonadeNexusFFI {
  final ffi.DynamicLibrary _lib;

  late final LnCreate _create;
  late final LnHealth _health;
  // ... 67 more functions

  LemonadeNexusFFI(String libPath) : _lib = ffi.DynamicLibrary.open(libPath) {
    _create = _lib.lookup<ffi.NativeFunction<LnCreateNative>>('ln_create')
        .asFunction<LnCreate>();
    _health = _lib.lookup<ffi.NativeFunction<LnHealthNative>>('ln_health')
        .asFunction<LnHealth>();
    // ... bind remaining functions
  }
}
```

### Memory Management Pattern

```dart
// Correct pattern for out_json parameters
Future<Map<String, dynamic>> health() async {
  final jsonPtr = calloc<Pointer<CChar>>();
  try {
    final result = _ffi._health(_client, jsonPtr);
    if (result != 0) {
      throw SdkException('Health check failed: $result');
    }
    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _ffi.lnFree(jsonPtr.value);  // SDK-allocated memory
    return jsonDecode(jsonString);
  } finally {
    calloc.free(jsonPtr);  // Dart-allocated pointer
  }
}

// Correct pattern for string parameters
Future<void> setSessionToken(String token) async {
  final tokenPtr = token.toNativeUtf8();
  try {
    _ffi.lnSetSessionToken(_client, tokenPtr);
  } finally {
    calloc.free(tokenPtr);
  }
}
```

### Error Handling

```dart
// LnError enum maps C error codes
enum LnError {
  ok(0),
  nullArg(-1),
  connect(-2),
  auth(-3),
  notFound(-4),
  rejected(-5),
  noIdentity(-6),
  internal(-99);

  final int code;
  const LnError(this.code);

  factory LnError.fromCode(int code) {
    return LnError.values.firstWhere(
      (e) => e.code == code,
      orElse: () => LnError.internal,
    );
  }
}

// Exception class for SDK errors
class SdkException implements Exception {
  final String message;
  final LnError? error;

  SdkException(this.message, {this.error});

  @override
  String toString() => 'SdkException: $message (${error?.name ?? "unknown"})';
}
```

### High-Level SDK Wrapper

```dart
// lemonade_nexus_sdk.dart - Idiomatic Dart API

class LemonadeNexusSdk {
  final LemonadeNexusFFI _ffi;
  Pointer<Void>? _client;

  // Lifecycle
  Future<void> connectTls(String host, int port) async {
    final hostPtr = host.toNativeUtf8();
    try {
      _client = _ffi.createTls(hostPtr, port);
    } finally {
      calloc.free(hostPtr);
    }
  }

  void dispose() {
    if (_client != null) {
      _ffi.destroy(_client!);
      _client = null;
    }
  }

  // Authentication
  Future<AuthResponse> authPassword(String username, String password) async {
    final result = await _callWithJson(
      (ptr) => _ffi.authPassword(_client, username.toNativeUtf8(),
                                   password.toNativeUtf8(), ptr),
    );
    return AuthResponse.fromJson(result);
  }

  // Tunnel operations
  Future<TunnelStatus> tunnelUp(WgConfig config) async {
    final configJson = jsonEncode(config.toJson());
    final result = await _callWithJson(
      (ptr) => _ffi.tunnelUp(_client, configJson.toNativeUtf8(), ptr),
    );
    return TunnelStatus.fromJson(result);
  }

  // Helper for JSON-returning functions
  Future<Map<String, dynamic>> _callWithJson(
    int Function(Pointer<Pointer<CChar>>) call,
  ) async {
    final jsonPtr = calloc<Pointer<CChar>>();
    try {
      final result = call(jsonPtr);
      if (result != 0) {
        throw SdkException('Operation failed: $result',
            error: LnError.fromCode(result));
      }
      final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
      _ffi.lnFree(jsonPtr.value);
      return jsonDecode(jsonString);
    } finally {
      calloc.free(jsonPtr);
    }
  }
}
```

### Model Classes

```dart
// models.dart - Type-safe data models

@JsonSerializable()
class AuthResponse {
  final String sessionToken;
  final String userId;
  final String username;
  final String? publicKey;

  AuthResponse({
    required this.sessionToken,
    required this.userId,
    required this.username,
    this.publicKey,
  });

  factory AuthResponse.fromJson(Map<String, dynamic> json) =>
      _$AuthResponseFromJson(json);

  Map<String, dynamic> toJson() => _$AuthResponseToJson(this);
}

@JsonSerializable()
class TunnelStatus {
  final bool isUp;
  final String? tunnelIp;
  final int? peerCount;
  final int bytesReceived;
  final int bytesSent;
  final DateTime? lastHandshake;

  TunnelStatus({
    required this.isUp,
    this.tunnelIp,
    this.peerCount,
    required this.bytesReceived,
    required this.bytesSent,
    this.lastHandshake,
  });

  factory TunnelStatus.fromJson(Map<String, dynamic> json) =>
      _$TunnelStatusFromJson(json);

  Map<String, dynamic> toJson() => _$TunnelStatusToJson(this);
}
```

---

## UI Component Structure

### View Hierarchy

```
MaterialApp
└── ProviderScope
    └── AppShell (ConsumerStatefulWidget)
        ├── LoginView (not authenticated)
        └── ContentView (authenticated)
            ├── Navigation Rail
            │   ├── Dashboard
            │   ├── Tunnel Control
            │   ├── Peers
            │   ├── Network Monitor
            │   ├── Tree Browser
            │   ├── Servers
            │   ├── Certificates
            │   └── Settings
            └── Detail View Area
```

### View Components

#### LoginView

```dart
class LoginView extends ConsumerStatefulWidget {
  @override
  _LoginViewState createState() => _LoginViewState();
}

class _LoginViewState extends ConsumerState<LoginView> {
  final _formKey = GlobalKey<FormState>();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  bool _isLoading = false;
  String? _errorMessage;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFF1A1A2E), Color(0xFF16213E)],
          ),
        ),
        child: Center(
          child: Card(
            child: Form(
              key: _formKey,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  LogoWidget(),  // Custom logo with network lines
                  TextFormField(controller: _usernameController),
                  TextFormField(controller: _passwordController),
                  if (_errorMessage != null)
                    Text(_errorMessage!, style: errorStyle),
                  ElevatedButton(
                    onPressed: _isLoading ? null : _handleLogin,
                    child: _isLoading
                        ? CircularProgressIndicator()
                        : Text('Sign In'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _handleLogin() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() => _isLoading = true);

    try {
      final notifier = ref.read(appNotifierProvider.notifier);
      final success = await notifier.signIn(
        _usernameController.text,
        _passwordController.text,
      );

      if (!success && mounted) {
        setState(() => _errorMessage = 'Authentication failed');
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }
}
```

#### DashboardView

```dart
class DashboardView extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appState = ref.watch(appNotifierProvider);

    return SingleChildScrollView(
      child: Column(
        children: [
          // Stats Row
          _buildStatsRow(appState),

          // Mesh Status Row
          _buildMeshStatusRow(appState),

          // Recent Activity
          _buildActivitySection(appState),
        ],
      ),
    );
  }

  Widget _buildStatsRow(AppState state) {
    return Row(
      children: [
        _buildStatCard('Peers', '${state.stats?.peerCount ?? 0}'),
        _buildStatCard('Servers', '${state.servers.length}'),
        _buildStatCard('Relays', '${state.relays.length}'),
        _buildStatCard('Uptime', _formatUptime(state.stats?.uptime)),
      ],
    );
  }
}
```

### Reusable Widget Patterns

```dart
// Card pattern used throughout
Widget _buildCard({required Widget child}) {
  return Container(
    decoration: BoxDecoration(
      color: Color(0xFF16213E),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: Color(0xFF2D3748)),
    ),
    padding: EdgeInsets.all(16),
    child: child,
  );
}

// Status badge pattern
Widget _buildStatusBadge({required String label, required Color color}) {
  return Container(
    padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
    decoration: BoxDecoration(
      color: color.withOpacity(0.2),
      borderRadius: BorderRadius.circular(4),
      border: Border.all(color: color),
    ),
    child: Text(
      label,
      style: TextStyle(color: color, fontSize: 12),
    ),
  );
}

// Detail row pattern
Widget _buildDetailRow({required String label, required String value}) {
  return Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      SizedBox(
        width: 120,
        child: Text(label, style: labelStyle),
      ),
      Expanded(
        child: Text(value, style: valueStyle),
      ),
    ],
  );
}
```

---

## State Management Guide

### AppState Structure

```dart
class AppState {
  final ConnectionStatus connectionStatus;
  final AuthState authState;
  final PeerState peerState;
  final Settings settings;
  final TunnelStatus? tunnelStatus;
  final HealthResponse? healthStatus;
  final ServiceStats? stats;
  final List<ServerInfo> servers;
  final List<RelayInfo> relays;
  final List<CertStatus> certificates;
  final List<TreeNode> treeNodes;
  final TreeNode? rootNode;
  final TrustStatus? trustStatus;
  final SidebarItem selectedSidebarItem;
  final bool isLoading;
  final String? errorMessage;
  final List<ActivityEntry> activityLog;

  AppState copyWith({
    ConnectionStatus? connectionStatus,
    AuthState? authState,
    PeerState? peerState,
    Settings? settings,
    // ... other fields
  }) {
    return AppState(
      connectionStatus: connectionStatus ?? this.connectionStatus,
      authState: authState ?? this.authState,
      // ... other fields
    );
  }

  factory AppState.initial() => AppState(
    connectionStatus: ConnectionStatus.disconnected,
    authState: AuthState.initial(),
    peerState: PeerState.initial(),
    settings: Settings.defaultSettings(),
    // ... other initial values
  );
}
```

### AppNotifier Methods

```dart
class AppNotifier extends StateNotifier<AppState> {
  final LemonadeNexusSdk _sdk;

  AppNotifier(this._sdk) : super(AppState.initial());

  // Authentication
  Future<bool> signIn(String username, String password) async {
    state = state.copyWith(isLoading: true, errorMessage: null);
    try {
      await _sdk.connectTls(state.settings.serverHost, state.settings.serverPort);
      final identity = await _sdk.deriveSeed(username, password);
      await _sdk.setIdentity(identity);
      final auth = await _sdk.authPassword(username, password);
      _sdk.setSessionToken(auth.sessionToken);

      state = state.copyWith(
        authState: AuthState(
          isAuthenticated: true,
          username: auth.username,
          userId: auth.userId,
          sessionToken: auth.sessionToken,
        ),
        isLoading: false,
      );
      return true;
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        errorMessage: e.toString(),
      );
      return false;
    }
  }

  // Tunnel control
  Future<void> connectTunnel() async {
    state = state.copyWith(
      connectionStatus: ConnectionStatus.connecting,
    );
    try {
      final config = await _prepareWireGuardConfig();
      await _sdk.tunnelUp(config);
      state = state.copyWith(
        connectionStatus: ConnectionStatus.connected,
      );
    } catch (e) {
      state = state.copyWith(
        connectionStatus: ConnectionStatus.error,
        errorMessage: e.toString(),
      );
    }
  }

  // Mesh networking
  Future<void> enableMesh() async {
    await _sdk.enableMesh();
    await refreshPeers();
  }
}
```

### Provider Definitions

```dart
// providers.dart

// SDK Provider
final sdkProvider = Provider<LemonadeNexusSdk>((ref) {
  final sdk = LemonadeNexusSdk();
  ref.onDispose(() => sdk.dispose());
  return sdk;
});

// Main App State Provider
final appNotifierProvider = StateNotifierProvider<AppNotifier, AppState>((ref) {
  return AppNotifier(ref.watch(sdkProvider));
});

// Selector Providers
final authStateProvider = Provider<AuthState>((ref) {
  return ref.watch(appNotifierProvider).authState;
});

final connectionStatusProvider = Provider<ConnectionStatus>((ref) {
  return ref.watch(appNotifierProvider).connectionStatus;
});

// Service Providers
final authServiceProvider = Provider<AuthService>((ref) {
  return AuthService(
    ref.watch(sdkProvider),
    ref.watch(appNotifierProvider.notifier),
  );
});
```

### Usage in Views

```dart
// Reading state
class MyView extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Watch full state
    final appState = ref.watch(appNotifierProvider);

    // Or watch specific slice
    final authState = ref.watch(authStateProvider);

    return Text('Hello, ${authState.username}');
  }
}

// Calling methods
class MyView extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return ElevatedButton(
      onPressed: () async {
        final notifier = ref.read(appNotifierProvider.notifier);
        await notifier.connectTunnel();
      },
      child: Text('Connect'),
    );
  }
}
```

---

## Windows-Specific Features

### System Tray Integration

```dart
// system_tray.dart
class WindowsSystemTray extends TrayListener {
  final Ref _ref;
  TrayIcon? _trayIcon;

  WindowsSystemTray(this._ref);

  Future<void> initialize() async {
    await trayManager.setIcon(
      Platform.isWindows
          ? 'assets/icons/tray_icon_connected.ico'
          : 'assets/icons/tray_icon_connected.png',
    );
    await trayManager.setToolTip('Lemonade Nexus VPN');

    final menu = Menu(items: [
      MenuItem(
        key: 'connect',
        label: 'Connect',
      ),
      MenuItem(
        key: 'disconnect',
        label: 'Disconnect',
      ),
      MenuItem.separator(),
      MenuItem(
        key: 'dashboard',
        label: 'Dashboard',
      ),
      MenuItem(
        key: 'settings',
        label: 'Settings',
      ),
      MenuItem.separator(),
      MenuItem(
        key: 'exit',
        label: 'Exit',
      ),
    ]);

    await trayManager.setContextMenu(menu);
    trayManager.addListener(this);
  }

  @override
  void onTrayIconRightMouseDown() {
    trayManager.popUpContextMenu();
  }

  @override
  void onTrayIconLeftMouseDown() {
    windowManager.show();
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) async {
    final notifier = _ref.read(appNotifierProvider.notifier);

    switch (menuItem.key) {
      case 'connect':
        await notifier.connectTunnel();
        break;
      case 'disconnect':
        await notifier.disconnectTunnel();
        break;
      case 'dashboard':
        await windowManager.show();
        break;
      case 'exit':
        await _exitApplication();
        break;
    }

    await _updateTrayTooltip();
  }

  Future<void> _updateTrayTooltip() async {
    final state = _ref.read(appNotifierProvider);
    String tooltip = 'Lemonade Nexus VPN';

    if (state.connectionStatus == ConnectionStatus.connected) {
      tooltip += ' - Connected (${state.tunnelStatus?.tunnelIp})';
    } else if (state.connectionStatus == ConnectionStatus.connecting) {
      tooltip += ' - Connecting...';
    } else {
      tooltip += ' - Disconnected';
    }

    await trayManager.setToolTip(tooltip);
  }
}
```

### Auto-Start on Login

```dart
// auto_start.dart
import 'package:win32_registry/win32_registry.dart';

class WindowsAutoStart {
  static const String _runKey =
      r'Software\Microsoft\Windows\CurrentVersion\Run';
  static const String _valueName = 'LemonadeNexus';

  Future<void> enable() async {
    final reg = Registry.currentUser;
    final key = reg.createKey(_runKey);

    final exePath = Platform.resolvedExecutable;
    key.createStringValue(_valueName, exePath);

    key.close();
    reg.close();
  }

  Future<void> disable() async {
    final reg = Registry.currentUser;
    final key = reg.createKey(_runKey);

    key.deleteValue(_valueName);

    key.close();
    reg.close();
  }

  bool isEnabled() {
    try {
      final reg = Registry.currentUser;
      final key = reg.createKey(_runKey);
      final value = key.getStringValue(_valueName);
      key.close();
      reg.close();
      return value != null;
    } catch (e) {
      return false;
    }
  }
}
```

### Windows Service Integration

```dart
// windows_service.dart
import 'dart:ffi';
import 'package:win32/win32.dart';

class WindowsServiceManager {
  static const String _serviceName = 'LemonadeNexusService';
  static const String _displayName = 'Lemonade Nexus VPN Service';

  void install() {
    final hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM == nullptr) {
      throw WindowsException('Failed to open SCM');
    }

    try {
      final exePath = Platform.resolvedExecutable;
      final hService = CreateService(
        hSCM,
        _serviceName.toNativeUtf16(),
        _displayName.toNativeUtf16(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath.toNativeUtf16(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
      );

      if (hService == nullptr) {
        throw WindowsException('Failed to create service');
      }

      // Configure recovery (restart on failure)
      final actions = calloc<SC_ACTION>(3);
      actions[0].type = SC_ACTION_RESTART;
      actions[0].delay = 60000;  // 1 minute
      actions[1].type = SC_ACTION_RESTART;
      actions[1].delay = 60000;
      actions[2].type = SC_ACTION_RESTART;
      actions[2].delay = 60000;

      final failureActions = SERVICE_FAILURE_ACTIONS();
      failureActions.cActions = 3;
      failureActions.lpsaActions = actions;

      ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS,
          failureActions.cast());

      CloseServiceHandle(hService);
    } finally {
      CloseServiceHandle(hSCM);
    }
  }

  bool isInstalled() {
    final hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM == nullptr) return false;

    try {
      final hService = OpenService(hSCM, _serviceName.toNativeUtf16(),
          SERVICE_QUERY_STATUS);
      if (hService != nullptr) {
        CloseServiceHandle(hService);
        return true;
      }
      return false;
    } finally {
      CloseServiceHandle(hSCM);
    }
  }

  void start() {
    final hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    final hService = OpenService(hSCM, _serviceName.toNativeUtf16(),
        SERVICE_START);

    if (!StartService(hService, 0, nullptr)) {
      throw WindowsException('Failed to start service');
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
  }

  void stop() {
    final hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    final hService = OpenService(hSCM, _serviceName.toNativeUtf16(),
        SERVICE_STOP);

    final status = SERVICE_STATUS();
    ControlService(hService, SERVICE_CONTROL_STOP, status);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
  }

  void uninstall() {
    final hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    final hService = OpenService(hSCM, _serviceName.toNativeUtf16(), DELETE);

    DeleteService(hService);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
  }
}
```

### Windows Path Management

```dart
// windows_paths.dart
import 'dart:io';
import 'package:path_provider/path_provider.dart';

class WindowsPaths {
  Future<String> getConfigDir() async {
    final appData = Platform.environment['APPDATA'];
    final path = Directory('$appData\\LemonadeNexus\\config');
    if (!await path.exists()) {
      await path.create(recursive: true);
    }
    return path.path;
  }

  Future<String> getDataDir() async {
    final localAppData = Platform.environment['LOCALAPPDATA'];
    final path = Directory('$localAppData\\LemonadeNexus\\data');
    if (!await path.exists()) {
      await path.create(recursive: true);
    }
    return path.path;
  }

  Future<String> getTunnelPath(String filename) async {
    final localAppData = Platform.environment['LOCALAPPDATA'];
    final path = Directory('$localAppData\\LemonadeNexus\\tunnel');
    if (!await path.exists()) {
      await path.create(recursive: true);
    }
    return '$path\\$filename';
  }

  Future<String> getLogDir() async {
    final programData = Platform.environment['PROGRAMDATA'];
    final path = Directory('$programData\\LemonadeNexus\\logs');
    if (!await path.exists()) {
      await path.create(recursive: true);
    }
    return path.path;
  }

  Future<void> createAllDirectories() async {
    await getConfigDir();
    await getDataDir();
    await getTunnelPath('');
    await getLogDir();
  }
}
```

---

## Testing

### Test Categories

| Category | Location | Count | Coverage Target |
|----------|----------|-------|-----------------|
| FFI Tests | `test/ffi/` | ~150 | 95% |
| Unit Tests | `test/unit/` | ~300 | 90% |
| Widget Tests | `test/widget/` | ~500 | 75% |
| Integration Tests | `test/integration/` | ~30 | 85% |
| **Total** | | **~700+** | **80%+** |

### Running Tests

```bash
# Run all tests
cd apps/LemonadeNexus
flutter test

# Run specific category
flutter test test/ffi/
flutter test test/unit/
flutter test test/widget/
flutter test test/integration/

# Run with coverage
flutter test --coverage

# View coverage report
genhtml coverage/lcov.info -o coverage/html
```

### Test Examples

```dart
// FFI binding test
test('ln_health returns valid JSON', () async {
  final sdk = LemonadeNexusSdk();
  await sdk.connectTls('test.example.com', 443);

  try {
    final health = await sdk.health();
    expect(health, containsPair('status', 'ok'));
  } finally {
    sdk.dispose();
  }
});

// Unit test for model
test('AuthResponse serializes correctly', () {
  final auth = AuthResponse(
    sessionToken: 'token123',
    userId: 'user456',
    username: 'testuser',
  );

  final json = auth.toJson();
  expect(json['sessionToken'], 'token123');
  expect(json['userId'], 'user456');
  expect(json['username'], 'testuser');

  final roundTrip = AuthResponse.fromJson(json);
  expect(roundTrip.sessionToken, auth.sessionToken);
});

// Widget test
testWidgets('LoginView shows error on failed auth', (tester) async {
  final mockNotifier = MockAppNotifier();
  when(mockNotifier.signIn(any, any))
      .thenAnswer((_) async => false);

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        appNotifierProvider.overrideWith((ref) => mockNotifier),
      ],
      child: MaterialApp(home: LoginView()),
    ),
  );

  await tester.enterText(find.byType(TextFormField).at(0), 'user');
  await tester.enterText(find.byType(TextFormField).at(1), 'wrong');
  await tester.tap(find.text('Sign In'));
  await tester.pumpAndSettle();

  expect(find.text('Authentication failed'), findsOneWidget);
});
```

---

## Packaging

### Package Types

| Package | File | Best For |
|---------|------|----------|
| MSIX | `lemonade_nexus-<version>.msix` | Modern Windows, Microsoft Store |
| MSI | `lemonade_nexus_setup-<version>.msi` | Enterprise deployment |
| Portable EXE | `lemonade_nexus_portable-<version>.zip` | Testing, portable use |

### Building Packages

```powershell
# Navigate to Flutter app
cd apps/LemonadeNexus

# Get dependencies
flutter pub get

# Build all packages
.\windows\packaging\build.ps1 -BuildType all

# Build specific package
.\windows\packaging\build.ps1 -BuildType msix
.\windows\packaging\build.ps1 -BuildType msi
```

### MSIX Configuration

```yaml
# In pubspec.yaml
msix_config:
  display_name: Lemonade Nexus VPN
  publisher_display_name: Lemonade Nexus
  identity_name: LemonadeNexus.LemonadeNexusVPN
  publisher: CN=PublisherName
  version: 1.0.0.0
  logo_path: assets\icons\app_icon.png
  capabilities: internetClient, privateNetworkClientServer
  start_menu_display_name: Lemonade Nexus VPN
  languages: en-us
```

---

## Troubleshooting

### FFI Loading Issues

#### Error: "Dynamic library not found"

```
Invalid argument(s): Failed to load dynamic library 'lemonade_nexus_sdk.dll'
```

**Solution:** Ensure the DLL is in the correct location:
```powershell
# Copy DLL to Flutter windows directory
copy ..\..\build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll windows\
```

### State Management Issues

#### Error: "ref.watch() called inside build but provider not ready"

**Solution:** Ensure ProviderScope wraps the entire app:
```dart
void main() {
  runApp(
    ProviderScope(
      child: MyApp(),
    ),
  );
}
```

### Windows Integration Issues

#### System tray not appearing

**Solution:** Check that tray_manager is initialized:
```dart
if (Platform.isWindows) {
  await trayManager.setIcon('assets/icons/tray_icon.ico');
}
```

#### Auto-start not working

**Solution:** Run as standard user (not admin) for registry-based auto-start.

---

## Related Documentation

- [Windows Port](WINDOWS-PORT.md) - C++ server port details
- [Installation Guide](INSTALLATION.md) - Installation procedures
- [Development Guide](DEVELOPMENT.md) - Development environment setup
- [State Management](STATE_MANAGEMENT.md) - Detailed Riverpod guide

---

**Document History:**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-09 | Initial release |
