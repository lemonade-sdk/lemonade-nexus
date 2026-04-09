# State Management - Riverpod Architecture

This document describes the Riverpod-based state management architecture for the Lemonade Nexus Flutter Windows client.

## Overview

The app uses **Riverpod StateNotifier** pattern for immutable, predictable state management. All state flows through a central `AppNotifier` that handles business logic and state transitions.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         UI Layer                                 │
│  (Views: ConsumerWidget / ConsumerStatefulWidget)                │
├─────────────────────────────────────────────────────────────────┤
│                          │                                       │
│                    ref.watch()                                   │
│                    ref.read()                                    │
├──────────────────────────▼──────────────────────────────────────┤
│                      Providers                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ appNotifier  │  │   sdkProvider│  │  themeProvider│          │
│  │   Provider   │  │              │  │               │          │
│  └──────┬───────┘  └──────────────┘  └──────────────┘          │
│         │                                                        │
│  ┌──────▼────────────────────────────────────────────┐          │
│  │              AppNotifier (StateNotifier)           │          │
│  │  - signIn/signOut                                  │          │
│  │  - connectTunnel/disconnectTunnel                  │          │
│  │  - enableMesh/disableMesh                          │          │
│  │  - refreshServers/refreshPeers                     │          │
│  └──────┬─────────────────────────────────────────────┘          │
│         │                                                        │
│  ┌──────▼─────────────────────────────────────────────┐          │
│  │                 AppState (Immutable)                │          │
│  │  - connectionStatus                                │          │
│  │  - authState                                       │          │
│  │  - peerState                                       │          │
│  │  - settings                                        │          │
│  └─────────────────────────────────────────────────────┘          │
├──────────────────────────────────────────────────────────────────┤
│                       Services Layer                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │AuthService│  │TunnelService│ │DiscoveryService│ │TreeService│         │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘         │
├──────────────────────────────────────────────────────────────────┤
│                       SDK Layer (FFI)                             │
│                    LemonadeNexusSdk                               │
└──────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. AppNotifier (`lib/src/state/app_state.dart`)

The `AppNotifier` is the central state management class. It extends `StateNotifier<AppState>` and provides all state mutation methods.

```dart
class AppNotifier extends StateNotifier<AppState> {
  final LemonadeNexusSdk _sdk;

  AppNotifier(this._sdk) : super(AppState.initial());

  // Authentication
  Future<bool> signIn(String username, String password);
  Future<bool> register(String username, String password);
  Future<void> signOut();

  // Connection
  Future<bool> connectToServer(String host, int port);
  Future<void> disconnectFromServer();

  // Tunnel
  Future<void> connectTunnel();
  Future<void> disconnectTunnel();
  Future<void> enableMesh();
  Future<void> disableMesh();

  // Refresh methods
  Future<void> refreshServers();
  Future<void> refreshPeers();
  Future<void> refreshTunnelStatus();
  Future<void> refreshHealth();
}
```

### 2. AppState (`lib/src/state/app_state.dart`)

Immutable state class using the `copyWith` pattern for predictable updates.

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
    // ... other fields
  });
}
```

### 3. State Models

#### ConnectionStatus

```dart
enum ConnectionStatus {
  disconnected,
  connecting,
  connected,
  error,
}
```

#### AuthState

```dart
class AuthState {
  final bool isAuthenticated;
  final String? username;
  final String? userId;
  final String? sessionToken;
  final String? publicKeyBase64;
  final DateTime? authenticatedAt;

  AuthState copyWith({...});
}
```

#### PeerState

```dart
class PeerState {
  final bool isMeshEnabled;
  final MeshStatus? meshStatus;
  final List<MeshPeer> meshPeers;

  PeerState copyWith({...});
}
```

#### Settings

```dart
class Settings {
  final String serverHost;
  final int serverPort;
  final bool autoDiscoveryEnabled;
  final bool autoConnectOnLaunch;
  final bool useTls;
  final bool darkModeEnabled;

  Settings copyWith({...});
}
```

## Providers (`lib/src/state/providers.dart`)

### Main Providers

| Provider | Type | Description |
|----------|------|-------------|
| `sdkProvider` | Provider | LemonadeNexusSdk singleton |
| `appNotifierProvider` | StateNotifierProvider | Main app state notifier |
| `themeProvider` | StateNotifierProvider | Theme mode (light/dark) |

### Selector Providers

These providers select specific slices of state for granular rebuilds:

```dart
final authStateProvider = Provider<AuthState>((ref) {
  return ref.watch(appNotifierProvider).authState;
});

final connectionStatusProvider = Provider<ConnectionStatus>((ref) {
  return ref.watch(appNotifierProvider).connectionStatus;
});

final settingsProvider = Provider<Settings>((ref) {
  return ref.watch(appNotifierProvider).settings;
});
```

### Service Providers

```dart
final authServiceProvider = Provider<AuthService>((ref) {
  return AuthService(ref.watch(sdkProvider), ref.watch(appNotifierProvider.notifier));
});

final tunnelServiceProvider = Provider<TunnelService>((ref) {
  return TunnelService(ref.watch(sdkProvider), ref.watch(appNotifierProvider.notifier));
});
```

## Usage in Views

### Reading State

Use `ref.watch()` to subscribe to state changes:

```dart
class MyView extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Watch full app state
    final appState = ref.watch(appNotifierProvider);

    // Or watch specific slices
    final authState = ref.watch(authStateProvider);
    final connectionStatus = ref.watch(connectionStatusProvider);

    return Text('Status: ${connectionStatus.name}');
  }
}
```

### Calling Methods

Use `ref.read().notifier` to access notifier methods:

```dart
// In a ConsumerWidget
ElevatedButton(
  onPressed: () {
    final notifier = ref.read(appNotifierProvider.notifier);
    notifier.connectTunnel();
  },
  child: Text('Connect'),
)

// In a ConsumerStatefulWidget
class _MyViewState extends ConsumerState<MyView> {
  void _handleConnect() async {
    final notifier = ref.read(appNotifierProvider.notifier);
    await notifier.signIn('username', 'password');
  }
}
```

### Async Operations

```dart
Future<void> _handleSignIn() async {
  final notifier = ref.read(appNotifierProvider.notifier);
  final success = await notifier.signIn(username, password);

  if (success) {
    // Navigate to main screen
  } else {
    // Show error
  }
}
```

## Service Classes

Service classes encapsulate business logic and provide a clean API for views:

### AuthService

```dart
class AuthService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  Future<bool> signIn(String username, String password);
  Future<bool> register(String username, String password);
  Future<void> signOut();

  bool get isAuthenticated;
  String? get username;
  String? get userId;
}
```

### TunnelService

```dart
class TunnelService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  Future<void> connect();
  Future<void> disconnect();
  Future<void> toggle();
  Future<void> enableMesh();
  Future<void> disableMesh();

  TunnelStatus? get status;
  bool get isTunnelUp;
  String? get tunnelIp;
}
```

### DiscoveryService

```dart
class DiscoveryService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  Future<bool> connectToServer(String host, int port);
  Future<void> refreshServers();
  Future<void> refreshRelays();

  List<ServerInfo> get servers;
  ConnectionStatus get connectionStatus;
}
```

### TreeService

```dart
class TreeService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  Future<void> loadTree();
  Future<TreeNode?> createChildNode({
    required String parentId,
    required String nodeType,
    String? hostname,
  });
  Future<bool> deleteNode({required String nodeId});

  TreeNode? get rootNode;
  List<TreeNode> get treeNodes;
}
```

## State Flow Diagram

```
User Action
    │
    ▼
┌─────────────┐
│   View      │  (e.g., TunnelControlView)
└──────┬──────┘
       │ ref.read(notifier).connectTunnel()
       ▼
┌─────────────┐
│ AppNotifier │
└──────┬──────┘
       │ 1. Update state to "connecting"
       │ 2. Call SDK
       │ 3. Update state based on result
       ▼
┌─────────────┐
│  Lemonade   │
│ NexusSdk    │
│  (FFI/C)    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  AppState   │──► ref.watch() triggers rebuild
└─────────────┘         in subscribed views
```

## Best Practices

### 1. Use Selector Providers for Granular Rebuilds

Instead of watching the entire `appState`, watch specific slices:

```dart
// Good - Only rebuilds when authState changes
final authState = ref.watch(authStateProvider);

// Less efficient - Rebuilds on any appState change
final appState = ref.watch(appNotifierProvider);
```

### 2. Use notifier for Actions, watch for State

```dart
// Good
final appState = ref.watch(appNotifierProvider);
final notifier = ref.read(appNotifierProvider.notifier);
await notifier.signIn(username, password);

// Avoid - Don't call methods on watched state
final appState = ref.watch(appNotifierProvider);
await appState.signIn(username, password); // WRONG
```

### 3. Handle Loading States

```dart
final isLoading = ref.watch(isLoadingProvider);

if (isLoading) {
  return CircularProgressIndicator();
}
```

### 4. Handle Errors

```dart
final errorMessage = ref.watch(errorMessageProvider);

if (errorMessage != null) {
  return ErrorWidget(errorMessage);
}
```

### 5. Dispose Resources

The SDK provider handles disposal automatically:

```dart
final sdkProvider = Provider<LemonadeNexusSdk>((ref) {
  final sdk = LemonadeNexusSdk();
  ref.onDispose(() => sdk.dispose());
  return sdk;
});
```

## File Structure

```
lib/src/state/
├── app_state.dart       # AppNotifier, AppState, state models
├── providers.dart       # All Riverpod providers and services
└── (future)
    ├── auth_state.dart  # May split out if grows
    └── peer_state.dart  # May split out if grows

lib/src/services/
├── auth_service.dart    # (Future dedicated service files)
├── tunnel_service.dart
├── discovery_service.dart
└── tree_service.dart
```

## Migration from ChangeNotifier

If migrating from provider + ChangeNotifier pattern:

| Old Pattern | New Pattern |
|-------------|-------------|
| `changeNotifierProvider` | `StateNotifierProvider` |
| `notifyListeners()` | `state = state.copyWith(...)` |
| `final model = ref.watch(provider)` | `final state = ref.watch(notifierProvider)` |
| `model.action()` | `ref.read(notifierProvider.notifier).action()` |

## Testing

```dart
test('signIn updates authState', () async {
  final container = ProviderContainer();
  addTearDown(container.dispose);

  final notifier = container.read(appNotifierProvider.notifier);
  await notifier.signIn('test', 'password');

  final state = container.read(appNotifierProvider);
  expect(state.authState.isAuthenticated, isTrue);
  expect(state.authState.username, 'test');
});
```

## Related Files

- `lib/main.dart` - App entry point with ProviderScope
- `lib/src/views/main_navigation.dart` - Main navigation shell
- `lib/src/sdk/sdk.dart` - SDK bindings
- `lib/src/sdk/models.dart` - SDK data models
