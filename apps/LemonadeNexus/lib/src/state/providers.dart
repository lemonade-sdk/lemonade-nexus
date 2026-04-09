/// @title Riverpod Providers
/// @description All providers for the Lemonade Nexus app.
///
/// This file contains all Riverpod providers used throughout the app:
/// - SDK provider (singleton instance)
/// - App state notifier provider
/// - Auth provider (login/logout)
/// - Connection provider (tunnel state)
/// - Peer provider (peer list)
/// - Settings provider (app preferences)
/// - Theme provider (light/dark mode)

import 'package:riverpod/riverpod.dart';
import '../sdk/sdk.dart';
import '../sdk/models.dart';
import 'app_state.dart';

// =========================================================================
// SDK Provider
// =========================================================================

/// Provider for the LemonadeNexusSdk singleton instance.
/// This is a lazy singleton - created only when first accessed.
final sdkProvider = Provider<LemonadeNexusSdk>((ref) {
  final sdk = LemonadeNexusSdk();

  // Add finalizer to dispose SDK when provider is disposed
  ref.onDispose(() {
    sdk.dispose();
  });

  return sdk;
});

/// Provider for FFI bindings (low-level access).
final ffiProvider = Provider<LemonadeNexusFfi>((ref) {
  return LemonadeNexusFfi();
});

// =========================================================================
// App State Notifier
// =========================================================================

/// Main app state notifier provider.
/// Provides the AppNotifier instance and AppState state.
final appNotifierProvider = StateNotifierProvider<AppNotifier, AppState>((ref) {
  return AppNotifier(ref.watch(sdkProvider));
});

/// Selector for authentication state only.
final authStateProvider = Provider<AuthState>((ref) {
  return ref.watch(appNotifierProvider).authState;
});

/// Selector for connection status only.
final connectionStatusProvider = Provider<ConnectionStatus>((ref) {
  return ref.watch(appNotifierProvider).connectionStatus;
});

/// Selector for peer state only.
final peerStateProvider = Provider<PeerState>((ref) {
  return ref.watch(appNotifierProvider).peerState;
});

/// Selector for settings only.
final settingsProvider = Provider<Settings>((ref) {
  return ref.watch(appNotifierProvider).settings;
});

/// Selector for tunnel status only.
final tunnelStatusProvider = Provider<TunnelStatus?>((ref) {
  return ref.watch(appNotifierProvider).tunnelStatus;
});

/// Selector for health status only.
final healthStatusProvider = Provider<HealthResponse?>((ref) {
  return ref.watch(appNotifierProvider).healthStatus;
});

/// Selector for service stats only.
final statsProvider = Provider<ServiceStats?>((ref) {
  return ref.watch(appNotifierProvider).stats;
});

/// Selector for servers list only.
final serversProvider = Provider<List<ServerInfo>>((ref) {
  return ref.watch(appNotifierProvider).servers;
});

/// Selector for relays list only.
final relaysProvider = Provider<List<RelayInfo>>((ref) {
  return ref.watch(appNotifierProvider).relays;
});

/// Selector for certificates list only.
final certificatesProvider = Provider<List<CertStatus>>((ref) {
  return ref.watch(appNotifierProvider).certificates;
});

/// Selector for tree nodes only.
final treeNodesProvider = Provider<List<TreeNode>>((ref) {
  return ref.watch(appNotifierProvider).treeNodes;
});

/// Selector for root node only.
final rootNodeProvider = Provider<TreeNode?>((ref) {
  return ref.watch(appNotifierProvider).rootNode;
});

/// Selector for trust status only.
final trustStatusProvider = Provider<TrustStatus?>((ref) {
  return ref.watch(appNotifierProvider).trustStatus;
});

/// Selector for selected sidebar item.
final selectedSidebarItemProvider = Provider<SidebarItem>((ref) {
  return ref.watch(appNotifierProvider).selectedSidebarItem;
});

/// Selector for loading state.
final isLoadingProvider = Provider<bool>((ref) {
  return ref.watch(appNotifierProvider).isLoading;
});

/// Selector for error message.
final errorMessageProvider = Provider<String?>((ref) {
  return ref.watch(appNotifierProvider).errorMessage;
});

/// Selector for activity log.
final activityLogProvider = Provider<List<ActivityEntry>>((ref) {
  return ref.watch(appNotifierProvider).activityLog;
});

// =========================================================================
// Theme Provider
// =========================================================================

/// Theme mode provider (light, dark, system).
final themeProvider = StateNotifierProvider<ThemeNotifier, ThemeMode>((ref) {
  return ThemeNotifier();
});

class ThemeNotifier extends StateNotifier<ThemeMode> {
  ThemeNotifier() : super(ThemeMode.system);

  void setTheme(ThemeMode mode) {
    state = mode;
  }

  void toggleDarkMode() {
    state = state == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
  }
}

// =========================================================================
// Service Providers
// =========================================================================

/// Authentication service provider.
/// Provides methods for authentication operations.
final authServiceProvider = Provider<AuthService>((ref) {
  return AuthService(ref.watch(sdkProvider), ref.watch(appNotifierProvider.notifier));
});

/// Tunnel service provider.
/// Provides methods for tunnel control operations.
final tunnelServiceProvider = Provider<TunnelService>((ref) {
  return TunnelService(ref.watch(sdkProvider), ref.watch(appNotifierProvider.notifier));
});

/// Discovery service provider.
/// Provides methods for server discovery and selection.
final discoveryServiceProvider = Provider<DiscoveryService>((ref) {
  return DiscoveryService(ref.watch(sdkProvider), ref.watch(appNotifierProvider.notifier));
});

/// Tree service provider.
/// Provides methods for permission tree operations.
final treeServiceProvider = Provider<TreeService>((ref) {
  return TreeService(ref.watch(sdkProvider), ref.watch(appNotifierProvider.notifier));
});

// =========================================================================
// Service Classes
// =========================================================================

/// Authentication service.
/// Handles all authentication-related operations.
class AuthService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  AuthService(this._sdk, this._notifier);

  /// Sign in with username and password.
  Future<bool> signIn(String username, String password) {
    return _notifier.signIn(username, password);
  }

  /// Register a new user.
  Future<bool> register(String username, String password) {
    return _notifier.register(username, password);
  }

  /// Sign out.
  Future<void> signOut() => _notifier.signOut();

  /// Check if user is authenticated.
  bool get isAuthenticated => _notifier.state.authState.isAuthenticated;

  /// Get current username.
  String? get username => _notifier.state.authState.username;

  /// Get user ID.
  String? get userId => _notifier.state.authState.userId;
}

/// Tunnel service.
/// Handles WireGuard tunnel lifecycle management.
class TunnelService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  TunnelService(this._sdk, this._notifier);

  /// Connect the WireGuard tunnel.
  Future<void> connect() => _notifier.connectTunnel();

  /// Disconnect the WireGuard tunnel.
  Future<void> disconnect() => _notifier.disconnectTunnel();

  /// Toggle tunnel connection.
  Future<void> toggle() async {
    if (_notifier.state.isTunnelUp) {
      await disconnect();
    } else {
      await connect();
    }
  }

  /// Refresh tunnel status.
  Future<void> refreshStatus() => _notifier.refreshTunnelStatus();

  /// Enable mesh networking.
  Future<void> enableMesh() => _notifier.enableMesh();

  /// Disable mesh networking.
  Future<void> disableMesh() => _notifier.disableMesh();

  /// Toggle mesh networking.
  Future<void> toggleMesh() => _notifier.toggleMesh();

  /// Get current tunnel status.
  TunnelStatus? get status => _notifier.state.tunnelStatus;

  /// Check if tunnel is up.
  bool get isTunnelUp => _notifier.state.isTunnelUp;

  /// Check if mesh is enabled.
  bool get isMeshEnabled => _notifier.state.isMeshEnabled;

  /// Get tunnel IP address.
  String? get tunnelIp => _notifier.state.tunnelIP;
}

/// Discovery service.
/// Handles server discovery and selection.
class DiscoveryService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  DiscoveryService(this._sdk, this._notifier);

  /// Connect to a server.
  Future<bool> connectToServer(String host, int port) {
    return _notifier.connectToServer(host, port);
  }

  /// Disconnect from server.
  Future<void> disconnectFromServer() => _notifier.disconnectFromServer();

  /// Refresh server list.
  Future<void> refreshServers() => _notifier.refreshServers();

  /// Refresh relay list.
  Future<void> refreshRelays() => _notifier.refreshRelays();

  /// Get available servers.
  List<ServerInfo> get servers => _notifier.state.servers;

  /// Get available relays.
  List<RelayInfo> get relays => _notifier.state.relays;

  /// Get current server host.
  String get serverHost => _notifier.settings.serverHost;

  /// Get current server port.
  int get serverPort => _notifier.settings.serverPort;

  /// Check if connected to server.
  bool get isConnected => _notifier.state.isConnected;

  /// Get connection status.
  ConnectionStatus get connectionStatus => _notifier.state.connectionStatus;
}

/// Tree service.
/// Handles permission tree operations.
class TreeService {
  final LemonadeNexusSdk _sdk;
  final AppNotifier _notifier;

  TreeService(this._sdk, this._notifier);

  /// Load the tree.
  Future<void> loadTree() => _notifier.loadTree();

  /// Create a child node.
  Future<TreeNode?> createChildNode({
    required String parentId,
    required String nodeType,
    String? hostname,
  }) {
    return _notifier.createChildNode(
      parentId: parentId,
      nodeType: nodeType,
      hostname: hostname,
    );
  }

  /// Delete a node.
  Future<bool> deleteNode({required String nodeId}) {
    return _notifier.deleteNode(nodeId: nodeId);
  }

  /// Get root node.
  TreeNode? get rootNode => _notifier.state.rootNode;

  /// Get all tree nodes.
  List<TreeNode> get treeNodes => _notifier.state.treeNodes;

  /// Get trust status.
  TrustStatus? get trustStatus => _notifier.state.trustStatus;
}

// =========================================================================
// Configuration Provider
// =========================================================================

/// Provider for app configuration.
final configProvider = Provider<AppConfig>((ref) {
  return const AppConfig(
    apiHost: 'api.lemonade-nexus.com',
    apiPort: 443,
    useTls: true,
  );
});

/// App configuration.
class AppConfig {
  final String apiHost;
  final int apiPort;
  final bool useTls;

  const AppConfig({
    required this.apiHost,
    required this.apiPort,
    required this.useTls,
  });

  String get endpoint => useTls ? 'https://$apiHost:$apiPort' : 'http://$apiHost:$apiPort';
}
