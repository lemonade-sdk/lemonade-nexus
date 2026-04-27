/// @title Application State
/// @description Central state management for the Flutter app using Riverpod.
///
/// Tracks authentication, tunnel status, UI navigation state,
/// and all data fetched from the C SDK.

import 'package:flutter/foundation.dart';
import 'package:riverpod/riverpod.dart';
import '../sdk/sdk.dart';
import '../sdk/models.dart';

/// Connection status enum
enum ConnectionStatus {
  disconnected,
  connecting,
  connected,
  error,
}

/// Authentication state class
class AuthState {
  final bool isAuthenticated;
  final String? username;
  final String? userId;
  final String? sessionToken;
  final String? publicKeyBase64;
  final DateTime? authenticatedAt;

  const AuthState({
    this.isAuthenticated = false,
    this.username,
    this.userId,
    this.sessionToken,
    this.publicKeyBase64,
    this.authenticatedAt,
  });

  AuthState copyWith({
    bool? isAuthenticated,
    String? username,
    String? userId,
    String? sessionToken,
    String? publicKeyBase64,
    DateTime? authenticatedAt,
  }) {
    return AuthState(
      isAuthenticated: isAuthenticated ?? this.isAuthenticated,
      username: username ?? this.username,
      userId: userId ?? this.userId,
      sessionToken: sessionToken ?? this.sessionToken,
      publicKeyBase64: publicKeyBase64 ?? this.publicKeyBase64,
      authenticatedAt: authenticatedAt ?? this.authenticatedAt,
    );
  }

  /// Initial unauthenticated state
  static const initial = AuthState();
}

/// Peer state class
class PeerState {
  final bool isMeshEnabled;
  final MeshStatus? meshStatus;
  final List<MeshPeer> meshPeers;

  const PeerState({
    this.isMeshEnabled = false,
    this.meshStatus,
    this.meshPeers = const [],
  });

  PeerState copyWith({
    bool? isMeshEnabled,
    MeshStatus? meshStatus,
    List<MeshPeer>? meshPeers,
  }) {
    return PeerState(
      isMeshEnabled: isMeshEnabled ?? this.isMeshEnabled,
      meshStatus: meshStatus ?? this.meshStatus,
      meshPeers: meshPeers ?? this.meshPeers,
    );
  }

  int get onlineCount => meshPeers.where((p) => p.isOnline).length;
  int get totalCount => meshPeers.length;

  /// Initial state
  static const initial = PeerState();
}

/// Settings class for app preferences
class Settings {
  final String serverHost;
  final int serverPort;
  final bool autoDiscoveryEnabled;
  final bool autoConnectOnLaunch;
  final bool useTls;
  final bool darkModeEnabled;

  const Settings({
    this.serverHost = 'localhost',
    this.serverPort = 9100,
    this.autoDiscoveryEnabled = true,
    this.autoConnectOnLaunch = false,
    this.useTls = false,
    this.darkModeEnabled = true,
  });

  Settings copyWith({
    String? serverHost,
    int? serverPort,
    bool? autoDiscoveryEnabled,
    bool? autoConnectOnLaunch,
    bool? useTls,
    bool? darkModeEnabled,
  }) {
    return Settings(
      serverHost: serverHost ?? this.serverHost,
      serverPort: serverPort ?? this.serverPort,
      autoDiscoveryEnabled: autoDiscoveryEnabled ?? this.autoDiscoveryEnabled,
      autoConnectOnLaunch: autoConnectOnLaunch ?? this.autoConnectOnLaunch,
      useTls: useTls ?? this.useTls,
      darkModeEnabled: darkModeEnabled ?? this.darkModeEnabled,
    );
  }

  String get endpoint => '$serverHost:$serverPort';
}

/// Activity log entry for dashboard
class ActivityEntry {
  final String id;
  final String message;
  final ActivityLevel level;
  final DateTime timestamp;

  ActivityEntry({
    required this.id,
    required this.message,
    required this.level,
    required this.timestamp,
  });

  factory ActivityEntry.info(String message) => ActivityEntry(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        message: message,
        level: ActivityLevel.info,
        timestamp: DateTime.now(),
      );

  factory ActivityEntry.success(String message) => ActivityEntry(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        message: message,
        level: ActivityLevel.success,
        timestamp: DateTime.now(),
      );

  factory ActivityEntry.warning(String message) => ActivityEntry(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        message: message,
        level: ActivityLevel.warning,
        timestamp: DateTime.now(),
      );

  factory ActivityEntry.error(String message) => ActivityEntry(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        message: message,
        level: ActivityLevel.error,
        timestamp: DateTime.now(),
      );
}

enum ActivityLevel { info, success, warning, error }

/// Sidebar navigation items
enum SidebarItem {
  dashboard,
  tunnel,
  peers,
  network,
  endpoints,
  servers,
  certificates,
  relays,
  settings,
}

extension SidebarItemExtension on SidebarItem {
  String get label {
    switch (this) {
      case SidebarItem.dashboard:
        return 'Dashboard';
      case SidebarItem.tunnel:
        return 'Tunnel';
      case SidebarItem.peers:
        return 'Peers';
      case SidebarItem.network:
        return 'Network';
      case SidebarItem.endpoints:
        return 'Endpoints';
      case SidebarItem.servers:
        return 'Servers';
      case SidebarItem.certificates:
        return 'Certificates';
      case SidebarItem.relays:
        return 'Relays';
      case SidebarItem.settings:
        return 'Settings';
    }
  }

  IconData get icon {
    switch (this) {
      case SidebarItem.dashboard:
        return Icons.dashboard;
      case SidebarItem.tunnel:
        return Icons.security;
      case SidebarItem.peers:
        return Icons.people;
      case SidebarItem.network:
        return Icons.network_check;
      case SidebarItem.endpoints:
        return Icons.account_tree;
      case SidebarItem.servers:
        return Icons.dns;
      case SidebarItem.certificates:
        return Icons.cert;
      case SidebarItem.relays:
        return Icons.wifi_tethering;
      case SidebarItem.settings:
        return Icons.settings;
    }
  }
}

/// Main application state - immutable data class
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
  final bool isDiscovering;
  final String? errorMessage;
  final List<ActivityEntry> activityLog;
  final DateTime? connectedSince;

  const AppState({
    this.connectionStatus = ConnectionStatus.disconnected,
    this.authState = AuthState.initial,
    this.peerState = PeerState.initial,
    this.settings = const Settings(),
    this.tunnelStatus,
    this.healthStatus,
    this.stats,
    this.servers = const [],
    this.relays = const [],
    this.certificates = const [],
    this.treeNodes = const [],
    this.rootNode,
    this.trustStatus,
    this.selectedSidebarItem = SidebarItem.dashboard,
    this.isLoading = false,
    this.isDiscovering = false,
    this.errorMessage,
    this.activityLog = const [],
    this.connectedSince,
  });

  AppState copyWith({
    ConnectionStatus? connectionStatus,
    AuthState? authState,
    PeerState? peerState,
    Settings? settings,
    TunnelStatus? tunnelStatus,
    HealthResponse? healthStatus,
    ServiceStats? stats,
    List<ServerInfo>? servers,
    List<RelayInfo>? relays,
    List<CertStatus>? certificates,
    List<TreeNode>? treeNodes,
    TreeNode? rootNode,
    TrustStatus? trustStatus,
    SidebarItem? selectedSidebarItem,
    bool? isLoading,
    bool? isDiscovering,
    String? errorMessage,
    List<ActivityEntry>? activityLog,
    DateTime? connectedSince,
  }) {
    return AppState(
      connectionStatus: connectionStatus ?? this.connectionStatus,
      authState: authState ?? this.authState,
      peerState: peerState ?? this.peerState,
      settings: settings ?? this.settings,
      tunnelStatus: tunnelStatus ?? this.tunnelStatus,
      healthStatus: healthStatus ?? this.healthStatus,
      stats: stats ?? this.stats,
      servers: servers ?? this.servers,
      relays: relays ?? this.relays,
      certificates: certificates ?? this.certificates,
      treeNodes: treeNodes ?? this.treeNodes,
      rootNode: rootNode ?? this.rootNode,
      trustStatus: trustStatus ?? this.trustStatus,
      selectedSidebarItem: selectedSidebarItem ?? this.selectedSidebarItem,
      isLoading: isLoading ?? this.isLoading,
      isDiscovering: isDiscovering ?? this.isDiscovering,
      errorMessage: errorMessage ?? this.errorMessage,
      activityLog: activityLog ?? this.activityLog,
      connectedSince: connectedSince ?? this.connectedSince,
    );
  }

  /// Initial app state
  static const initial = AppState();

  // Convenience getters
  bool get isAuthenticated => authState.isAuthenticated;
  bool get isTunnelUp => tunnelStatus?.isUp ?? false;
  bool get isMeshEnabled => peerState.isMeshEnabled;
  bool get isConnected => connectionStatus == ConnectionStatus.connected;
  bool get isServerHealthy => healthStatus?.status == 'ok';
  String? get username => authState.username;
  String? get userId => authState.userId;
  String? get sessionToken => authState.sessionToken;
  String? get publicKeyBase64 => authState.publicKeyBase64;
  String get serverHost => settings.serverHost;
  int get serverPort => settings.serverPort;
  String? get tunnelIP => tunnelStatus?.tunnelIp;
  MeshStatus? get meshStatus => peerState.meshStatus;
  List<MeshPeer> get meshPeers => peerState.meshPeers;
}

/// Notifier for managing app state
class AppNotifier extends StateNotifier<AppState> {
  final LemonadeNexusSdk _sdk;

  AppNotifier(this._sdk) : super(AppState.initial);

  /// Initialize app state - load preferences
  Future<void> initialize() async {
    await _loadPreferences();
  }

  /// Load preferences from storage
  Future<void> _loadPreferences() async {
    // TODO: Load from shared_preferences when implemented
    // For now, use defaults
    state = state.copyWith(
      settings: state.settings.copyWith(
        autoDiscoveryEnabled: true,
        autoConnectOnLaunch: false,
      ),
    );
  }

  /// Connect to server
  Future<bool> connectToServer(String host, int port) async {
    state = state.copyWith(
      isLoading: true,
      errorMessage: null,
      connectionStatus: ConnectionStatus.connecting,
    );

    try {
      await _sdk.connect(host, port);
      state = state.copyWith(
        settings: state.settings.copyWith(
          serverHost: host,
          serverPort: port,
        ),
        connectionStatus: ConnectionStatus.connected,
        connectedSince: DateTime.now(),
        isLoading: false,
      );
      addActivity(ActivityLevel.success, 'Connected to $host:$port');
      return true;
    } catch (e) {
      state = state.copyWith(
        errorMessage: 'Failed to connect: $e',
        connectionStatus: ConnectionStatus.error,
        isLoading: false,
      );
      addActivity(ActivityLevel.error, 'Connection failed: $e');
      return false;
    }
  }

  /// Disconnect from server
  Future<void> disconnectFromServer() async {
    try {
      _sdk.dispose();
    } catch (e) {
      // Ignore disconnect errors
    }
    state = state.copyWith(
      connectionStatus: ConnectionStatus.disconnected,
      connectedSince: null,
    );
    addActivity(ActivityLevel.info, 'Disconnected from server');
  }

  /// Sign in with username and password
  Future<bool> signIn(String username, String password) async {
    state = state.copyWith(isLoading: true, errorMessage: null);

    try {
      final response = await _sdk.authPassword(username, password);
      if (response.authenticated) {
        state = state.copyWith(
          authState: state.authState.copyWith(
            isAuthenticated: true,
            username: username,
            userId: response.userId,
            sessionToken: response.sessionToken,
            authenticatedAt: DateTime.now(),
          ),
          isLoading: false,
        );

        // Set session token for future requests
        if (response.sessionToken != null) {
          await _sdk.setSessionToken(response.sessionToken!);
        }

        await _loadIdentity();
        await refreshAllData();
        addActivity(ActivityLevel.success, 'Signed in as $username');
        return true;
      } else {
        state = state.copyWith(
          errorMessage: response.error ?? 'Authentication failed',
          isLoading: false,
        );
        addActivity(ActivityLevel.error, 'Sign in failed: ${response.error}');
        return false;
      }
    } catch (e) {
      state = state.copyWith(
        errorMessage: 'Sign in failed: $e',
        isLoading: false,
      );
      addActivity(ActivityLevel.error, 'Sign in failed: $e');
      return false;
    }
  }

  /// Register a new user
  Future<bool> register(String username, String password) async {
    state = state.copyWith(isLoading: true, errorMessage: null);

    try {
      // First derive seed from credentials
      final seed = await _sdk.deriveSeed(username, password);
      // Create identity from seed
      await _sdk.createIdentityFromSeed(seed.codeUnits);
      // Set identity for client
      await _sdk.setIdentity();

      // Try to authenticate
      final response = await _sdk.authPassword(username, password);
      if (response.authenticated) {
        state = state.copyWith(
          authState: state.authState.copyWith(
            isAuthenticated: true,
            username: username,
            userId: response.userId,
            sessionToken: response.sessionToken,
            authenticatedAt: DateTime.now(),
          ),
          isLoading: false,
        );
        await _loadIdentity();
        addActivity(ActivityLevel.success, 'Registered as $username');
        return true;
      } else {
        state = state.copyWith(
          errorMessage: response.error ?? 'Registration failed',
          isLoading: false,
        );
        addActivity(ActivityLevel.error, 'Registration failed: ${response.error}');
        return false;
      }
    } catch (e) {
      state = state.copyWith(
        errorMessage: 'Registration failed: $e',
        isLoading: false,
      );
      addActivity(ActivityLevel.error, 'Registration failed: $e');
      return false;
    }
  }

  /// Load identity public key
  Future<void> _loadIdentity() async {
    try {
      state = state.copyWith(
        authState: state.authState.copyWith(
          publicKeyBase64: _sdk.identityPubkey,
        ),
      );
    } catch (e) {
      // Identity not available
    }
  }

  /// Sign out
  Future<void> signOut() async {
    await disconnectFromServer();
    state = state.copyWith(
      authState: AuthState.initial,
      peerState: PeerState.initial,
      tunnelStatus: null,
      healthStatus: null,
      stats: null,
      servers: [],
      relays: [],
      certificates: [],
      treeNodes: [],
      rootNode: null,
      trustStatus: null,
      activityLog: [],
    );
    addActivity(ActivityLevel.info, 'Signed out');
  }

  /// Refresh all data
  Future<void> refreshAllData() async {
    await Future.wait([
      refreshHealth(),
      refreshStats(),
      refreshServers(),
      refreshRelays(),
      refreshMeshStatus(),
      refreshTrustStatus(),
    ]);
  }

  /// Refresh health status
  Future<void> refreshHealth() async {
    try {
      await _sdk.health();
      state = state.copyWith(
        healthStatus: HealthResponse(status: 'ok', version: 'unknown', uptime: 0),
      );
    } catch (e) {
      state = state.copyWith(
        healthStatus: HealthResponse(status: 'error', version: 'unknown', uptime: 0),
      );
    }
  }

  /// Refresh stats
  Future<void> refreshStats() async {
    try {
      state = state.copyWith(stats: await _sdk.getStats());
    } catch (e) {
      // Stats unavailable
    }
  }

  /// Refresh servers
  Future<void> refreshServers() async {
    try {
      state = state.copyWith(servers: await _sdk.listServers());
    } catch (e) {
      state = state.copyWith(servers: []);
    }
  }

  /// Refresh relays
  Future<void> refreshRelays() async {
    try {
      state = state.copyWith(relays: await _sdk.listRelays());
    } catch (e) {
      state = state.copyWith(relays: []);
    }
  }

  /// Refresh mesh status
  Future<void> refreshMeshStatus() async {
    try {
      final meshStatus = await _sdk.getMeshStatus();
      final meshPeers = await _sdk.getMeshPeers();
      state = state.copyWith(
        peerState: state.peerState.copyWith(
          meshStatus: meshStatus,
          meshPeers: meshPeers,
          isMeshEnabled: meshStatus.isUp,
        ),
      );
    } catch (e) {
      state = state.copyWith(
        peerState: const PeerState(
          meshStatus: null,
          meshPeers: [],
        ),
      );
    }
  }

  /// Refresh trust status
  Future<void> refreshTrustStatus() async {
    try {
      state = state.copyWith(trustStatus: await _sdk.getTrustStatus());
    } catch (e) {
      // Trust status unavailable
    }
  }

  /// Refresh certificates
  Future<void> refreshCertificates(List<String> domains) async {
    final certificates = <CertStatus>[];
    for (final domain in domains) {
      try {
        final status = await _sdk.getCertStatus(domain);
        certificates.add(status);
      } catch (e) {
        // Certificate not found
      }
    }
    state = state.copyWith(certificates: certificates);
  }

  /// Load tree nodes
  Future<void> loadTree() async {
    try {
      // Load root node
      final rootNode = await _sdk.getNode('root');

      // Load children
      final children = await _sdk.getChildren('root');

      // Load grandchildren (endpoints under customer groups)
      final allNodes = <TreeNode>[...children];
      for (final child in children) {
        if (child.nodeType == 'customer') {
          try {
            final grandchildren = await _sdk.getChildren(child.id);
            allNodes.addAll(grandchildren);
          } catch (e) {
            // No children
          }
        }
      }

      state = state.copyWith(
        rootNode: rootNode,
        treeNodes: allNodes,
      );
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to load tree: $e');
    }
  }

  /// Create child node
  Future<TreeNode?> createChildNode({
    required String parentId,
    required String nodeType,
    String? hostname,
  }) async {
    try {
      final node = await _sdk.createChildNode(parentId: parentId, nodeType: nodeType);
      await loadTree();
      addActivity(ActivityLevel.success, 'Created $nodeType node under $parentId');
      return node;
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to create node: $e');
      addActivity(ActivityLevel.error, 'Failed to create node: $e');
      return null;
    }
  }

  /// Delete node
  Future<bool> deleteNode({required String nodeId}) async {
    try {
      await _sdk.deleteNode(nodeId);
      await loadTree();
      addActivity(ActivityLevel.success, 'Deleted node $nodeId');
      return true;
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to delete node: $e');
      addActivity(ActivityLevel.error, 'Failed to delete node: $e');
      return false;
    }
  }

  /// Connect tunnel
  Future<void> connectTunnel() async {
    state = state.copyWith(isLoading: true);
    try {
      // Get WG config first
      final config = await _sdk.getWgConfigJson();
      if (config != null) {
        await _sdk.tunnelUp(config);
      }
      await refreshTunnelStatus();
      addActivity(ActivityLevel.success, 'Tunnel connected');
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to connect tunnel: $e');
      addActivity(ActivityLevel.error, 'Failed to connect tunnel: $e');
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  /// Disconnect tunnel
  Future<void> disconnectTunnel() async {
    state = state.copyWith(isLoading: true);
    try {
      await _sdk.tunnelDown();
      await refreshTunnelStatus();
      addActivity(ActivityLevel.info, 'Tunnel disconnected');
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to disconnect tunnel: $e');
      addActivity(ActivityLevel.error, 'Failed to disconnect tunnel: $e');
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  /// Refresh tunnel status
  Future<void> refreshTunnelStatus() async {
    try {
      final tunnelStatus = await _sdk.getTunnelStatus();
      state = state.copyWith(
        tunnelStatus: tunnelStatus,
      );
    } catch (e) {
      state = state.copyWith(tunnelStatus: null);
    }
  }

  /// Enable mesh
  Future<void> enableMesh() async {
    state = state.copyWith(isLoading: true);
    try {
      await _sdk.enableMesh();
      await refreshMeshStatus();
      addActivity(ActivityLevel.success, 'Mesh enabled');
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to enable mesh: $e');
      addActivity(ActivityLevel.error, 'Failed to enable mesh: $e');
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  /// Disable mesh
  Future<void> disableMesh() async {
    state = state.copyWith(isLoading: true);
    try {
      await _sdk.disableMesh();
      await refreshMeshStatus();
      addActivity(ActivityLevel.info, 'Mesh disabled');
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to disable mesh: $e');
      addActivity(ActivityLevel.error, 'Failed to disable mesh: $e');
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  /// Toggle mesh
  Future<void> toggleMesh() async {
    if (state.isMeshEnabled) {
      await disableMesh();
    } else {
      await enableMesh();
    }
  }

  /// Request certificate
  Future<Map<String, dynamic>?> requestCertificate(String hostname) async {
    try {
      final result = await _sdk.requestCert(hostname);
      addActivity(ActivityLevel.success, 'Certificate requested for $hostname');
      return result;
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to request certificate: $e');
      addActivity(ActivityLevel.error, 'Failed to request certificate: $e');
      return null;
    }
  }

  /// Add activity log entry
  void addActivity(ActivityLevel level, String message) {
    final entry = ActivityEntry(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      message: message,
      level: level,
      timestamp: DateTime.now(),
    );
    final updatedLog = [entry, ...state.activityLog];
    // Keep only last 50 entries
    if (updatedLog.length > 50) {
      updatedLog.removeRange(50, updatedLog.length);
    }
    state = state.copyWith(activityLog: updatedLog);
  }

  /// Set selected sidebar item
  void setSelectedSidebarItem(SidebarItem item) {
    state = state.copyWith(selectedSidebarItem: item);
  }

  /// Set auto discovery enabled
  void setAutoDiscoveryEnabled(bool enabled) {
    state = state.copyWith(
      settings: state.settings.copyWith(autoDiscoveryEnabled: enabled),
    );
  }

  /// Set auto connect on launch
  void setAutoConnectOnLaunch(bool enabled) {
    state = state.copyWith(
      settings: state.settings.copyWith(autoConnectOnLaunch: enabled),
    );
  }

  /// Clear error message
  void clearError() {
    state = state.copyWith(errorMessage: null);
  }

  @override
  void dispose() {
    try {
      _sdk.dispose();
    } catch (e) {
      // Ignore dispose errors
    }
    super.dispose();
  }
}
