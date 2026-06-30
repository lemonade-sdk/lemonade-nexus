/// @title Application State
/// @description Central state management for the Flutter app using Riverpod.
///
/// Tracks authentication, mesh status, UI navigation state,
/// and all data fetched from the C SDK.

import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../sdk/sdk.dart';
import '../platform/settings_store.dart';
import '../platform/secure_store.dart';
import '../platform/app_paths.dart';
import '../services/dns_discovery.dart';
import '../services/passkey_manager.dart';

/// Lightweight console logger for connection/state diagnostics.
/// Mirrors the `[Discovery]`-style tagging used in dns_discovery.dart.
/// Debug-only: compiles to nothing in release builds (mirrors the native
/// `LN_DEBUG` gate), so the diagnostics stay in the source without adding
/// noise to production.
void _log(String msg) {
  if (kDebugMode) debugPrint('[AppState] $msg');
}

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
      case SidebarItem.peers:
        return Icons.people;
      case SidebarItem.network:
        return Icons.network_check;
      case SidebarItem.endpoints:
        return Icons.account_tree;
      case SidebarItem.servers:
        return Icons.dns;
      case SidebarItem.certificates:
        return Icons.verified_user;
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
  final List<DiscoveredServer> discoveredServers;
  final String? discoveryMessage;
  final bool hasStoredPasskey;
  final String? storedPasskeyUserId;
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
    this.discoveredServers = const [],
    this.discoveryMessage,
    this.hasStoredPasskey = false,
    this.storedPasskeyUserId,
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
    List<DiscoveredServer>? discoveredServers,
    String? discoveryMessage,
    bool? hasStoredPasskey,
    String? storedPasskeyUserId,
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
      discoveredServers: discoveredServers ?? this.discoveredServers,
      discoveryMessage: discoveryMessage ?? this.discoveryMessage,
      hasStoredPasskey: hasStoredPasskey ?? this.hasStoredPasskey,
      storedPasskeyUserId: storedPasskeyUserId ?? this.storedPasskeyUserId,
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
  bool get isServerHealthy =>
      healthStatus?.status == 'ok' || healthStatus?.status == 'healthy';
  String? get username => authState.username;
  String? get userId => authState.userId;
  String? get sessionToken => authState.sessionToken;
  String? get publicKeyBase64 => authState.publicKeyBase64;
  String get serverHost => settings.serverHost;
  int get serverPort => settings.serverPort;
  // The WireGuard tunnel was removed in favour of the userspace mesh; surface
  // the mesh-assigned IP here so existing views keep showing a usable address.
  String? get tunnelIP => tunnelStatus?.tunnelIp ?? meshStatus?.tunnelIp;
  MeshStatus? get meshStatus => peerState.meshStatus;
  List<MeshPeer> get meshPeers => peerState.meshPeers;
}

/// Notifier for managing app state
class AppNotifier extends StateNotifier<AppState> {
  final LemonadeNexusSdk _sdk;
  final SettingsStore _settingsStore = SettingsStore();
  final SecureStore _secureStore = SecureStore();
  final PasskeyManager _passkey = PasskeyManager();

  AppNotifier(this._sdk) : super(AppState.initial);

  /// Initialize app state - load preferences
  Future<void> initialize() async {
    await _loadPreferences();
    await _loadPasskeyState();
  }

  Future<void> _loadPasskeyState() async {
    try {
      state = state.copyWith(
        hasStoredPasskey: await _passkey.hasCredential(),
        storedPasskeyUserId: await _passkey.storedUserId(),
      );
    } catch (_) {}
  }

  /// Load persisted preferences, then attempt to restore a prior session.
  Future<void> _loadPreferences() async {
    final settings = await _settingsStore.load();
    state = state.copyWith(settings: settings);
    await _restoreSession();
  }

  Future<void> _persistSettings() => _settingsStore.save(state.settings);

  Future<void> _persistIdentity() async {
    try {
      await _sdk.saveIdentity(await AppPaths.identityFilePath());
    } catch (_) {
      // No identity to persist (e.g. password-only auth).
    }
  }

  /// Best-effort restore of a previous session (identity + token) on launch.
  Future<void> _restoreSession() async {
    final session = await _secureStore.loadSession();
    if (session == null) {
      _log('_restoreSession: no stored session');
      return;
    }
    _log('_restoreSession: restoring user=${session.username} '
        'host=${state.settings.serverHost}:${state.settings.serverPort} tls=${state.settings.useTls}');
    try {
      final s = state.settings;
      if (s.useTls) {
        await _sdk.connectTls(s.serverHost, s.serverPort);
      } else {
        await _sdk.connect(s.serverHost, s.serverPort);
      }
      final idPath = await AppPaths.identityFilePath();
      if (await File(idPath).exists()) {
        await _sdk.loadIdentity(idPath);
        await _sdk.setIdentity();
      }
      await _sdk.setSessionToken(session.token);
      // Stay on the login view until the restored session's data has loaded;
      // isAuthenticated (which reveals the dashboard) flips only after.
      state = state.copyWith(
        connectionStatus: ConnectionStatus.connecting,
        authState: state.authState.copyWith(
          username: session.username,
          userId: session.userId,
          sessionToken: session.token,
        ),
      );
      await _loadIdentity();
      await _joinNetwork();
      _log('_restoreSession: connected + identity set, refreshing data');
      await refreshAllData();
      state = state.copyWith(
        connectionStatus: ConnectionStatus.connected,
        authState: state.authState.copyWith(isAuthenticated: true),
      );
    } catch (e) {
      _log('_restoreSession: FAILED -> $e (clearing stored session)');
      await _secureStore.clear();
    }
  }

  /// Connect to server
  Future<bool> connectToServer(String host, int port, {bool useTls = false}) async {
    state = state.copyWith(
      isLoading: true,
      errorMessage: null,
      connectionStatus: ConnectionStatus.connecting,
    );

    _log('connectToServer: host=$host port=$port useTls=$useTls');
    try {
      if (useTls) {
        await _sdk.connectTls(host, port);
      } else {
        await _sdk.connect(host, port);
      }
      state = state.copyWith(
        settings: state.settings.copyWith(
          serverHost: host,
          serverPort: port,
          useTls: useTls,
        ),
        connectionStatus: ConnectionStatus.connected,
        connectedSince: DateTime.now(),
        isLoading: false,
      );
      await _persistSettings();
      addActivity(ActivityLevel.success, 'Connected to $host:$port');
      _log('connectToServer: client created OK for $host:$port');
      return true;
    } catch (e) {
      state = state.copyWith(
        errorMessage: 'Failed to connect: $e',
        connectionStatus: ConnectionStatus.error,
        isLoading: false,
      );
      addActivity(ActivityLevel.error, 'Connection failed: $e');
      _log('connectToServer: FAILED -> $e');
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

    _log('signIn: start user=$username (connStatus=${state.connectionStatus.name})');
    try {
      final response = await _sdk.authPassword(username, password);
      _log('signIn: authPassword authenticated=${response.authenticated}');
      if (response.authenticated) {
        // Record session/identity but stay on the login view (spinner) until
        // the initial data load completes. isAuthenticated (which gates the
        // dashboard) and isLoading flip only once the connection is established.
        state = state.copyWith(
          authState: state.authState.copyWith(
            username: username,
            userId: response.userId,
            sessionToken: response.sessionToken,
            authenticatedAt: DateTime.now(),
          ),
          connectionStatus: ConnectionStatus.connecting,
        );

        // Set session token for future requests
        if (response.sessionToken != null) {
          await _sdk.setSessionToken(response.sessionToken!);
        }

        await _loadIdentity();
        await _joinNetwork();
        await refreshAllData();
        await _persistIdentity();
        if (response.sessionToken != null) {
          await _secureStore.saveSession(StoredSession(
            token: response.sessionToken!,
            username: username,
            userId: response.userId,
          ));
        }
        // Connection established — reveal the dashboard.
        state = state.copyWith(
          authState: state.authState.copyWith(isAuthenticated: true),
          connectionStatus: ConnectionStatus.connected,
          isLoading: false,
        );
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
      // First derive seed from credentials (returns base64-encoded 32-byte seed)
      final seedB64 = await _sdk.deriveSeed(username, password);
      // Decode base64 to raw 32 bytes for identity creation
      final seedBytes = base64Decode(seedB64);
      await _sdk.createIdentityFromSeed(seedBytes);
      // Set identity for client
      await _sdk.setIdentity();

      // Try to authenticate
      final response = await _sdk.authPassword(username, password);
      if (response.authenticated) {
        // Stay on the login view (spinner) until the initial data load finishes.
        state = state.copyWith(
          authState: state.authState.copyWith(
            username: username,
            userId: response.userId,
            sessionToken: response.sessionToken,
            authenticatedAt: DateTime.now(),
          ),
          connectionStatus: ConnectionStatus.connecting,
        );
        if (response.sessionToken != null) {
          await _sdk.setSessionToken(response.sessionToken!);
        }
        await _loadIdentity();
        await _joinNetwork();
        await refreshAllData();
        await _persistIdentity();
        if (response.sessionToken != null) {
          await _secureStore.saveSession(StoredSession(
            token: response.sessionToken!,
            username: username,
            userId: response.userId,
          ));
        }
        // Connection established — reveal the dashboard.
        state = state.copyWith(
          authState: state.authState.copyWith(isAuthenticated: true),
          connectionStatus: ConnectionStatus.connected,
          isLoading: false,
        );
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

  /// Register a passkey (Secure Enclave) and authenticate with it.
  Future<bool> registerPasskey(String username) async {
    state = state.copyWith(isLoading: true, errorMessage: null);
    try {
      final cred = await _passkey.generateCredential(username);
      final resp = await _sdk.registerPasskey(
        userId: username,
        credentialId: cred.credentialId,
        publicKeyX: cred.publicKeyX,
        publicKeyY: cred.publicKeyY,
      );
      final token = resp['session_token'] as String?;
      if (resp['authenticated'] == true) {
        if (token != null) await _sdk.setSessionToken(token);
        // Stay on the login view (spinner) until the initial data load finishes.
        state = state.copyWith(
          authState: state.authState.copyWith(
            username: username,
            userId: resp['user_id'] as String?,
            sessionToken: token,
          ),
          hasStoredPasskey: true,
          storedPasskeyUserId: username,
          connectionStatus: ConnectionStatus.connecting,
        );
        if (token != null) {
          await _secureStore.saveSession(StoredSession(
              token: token, username: username, userId: resp['user_id'] as String?));
        }
        await _establishPasskeyMeshIdentity(token);
        await _loadIdentity();
        await _joinNetwork();
        await refreshAllData();
        // Connection established — reveal the dashboard.
        state = state.copyWith(
          authState: state.authState.copyWith(isAuthenticated: true),
          connectionStatus: ConnectionStatus.connected,
          isLoading: false,
        );
        addActivity(ActivityLevel.success, 'Registered passkey for $username');
        return true;
      }
      state = state.copyWith(
        isLoading: false,
        hasStoredPasskey: true,
        storedPasskeyUserId: username,
        errorMessage: resp['error'] as String? ?? 'Passkey registration failed',
      );
      return false;
    } catch (e) {
      state = state.copyWith(
          isLoading: false, errorMessage: 'Passkey registration failed: $e');
      return false;
    }
  }

  /// Sign in with the stored passkey (triggers Touch ID).
  Future<bool> signInWithPasskey() async {
    state = state.copyWith(isLoading: true, errorMessage: null);
    _log('signInWithPasskey: start (connStatus=${state.connectionStatus.name})');
    try {
      final assertion = await _passkey.signAssertion('lemonade-nexus.local');
      final resp = await _sdk.authPasskey({
        'method': 'passkey',
        'assertion': assertion.toAssertionJson(),
      });
      _log('signInWithPasskey: authPasskey authenticated=${resp.authenticated}');
      if (resp.authenticated) {
        final username = state.storedPasskeyUserId ?? '';
        if (resp.sessionToken != null) await _sdk.setSessionToken(resp.sessionToken!);
        // Stay on the login view (spinner) until the initial data load finishes;
        // isAuthenticated/isLoading flip only once the connection is established.
        state = state.copyWith(
          authState: state.authState.copyWith(
            username: username,
            userId: resp.userId,
            sessionToken: resp.sessionToken,
          ),
          connectionStatus: ConnectionStatus.connecting,
        );
        if (resp.sessionToken != null) {
          await _secureStore.saveSession(StoredSession(
              token: resp.sessionToken!, username: username, userId: resp.userId));
        }
        await _establishPasskeyMeshIdentity(resp.sessionToken);
        await _loadIdentity();
        await _joinNetwork();
        await refreshAllData();
        // Connection established — reveal the dashboard.
        state = state.copyWith(
          authState: state.authState.copyWith(isAuthenticated: true),
          connectionStatus: ConnectionStatus.connected,
          isLoading: false,
        );
        addActivity(ActivityLevel.success, 'Signed in with passkey');
        return true;
      }
      state = state.copyWith(
          isLoading: false, errorMessage: resp.error ?? 'Passkey sign-in failed');
      return false;
    } catch (e) {
      state = state.copyWith(
          isLoading: false, errorMessage: 'Passkey sign-in failed: $e');
      return false;
    }
  }

  /// Remove the stored passkey credential.
  Future<void> deletePasskey() async {
    await _passkey.deleteCredential();
    state = state.copyWith(hasStoredPasskey: false);
  }

  /// Joins the mesh network as an endpoint (auth + create_node + IP allocation).
  ///
  /// This is what populates the SDK's WireGuard config (assigns the tunnel IP +
  /// node id); without it [connectTunnel] has no config to bring up. Mirrors the
  /// macOS `joinAsEndpoint()`. Best-effort: a join failure leaves the user
  /// authenticated but without a tunnel.
  Future<void> _joinNetwork() async {
    try {
      final username = state.username ?? '';
      final join = await _sdk.joinNetwork(username: username, password: '');
      _log('joinNetwork: success=${join.success} nodeId=${join.nodeId} '
          'tunnelIp=${join.tunnelIp}');
      if (join.nodeId != null) {
        await _sdk.setNodeId(join.nodeId!);
      }
      if (join.tunnelIp != null) {
        addActivity(ActivityLevel.success,
            'Joined network — tunnel IP: ${join.tunnelIp}');
      } else if (!join.success) {
        addActivity(ActivityLevel.warning,
            'Network join incomplete: ${join.error ?? 'no tunnel IP assigned'}');
      }
    } catch (e) {
      _log('joinNetwork: FAILED -> $e');
      addActivity(ActivityLevel.warning, 'Network join failed: $e');
    }
  }

  /// Establishes the Ed25519 mesh identity for a passkey session.
  ///
  /// Passkey auth (Secure Enclave P-256) is auth-only; mesh node creation needs
  /// a separate Ed25519 identity. Generate + set one, register it via an Ed25519
  /// challenge so the server grants node-creation permission, then restore the
  /// passkey session token (Ed25519 auth returns its own). Mirrors the macOS
  /// passkey flow (generateIdentity -> authenticateEd25519 -> re-set token).
  Future<void> _establishPasskeyMeshIdentity(String? passkeyToken) async {
    try {
      await _sdk.generateIdentity();
      // Flutter's generateIdentity() (unlike macOS) does not set the identity on
      // the client — do it explicitly so join/tree ops can sign.
      await _sdk.setIdentity();
      try {
        await _sdk.authEd25519();
        _log('establishPasskeyMeshIdentity: Ed25519 key registered');
      } catch (e) {
        _log('establishPasskeyMeshIdentity: authEd25519 failed (non-fatal): $e');
      }
      // Ed25519 auth returns its own token; restore the passkey session token.
      // (The join flow then overrides this with the node-scoped token.)
      if (passkeyToken != null) await _sdk.setSessionToken(passkeyToken);
    } catch (e) {
      _log('establishPasskeyMeshIdentity: FAILED -> $e');
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
    await _secureStore.clear();
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
    _log('refreshAllData: meshEnabled=${state.isMeshEnabled} '
        'connStatus=${state.connectionStatus.name} authed=${state.isAuthenticated}');
    await Future.wait([
      refreshHealth(),
      refreshStats(),
      refreshServers(),
      refreshMeshStatus(),
      // /api/relay/list and /api/trust/status are private-API endpoints reached
      // through the mesh/routing layer; they 404 on the plain public connection.
      // Refresh them once the mesh is up.
      if (state.isMeshEnabled) refreshRelays(),
      if (state.isMeshEnabled) refreshTrustStatus(),
    ]);
    _log('refreshAllData done: isServerHealthy=${state.isServerHealthy} '
        'servers=${state.servers.length} stats=${state.stats != null}');
  }

  /// Refresh health status
  Future<void> refreshHealth() async {
    try {
      final h = await _sdk.health();
      state = state.copyWith(healthStatus: h);
      _log('refreshHealth: OK (status=${h.status} service=${h.service}) '
          '-> isServerHealthy=${state.isServerHealthy}');
    } catch (e) {
      state = state.copyWith(
        healthStatus: HealthResponse(status: 'error'),
      );
      _log('refreshHealth: FAILED -> $e');
    }
  }

  /// Refresh stats
  ///
  /// Note: the value is awaited into a local *before* `state = state.copyWith`.
  /// Inlining the await (`state.copyWith(stats: await ...)`) evaluates the
  /// `state` receiver before suspending, so a concurrent refresh in
  /// [refreshAllData]'s Future.wait can overwrite this update from a stale
  /// snapshot (this is what was wiping out the health status -> "Disconnected").
  Future<void> refreshStats() async {
    try {
      final stats = await _sdk.getStats();
      state = state.copyWith(stats: stats);
    } catch (e) {
      // Stats unavailable
    }
  }

  /// Refresh servers
  Future<void> refreshServers() async {
    try {
      final servers = await _sdk.listServers();
      state = state.copyWith(servers: servers);
      _log('refreshServers: ${servers.length} server(s)');
    } catch (e) {
      state = state.copyWith(servers: []);
      _log('refreshServers: FAILED -> $e');
    }
  }

  /// Refresh relays
  Future<void> refreshRelays() async {
    try {
      final relays = await _sdk.listRelays();
      state = state.copyWith(relays: relays);
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
      _log('refreshMeshStatus: up=${meshStatus.isUp} '
          'peers=${meshStatus.peerCount} online=${meshStatus.onlineCount} '
          'meshIp=${meshStatus.tunnelIp} (${meshPeers.length} peer records)');
    } catch (e) {
      state = state.copyWith(
        peerState: const PeerState(
          meshStatus: null,
          meshPeers: [],
        ),
      );
      _log('refreshMeshStatus: FAILED -> $e');
    }
  }

  /// Refresh trust status (private API — reached via the mesh routing layer).
  Future<void> refreshTrustStatus() async {
    try {
      final trustStatus = await _sdk.getTrustStatus();
      state = state.copyWith(trustStatus: trustStatus);
      _log('refreshTrustStatus: OK tier=${trustStatus.trustTier} '
          'peers=${trustStatus.peerCount}');
    } catch (e) {
      _log('refreshTrustStatus: FAILED -> $e');
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

  /// Enable P2P mesh networking (userspace BoringTun via the routing layer).
  Future<void> enableMesh() async {
    state = state.copyWith(isLoading: true);
    _log('enableMesh: start (nodeId set, connStatus=${state.connectionStatus.name})');
    try {
      await _sdk.enableMesh();
      _log('enableMesh: ln_mesh_enable OK — refreshing mesh status');
      await refreshMeshStatus();
      final m = state.meshStatus;
      _log('enableMesh: meshUp=${m?.isUp} peers=${m?.peerCount} '
          'online=${m?.onlineCount} meshIp=${m?.tunnelIp}');
      addActivity(ActivityLevel.success, 'Mesh enabled');
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to enable mesh: $e');
      addActivity(ActivityLevel.error, 'Failed to enable mesh: $e');
      _log('enableMesh: FAILED -> $e');
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  /// Disable P2P mesh networking.
  Future<void> disableMesh() async {
    state = state.copyWith(isLoading: true);
    _log('disableMesh: start');
    try {
      await _sdk.disableMesh();
      await refreshMeshStatus();
      _log('disableMesh: ln_mesh_disable OK -> meshUp=${state.meshStatus?.isUp}');
      addActivity(ActivityLevel.info, 'Mesh disabled');
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to disable mesh: $e');
      addActivity(ActivityLevel.error, 'Failed to disable mesh: $e');
      _log('disableMesh: FAILED -> $e');
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  /// Toggle P2P mesh networking.
  Future<void> toggleMesh() async {
    _log('toggleMesh: currentlyEnabled=${state.isMeshEnabled}');
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

  /// Region-aware DNS discovery of the nearest server; points settings at it.
  Future<void> discoverNearestServer() async {
    state = state.copyWith(isDiscovering: true);
    final service = DnsDiscoveryService();
    try {
      final servers = await service.discoverServers();
      state = state.copyWith(
        isDiscovering: false,
        discoveredServers: servers,
        discoveryMessage: service.lastMessage,
      );
      _log('discoverNearestServer: found ${servers.length} server(s)');
      if (servers.isNotEmpty) {
        final best = servers.first;
        _log('discoverNearestServer: best=${best.displayName} '
            'host=${best.connectHost ?? best.hostname ?? best.ip} '
            'port=${best.port} scheme=${best.scheme}');
        await connectToServer(
          best.connectHost ?? best.hostname ?? best.ip,
          best.port,
          useTls: best.scheme == 'https',
        );
        addActivity(ActivityLevel.success,
            'Discovered ${servers.length} server${servers.length == 1 ? '' : 's'} — nearest ${best.displayName}');
      } else {
        addActivity(ActivityLevel.warning,
            service.lastMessage ?? 'No servers discovered');
      }
    } catch (e) {
      state = state.copyWith(
          isDiscovering: false, discoveryMessage: 'Discovery failed: $e');
    } finally {
      service.close();
    }
  }

  /// Set auto discovery enabled
  void setAutoDiscoveryEnabled(bool enabled) {
    state = state.copyWith(
      settings: state.settings.copyWith(autoDiscoveryEnabled: enabled),
    );
    _persistSettings();
  }

  /// Set auto connect on launch
  void setAutoConnectOnLaunch(bool enabled) {
    state = state.copyWith(
      settings: state.settings.copyWith(autoConnectOnLaunch: enabled),
    );
    _persistSettings();
  }

  /// Clear error message
  void clearError() {
    state = state.copyWith(errorMessage: null);
  }

  /// Set an error message (e.g. client-side validation).
  void setError(String message) {
    state = state.copyWith(errorMessage: message);
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
