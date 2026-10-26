/// @title Application State
/// @description Central state management for the Flutter app using Riverpod.
///
/// Tracks authentication, mesh status, UI navigation state,
/// and all data fetched from the C SDK.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
import '../platform/app_paths.dart';
import '../platform/settings_store.dart';
import '../platform/secure_store.dart';
import 'package:lemonade_nexus_sdk/dns_discovery.dart';
import '../services/passkey_manager.dart';
import 'cluster_keyring.dart';
import 'device_identity.dart';
import 'session_policy.dart';

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
  /// The seed server: where the SDK starts discovery and the Tier 1
  /// membership walk. Tree, session, and private-API requests go only to the
  /// Tier 1 servers the SDK verifies, never to this host unless it is one.
  final String serverHost;
  final int serverPort;
  final bool autoDiscoveryEnabled;
  final bool autoConnectOnLaunch;
  final bool useTls;
  final bool darkModeEnabled;

  /// The network's Genesis public key (base64). The SDK verifies Tier 1
  /// servers from it; without it no tree request is sent. When empty at
  /// connect, the app discovers it once and saves it here.
  final String genesisKey;

  /// The highest Tier 1 epoch this app verified. The SDK refuses an older
  /// membership after a restart.
  final int tier1MinEpoch;

  const Settings({
    this.serverHost = 'localhost',
    this.serverPort = 9100,
    this.autoDiscoveryEnabled = true,
    this.autoConnectOnLaunch = false,
    this.useTls = false,
    this.darkModeEnabled = true,
    this.genesisKey = '',
    this.tier1MinEpoch = 0,
  });

  Settings copyWith({
    String? serverHost,
    int? serverPort,
    bool? autoDiscoveryEnabled,
    bool? autoConnectOnLaunch,
    bool? useTls,
    bool? darkModeEnabled,
    String? genesisKey,
    int? tier1MinEpoch,
  }) {
    return Settings(
      serverHost: serverHost ?? this.serverHost,
      serverPort: serverPort ?? this.serverPort,
      autoDiscoveryEnabled: autoDiscoveryEnabled ?? this.autoDiscoveryEnabled,
      autoConnectOnLaunch: autoConnectOnLaunch ?? this.autoConnectOnLaunch,
      useTls: useTls ?? this.useTls,
      darkModeEnabled: darkModeEnabled ?? this.darkModeEnabled,
      genesisKey: genesisKey ?? this.genesisKey,
      tier1MinEpoch: tier1MinEpoch ?? this.tier1MinEpoch,
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

/// Sidebar navigation items (declaration order drives the sidebar order).
enum SidebarItem {
  dashboard,
  account,
  peers,
  meshPort,
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
      case SidebarItem.meshPort:
        return 'Mesh Port';
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
      case SidebarItem.account:
        return 'Cluster';
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
      case SidebarItem.meshPort:
        return Icons.lan;
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
      case SidebarItem.account:
        return Icons.account_circle_outlined;
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

  /// Clusters (accounts) this install can connect to — rendered by the login page.
  final List<ClusterEntry> clusters;

  /// localId of the Cluster currently connected (null when none).
  final String? activeClusterId;

  /// The loopback mesh port that serves group devices by name.
  final MeshPortStatus meshPortStatus;

  /// This OS user's device identity in the SDK's per-user store.
  final DeviceIdentityState deviceIdentity;

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
    this.clusters = const [],
    this.activeClusterId,
    this.meshPortStatus = MeshPortStatus.stopped,
    this.deviceIdentity = DeviceIdentityState.unknown,
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
    List<ClusterEntry>? clusters,
    String? activeClusterId,
    MeshPortStatus? meshPortStatus,
    DeviceIdentityState? deviceIdentity,
    // copyWith can't null a field via the ?? pattern; sign-out needs to.
    bool clearActiveCluster = false,
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
      clusters: clusters ?? this.clusters,
      activeClusterId:
          clearActiveCluster ? null : (activeClusterId ?? this.activeClusterId),
      meshPortStatus: meshPortStatus ?? this.meshPortStatus,
      deviceIdentity: deviceIdentity ?? this.deviceIdentity,
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
  // The legacy VPN tunnel was removed in favour of the userspace mesh; surface
  // the mesh-assigned IP here so existing views keep showing a usable address.
  String? get tunnelIP => tunnelStatus?.tunnelIp ?? meshStatus?.tunnelIp;
  MeshStatus? get meshStatus => peerState.meshStatus;
  List<MeshPeer> get meshPeers => peerState.meshPeers;

  /// The Cluster currently connected, if any.
  ClusterEntry? get activeCluster {
    if (activeClusterId == null) return null;
    for (final c in clusters) {
      if (c.localId == activeClusterId) return c;
    }
    return null;
  }
}

/// Notifier for managing app state
class AppNotifier extends StateNotifier<AppState> {
  final LemonadeNexusSdk _sdk;
  final SettingsStore _settingsStore = SettingsStore();
  final SecureStore _secureStore = SecureStore();
  final PasskeyManager _passkey = PasskeyManager();
  final ClusterKeyring _keyring = ClusterKeyring();

  // --- Connection recovery ---
  // Periodic health probe that drives auto-reconnect when the connected server
  // goes down. One timer for the notifier's lifetime; no-ops until authed.
  Timer? _healthTimer;
  bool _isRecovering = false;
  DateTime? _lastRecoveryAttempt;
  int _recoveryFailures = 0;
  static const Duration _recoveryCooldown = Duration(seconds: 20);
  static const Duration _healthInterval = Duration(seconds: 5);
  static const int _maxRecoveryFailures = 3;

  // --- Session moves and re-join ---
  // When the session's Tier 1 server leaves the membership at an epoch
  // boundary the SDK moves the session to another verified server by itself
  // and reports it on [LemonadeNexusSdk.sessionMoves]. Only when it cannot
  // (no identity, or the silent join failed) does it drop the session: every
  // private call is then refused until the device joins again, so the event
  // handler and refreshMeshStatus re-join when the SDK says so.
  StreamSubscription<SessionMoveEvent>? _sessionMoves;
  DateTime? _lastRejoinAttempt;
  static const Duration _rejoinCooldown = Duration(seconds: 30);

  // --- Device name ---
  // True once this session has checked the endpoint's name against the
  // machine's host name; the check needs the private API, so it waits for
  // the mesh. Reset at sign-out.
  bool _deviceNamed = false;

  AppNotifier(this._sdk) : super(AppState.initial) {
    _sessionMoves = _sdk.sessionMoves.listen(_onSessionMoved);
    _startHealthMonitor();
  }

  /// Public, read-only accessor to the current state for external callers.
  AppState get currentState => state;

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

  /// Load persisted preferences + the Cluster keyring, bring up the device
  /// identity, then optionally reconnect to the last-used Cluster.
  Future<void> _loadPreferences() async {
    final settings = await _settingsStore.load();
    state = state.copyWith(settings: settings);
    await loadClusters();
    await prepareDeviceIdentity();
    await _restoreSession();
  }

  Future<void> _persistSettings() => _settingsStore.save(state.settings);

  /// Reconnect to the most recently used Cluster when auto-connect is on.
  Future<void> _restoreSession() async {
    if (!state.settings.autoConnectOnLaunch) return;
    final previous = state.clusters
        .where((c) => c.lastUsed != null)
        .toList(); // keyring returns most-recent first
    if (previous.isEmpty) {
      _log('_restoreSession: no previously connected Cluster');
      return;
    }
    _log('_restoreSession: auto-connecting to "${previous.first.name}"');
    if (!await connectToCluster(previous.first)) {
      _log('_restoreSession: auto-connect failed; showing the login page');
      state = state.copyWith(
        authState: AuthState.initial,
        connectionStatus: ConnectionStatus.disconnected,
        isLoading: false,
      );
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
      if (state.settings.genesisKey.trim().isEmpty) {
        await _discoverGenesisKey();
      } else {
        _applyGenesisKey();
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

  /// Pin the network key in the SDK. Tree, session, and private-API requests
  /// go only to Tier 1 servers verified from it; without it they fail with an
  /// error that names the missing key.
  void _applyGenesisKey() {
    final key = state.settings.genesisKey.trim();
    if (key.isEmpty) {
      _log('connectToServer: no network key set; tree requests will not be sent');
      addActivity(ActivityLevel.warning,
          'Set the network key in Settings to reach Tier 1 servers');
      return;
    }
    try {
      _sdk.setGenesisKey(key, minEpoch: state.settings.tier1MinEpoch);
    } catch (e) {
      _log('connectToServer: network key refused -> $e');
      addActivity(ActivityLevel.error, 'The network key is not valid: $e');
    }
  }

  /// First connect with no network key: the SDK finds the key on several
  /// servers of the network and pins it, then this saves it. It is trust on
  /// first use: it rests on verified-HTTPS ownership of the network domain
  /// and on agreement of at least 3 servers. The saved key is never replaced
  /// automatically; the Settings field stays the manual override.
  Future<void> _discoverGenesisKey() async {
    try {
      var servers = state.discoveredServers;
      if (servers.isEmpty && state.settings.autoDiscoveryEnabled) {
        final service = DnsDiscoveryService();
        try {
          servers = await service.discoverServers();
        } finally {
          service.close();
        }
      }
      final hosts = [
        for (final s in servers)
          if ((s.connectHost ?? s.hostname) != null)
            (host: (s.connectHost ?? s.hostname)!, port: s.port),
      ];
      final found = await _sdk.discoverGenesisKey(hosts: hosts);
      final key = (found['genesis_pubkey'] as String?) ?? '';
      final agreeing = (found['hosts'] as List?)?.length ?? 0;
      _log('connectToServer: network key found on $agreeing servers');
      await setGenesisKey(key);
      addActivity(ActivityLevel.success,
          'Found the network key on $agreeing servers and saved it');
    } catch (e) {
      _log('connectToServer: network key discovery failed -> $e');
      addActivity(ActivityLevel.error,
          'The network key was not found: $e. Set it in Settings.');
    }
  }

  /// Save the network key and pin it in the SDK. A new key resets the
  /// stored Tier 1 epoch floor.
  Future<void> setGenesisKey(String key) async {
    final trimmed = key.trim();
    final changed = trimmed != state.settings.genesisKey;
    state = state.copyWith(
      settings: state.settings.copyWith(
        genesisKey: trimmed,
        tier1MinEpoch: changed ? 0 : state.settings.tier1MinEpoch,
      ),
    );
    await _persistSettings();
    if (state.connectionStatus != ConnectionStatus.disconnected) {
      _applyGenesisKey();
    }
  }

  /// Remember the verified Tier 1 epoch, so a later run refuses an older one.
  /// Reads the SDK's last verified membership (no network I/O) and saves the
  /// epoch next to the network key when it grows; it never shrinks.
  Future<void> _recordTier1Epoch() async {
    try {
      final membership = await _sdk.tier1Membership();
      final stored = state.settings.tier1MinEpoch;
      final epoch = nextTier1MinEpoch(stored, membership['epoch']);
      if (epoch != stored) {
        state = state.copyWith(
            settings: state.settings.copyWith(tier1MinEpoch: epoch));
        await _persistSettings();
        _log('_recordTier1Epoch: Tier 1 epoch floor is now $epoch');
      }
    } catch (e) {
      _log('_recordTier1Epoch: $e');
    }
  }

  /// Disconnect from server.
  ///
  /// Uses [LemonadeNexusSdk.disconnect] (not [dispose]) so the SDK stays
  /// reusable for a later reconnect/re-login; [clearIdentity] drops the Ed25519
  /// identity too, which logout wants so the next session starts clean.
  Future<void> disconnectFromServer({bool clearIdentity = false}) async {
    await stopMeshPort();
    try {
      _sdk.disconnect(clearIdentity: clearIdentity);
    } catch (e) {
      // Ignore disconnect errors
    }
    state = state.copyWith(
      connectionStatus: ConnectionStatus.disconnected,
      connectedSince: null,
    );
    addActivity(ActivityLevel.info, 'Disconnected from server');
  }

  // =========================================================================
  // Clusters (accounts). A membership is this user's device identity (SDK
  // store) plus the group key in the keyring — no passwords. Register (new),
  // Join (invite code), Connect (already held).
  // =========================================================================

  /// Load the keyring into state; the login page renders this list.
  Future<void> loadClusters() async {
    final clusters = await _keyring.load();
    _log('loadClusters: ${clusters.length} cluster(s)');
    state = state.copyWith(clusters: clusters);
  }

  String _randomBase64(int byteCount) {
    final rng = Random.secure();
    return base64Encode(List<int>.generate(byteCount, (_) => rng.nextInt(256)));
  }

  // ---- device identity --------------------------------------------------------
  //
  // One identity per signed-in OS user, kept by the SDK's per-user store
  // behind the OS keystore (ln_identity_user_*). The app never generates a
  // key of its own and never keeps a seed in secure storage: when the store
  // is unavailable or locked the identity is missing and join/register say
  // why. Legacy seeds (per-Cluster, in the keyring) and identity.json move
  // into the store once, then the legacy copy is deleted.

  /// Read the store, run the one-time migration, and load (or create) the
  /// user's identity into the SDK. Safe to call again from the settings view
  /// after the user fixes the keystore.
  Future<void> prepareDeviceIdentity() async {
    IdentityStoreStatus? status;
    try {
      status = await _sdk.identityStoreStatus();
      _log('prepareDeviceIdentity: backend=${status.backend} '
          'present=${status.present} unlocked=${status.unlocked}');
      await _migrateLegacyIdentities(status);
      await _ensureIdentityLoaded();
      status = await _sdk.identityStoreStatus();
      state = state.copyWith(deviceIdentity: DeviceIdentityState(status: status));
      await _loadIdentity();
    } on SdkException catch (e) {
      final why = explainIdentityStoreFailure(e.error, status: status);
      _log('prepareDeviceIdentity: ${e.error.name} -> $why');
      state = state.copyWith(
          deviceIdentity: DeviceIdentityState(status: status, error: why));
      addActivity(ActivityLevel.error, 'Device identity unavailable: $why');
    } catch (e) {
      _log('prepareDeviceIdentity: FAILED -> $e');
      state = state.copyWith(
          deviceIdentity: DeviceIdentityState(status: status, error: '$e'));
      addActivity(ActivityLevel.error, 'Device identity unavailable: $e');
    }
  }

  /// Load the stored identity into the SDK when none is loaded; create one
  /// when the store is empty. Throws [SdkException] when the store cannot
  /// give one (no keystore, locked, or a damaged file).
  Future<void> _ensureIdentityLoaded() async {
    if (_sdk.identityPubkey != null) return;
    try {
      await _sdk.loadUserIdentity();
      _log('ensureIdentityLoaded: loaded the stored identity');
    } on SdkException catch (e) {
      if (e.error != LnError.notFound) rethrow;
      final created = await _sdk.createUserIdentity();
      _log('ensureIdentityLoaded: created ${created.pubkey}');
      addActivity(ActivityLevel.success, 'Created this device\'s identity');
    }
  }

  /// Move legacy identity copies into the store. Imports the most recently
  /// used copy when the store is empty, verifies the store then holds that
  /// key, and deletes the legacy copies of the stored identity. A copy with
  /// a different key is kept and reported; neither side is overwritten.
  Future<void> _migrateLegacyIdentities(IdentityStoreStatus status) async {
    final legacy = <LegacyIdentity>[];
    for (final c in state.clusters) {
      // Keyring order is most recently used first.
      if (!c.hasLegacySeed) continue;
      final seed = _decodeSeed(c.legacySeedB64!);
      final pubkey = seed == null ? null : _sdk.publicKeyOfSeed(seed);
      if (pubkey == null) {
        addActivity(ActivityLevel.warning,
            'The stored key of Cluster "${c.name}" is not valid and was left alone');
        continue;
      }
      legacy.add(LegacyIdentity(
          source: LegacyIdentitySource.keyring,
          localId: c.localId,
          name: 'Cluster "${c.name}"',
          publicKey: pubkey));
    }
    final file = File(await AppPaths.identityFilePath());
    String? fileText;
    if (await file.exists()) {
      fileText = await file.readAsString();
      final pubkey = _sdk.publicKeyOfIdentityJson(fileText);
      if (pubkey == null) {
        addActivity(ActivityLevel.warning,
            'The identity file ${file.path} is not valid and was left alone');
      } else {
        legacy.add(LegacyIdentity(
            source: LegacyIdentitySource.identityFile,
            name: file.path,
            publicKey: pubkey));
      }
    }
    if (legacy.isEmpty) return;

    final plan = planIdentityMigration(
        storePublicKey: status.present ? status.publicKey : null, legacy: legacy);
    final toImport = plan.import;
    if (toImport != null) {
      final imported = toImport.source == LegacyIdentitySource.keyring
          ? await _sdk.importUserIdentityFromSeed(
              _decodeSeed(_clusterById(toImport.localId!)!.legacySeedB64!)!)
          : await _sdk.importUserIdentityFromJson(fileText!);
      final after = await _sdk.identityStoreStatus();
      if (!after.present ||
          after.publicKey == null ||
          !sameIdentityKey(after.publicKey!, imported) ||
          !sameIdentityKey(imported, toImport.publicKey)) {
        // The store does not hold what was imported; keep the legacy copy.
        throw SdkException(LnError.rejected,
            message: 'the imported identity does not match the store');
      }
      await _deleteLegacyIdentity(toImport, file);
      addActivity(ActivityLevel.success,
          'Moved the device identity of ${toImport.name} into the user identity store');
    }
    for (final copy in plan.remove) {
      await _deleteLegacyIdentity(copy, file);
    }
    for (final copy in plan.conflicts) {
      addActivity(ActivityLevel.warning,
          '${copy.name} uses a different device identity than the one stored for '
          'this user; it was left in place and cannot connect. Forget it and '
          'join again with an invitation code.');
    }
  }

  Future<void> _deleteLegacyIdentity(LegacyIdentity copy, File identityFile) async {
    switch (copy.source) {
      case LegacyIdentitySource.keyring:
        final entry = _clusterById(copy.localId!);
        if (entry == null) return;
        final clusters = await _keyring.upsert(entry.copyWith(clearLegacySeed: true));
        state = state.copyWith(clusters: clusters);
      case LegacyIdentitySource.identityFile:
        if (await identityFile.exists()) await identityFile.delete();
    }
  }

  ClusterEntry? _clusterById(String localId) {
    for (final c in state.clusters) {
      if (c.localId == localId) return c;
    }
    return null;
  }

  Uint8List? _decodeSeed(String seedB64) {
    try {
      final seed = Uint8List.fromList(base64Decode(base64.normalize(seedB64)));
      return seed.length == 32 ? seed : null;
    } on FormatException {
      return null;
    }
  }

  /// Bind this user's device identity to the connected client. Loads it from
  /// the store first when needed; a store failure surfaces as the reason the
  /// join or register cannot proceed.
  Future<void> _activateIdentity() async {
    try {
      await _ensureIdentityLoaded();
    } on SdkException catch (e) {
      final why = explainIdentityStoreFailure(e.error,
          status: state.deviceIdentity.status);
      state = state.copyWith(
          deviceIdentity: DeviceIdentityState(
              status: state.deviceIdentity.status, error: why));
      throw DeviceIdentityUnavailable(why);
    }
    await _sdk.setIdentity();
  }

  /// Ensure the SDK is connected to a server before an auth/join attempt.
  Future<bool> _ensureServerConnection({
    String? host,
    int? port,
    bool? useTls,
  }) async {
    final s = state.settings;
    final targetHost = host ?? s.serverHost;
    final targetPort = port ?? s.serverPort;
    if (targetHost.isEmpty || targetPort == 0) {
      state = state.copyWith(
        errorMessage: 'No server available — run discovery first.',
        isLoading: false,
      );
      return false;
    }
    final switching = targetHost != s.serverHost || targetPort != s.serverPort;
    if (state.isConnected && !switching) return true;
    return connectToServer(targetHost, targetPort, useTls: useTls ?? s.useTls);
  }

  /// Shared tail of register/join/connect: Ed25519 auth, mesh join, initial load.
  /// [clusterName] labels this device's endpoint on the server.
  Future<bool> _authJoinAndLoad(String clusterName) async {
    final response = await _sdk.authEd25519();
    _log('_authJoinAndLoad: authenticated=${response.authenticated}');
    if (!response.authenticated) {
      state = state.copyWith(
        errorMessage: response.error ?? 'Authentication failed',
        isLoading: false,
      );
      return false;
    }
    // isAuthenticated flips only after the initial load, so the login view
    // keeps its spinner until the dashboard has data.
    state = state.copyWith(
      authState: state.authState.copyWith(
        username: clusterName,
        userId: response.userId,
        sessionToken: response.sessionToken,
        authenticatedAt: DateTime.now(),
      ),
      connectionStatus: ConnectionStatus.connecting,
    );
    if (response.sessionToken != null) {
      await _sdk.setSessionToken(response.sessionToken!);
      await _secureStore.saveSession(StoredSession(
        token: response.sessionToken!,
        username: clusterName,
        userId: response.userId,
      ));
    }
    await _loadIdentity();
    await _recordTier1Epoch();
    _deviceNamed = false;
    // Cluster operations all ride the private mesh API, so bring it up here.
    if (await _joinNetwork()) {
      await _recordTier1Epoch();
      await enableMesh();
      await _waitForMesh();
      await _applyDefaultDeviceName();
    }
    await refreshAllData();
    state = state.copyWith(
      authState: state.authState.copyWith(isAuthenticated: true),
      connectionStatus: ConnectionStatus.connected,
      isLoading: false,
    );
    return true;
  }

  /// The tunnel handshakes asynchronously after enableMesh; private-API loads
  /// are gated on it being up, so give it a moment before the first refresh.
  Future<void> _waitForMesh(
      {Duration timeout = const Duration(seconds: 6)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!state.isMeshEnabled && DateTime.now().isBefore(deadline)) {
      await Future.delayed(const Duration(milliseconds: 400));
      await refreshMeshStatus();
    }
    if (!state.isMeshEnabled) _log('_waitForMesh: timed out, mesh still down');
  }

  Future<void> _saveActiveCluster(ClusterEntry entry) async {
    final clusters = await _keyring.upsert(entry);
    state = state.copyWith(clusters: clusters, activeClusterId: entry.localId);
  }

  /// Register a brand-new Cluster; this device owns it and holds the group key.
  Future<bool> registerCluster(String name) async {
    state = state.copyWith(isLoading: true, errorMessage: null);
    _log('registerCluster: "$name"');
    try {
      if (!await _ensureServerConnection()) return false;

      await _activateIdentity();
      if (!await _authJoinAndLoad(name)) return false;

      String? groupKey;
      try {
        groupKey = _sdk.generateGroupKey();
        await _provisionGroupKeyTo(_sdk.identityPubkey ?? '', groupKey);
      } catch (e) {
        // The key is still held locally; provisioning retries on next connect.
        _log('registerCluster: self-provision deferred -> $e');
      }

      final s = state.settings;
      await _saveActiveCluster(ClusterEntry(
        localId: _randomBase64(8),
        name: name,
        role: 'owner',
        groupKeyB64: groupKey,
        userId: state.userId,
        serverHost: s.serverHost,
        serverPort: s.serverPort,
        useTls: s.useTls,
        lastUsed: DateTime.now(),
      ));
      addActivity(ActivityLevel.success, 'Registered Cluster "$name"');
      return true;
    } catch (e) {
      state = state.copyWith(errorMessage: 'Register failed: $e', isLoading: false);
      addActivity(ActivityLevel.error, 'Register failed: $e');
      return false;
    }
  }

  /// Join an existing Cluster with an invitation code. Can succeed without the
  /// group key — an owner device must seal it to us separately.
  Future<bool> joinCluster(String inviteCode, {String name = 'Cluster'}) async {
    state = state.copyWith(isLoading: true, errorMessage: null);
    _log('joinCluster: name="$name"');
    try {
      if (!await _ensureServerConnection()) return false;

      await _activateIdentity();
      _sdk.setLinkToken(inviteCode.trim());
      if (!await _authJoinAndLoad(name)) return false;

      final groupKey = await fetchGroupKey();
      final s = state.settings;
      await _saveActiveCluster(ClusterEntry(
        localId: _randomBase64(8),
        name: name,
        role: 'member',
        groupKeyB64: groupKey,
        userId: state.userId,
        serverHost: s.serverHost,
        serverPort: s.serverPort,
        useTls: s.useTls,
        lastUsed: DateTime.now(),
      ));
      addActivity(
          ActivityLevel.success,
          groupKey == null
              ? 'Joined "$name" — waiting for the account key'
              : 'Joined Cluster "$name"');
      return true;
    } catch (e) {
      state = state.copyWith(errorMessage: 'Join failed: $e', isLoading: false);
      addActivity(ActivityLevel.error, 'Join failed: $e');
      return false;
    }
  }

  /// Connect to a Cluster already in the keyring.
  Future<bool> connectToCluster(ClusterEntry entry) async {
    state = state.copyWith(isLoading: true, errorMessage: null);
    _log('connectToCluster: "${entry.name}" (${entry.role})');
    try {
      if (entry.hasLegacySeed) {
        // Its key was not moved into the store because the store holds a
        // different identity; the server knows this membership by that key.
        state = state.copyWith(
          errorMessage: '"${entry.name}" was registered with a different device '
              'identity than the one stored for this user. Forget it on this '
              'device and join again with an invitation code.',
          isLoading: false,
        );
        return false;
      }
      if (!await _ensureServerConnection(
          host: entry.serverHost.isEmpty ? null : entry.serverHost,
          port: entry.serverPort == 0 ? null : entry.serverPort,
          useTls: entry.useTls)) {
        return false;
      }

      await _activateIdentity();
      if (!await _authJoinAndLoad(entry.name)) return false;

      // Pick up the group key if an owner provisioned it since last time.
      final groupKey = entry.groupKeyB64 ?? await fetchGroupKey();
      if (entry.groupKeyB64 != null) await _ensureOwnEnvelope(entry.groupKeyB64!);
      await _saveActiveCluster(entry.copyWith(
        groupKeyB64: groupKey,
        userId: state.userId ?? entry.userId,
        lastUsed: DateTime.now(),
      ));
      addActivity(ActivityLevel.success, 'Connected to "${entry.name}"');
      return true;
    } catch (e) {
      state = state.copyWith(errorMessage: 'Connect failed: $e', isLoading: false);
      addActivity(ActivityLevel.error, 'Connect failed: $e');
      return false;
    }
  }

  /// Forget a Cluster on this device (drops its key; does not touch the server).
  Future<void> forgetCluster(String localId) async {
    final clusters = await _keyring.remove(localId);
    final wasActive = state.activeClusterId == localId;
    state = state.copyWith(clusters: clusters, clearActiveCluster: wasActive);
  }

  /// Permanently delete the active account. Irreversible. The server removes
  /// the account's groups and devices, its memberships and account data, and
  /// revokes its key (ln_account_delete); the application root stays. After a
  /// confirmed deletion this device removes its own copy: the Cluster keyring
  /// entry (group key), the stored session, the group loopback certificates,
  /// and the revoked device identity in the user identity store (a new one is
  /// created in its place), then signs out. Returns the server answer. With
  /// status "pending" Tier 1 has not committed the deletion yet, and nothing
  /// local is removed. Throws SdkException when the server refuses.
  Future<Map<String, dynamic>> deleteAccount() async {
    final result = await _sdk.deleteAccount();
    if (result['status'] != 'deleted') {
      addActivity(ActivityLevel.info, 'Account deletion is pending');
      return result;
    }
    final localId = state.activeClusterId;
    await stopMeshPort();
    try {
      final support = await AppPaths.supportDir();
      final certs = Directory('${support.path}/certs/group-loopback');
      if (await certs.exists()) await certs.delete(recursive: true);
    } catch (e) {
      _log('deleteAccount: could not remove the local certificates: $e');
    }
    if (localId != null) await forgetCluster(localId);
    await signOut();
    // The server revoked this key: every membership of the identity is gone,
    // so a fresh identity replaces it in the store.
    try {
      await _sdk.removeUserIdentity();
      addActivity(ActivityLevel.info, 'Removed the revoked device identity');
    } on SdkException catch (e) {
      _log('deleteAccount: could not remove the stored identity: ${e.error.name}');
      addActivity(ActivityLevel.warning,
          'The revoked device identity is still stored: '
          '${explainIdentityStoreFailure(e.error, status: state.deviceIdentity.status)}');
    }
    await prepareDeviceIdentity();
    addActivity(ActivityLevel.warning, 'Account deleted');
    return result;
  }

  /// Rename a Cluster locally (display label only).
  Future<void> renameCluster(String localId, String name) async {
    for (final c in state.clusters) {
      if (c.localId == localId) {
        final clusters = await _keyring.upsert(c.copyWith(name: name));
        state = state.copyWith(clusters: clusters);
        return;
      }
    }
  }

  // ---- device linking + group-key provisioning ------------------------------

  /// Mint an invitation code for another device. Owner-only; needs the mesh.
  Future<Map<String, dynamic>> createDeviceInvite(
          {int ttlSec = 600, String? targetNodeId}) =>
      _sdk.createInvite(targetNodeId: targetNodeId, ttlSec: ttlSec);

  /// Join another network: accept an invite code with this account's
  /// identity. Nothing this account owns moves; it becomes a member of the
  /// invite's group. Throws SdkException with the server's reason.
  Future<Map<String, dynamic>> acceptInvite(String code) async {
    final result = await _sdk.acceptInvite(code.trim());
    addActivity(ActivityLevel.info, 'Joined network ${result['node_id'] ?? ''}');
    return result;
  }

  /// The groups this identity belongs to (home groups and invite memberships).
  Future<List<Map<String, dynamic>>> listMemberships() => _sdk.listMemberships();

  /// Leave a group entered through an invite.
  Future<void> leaveMembership(String groupNodeId) async {
    await _sdk.leaveMembership(groupNodeId);
    addActivity(ActivityLevel.info, 'Left network $groupNodeId');
  }

  /// Move a device or a subgroup under another group.
  Future<void> moveNode(String nodeId, String newParentId) async {
    await _sdk.moveNode(nodeId, newParentId);
    addActivity(ActivityLevel.info, 'Moved $nodeId to $newParentId');
  }

  /// Devices in the active Cluster that have no group-key envelope yet.
  Future<List<Map<String, dynamic>>> pendingDevices() async {
    final resp = await callPrivateApi('GET', '/api/account/keys/pending');
    final list = (resp['pending'] as List?) ?? const [];
    return list.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  /// Seal the group key to [targetPubkey]; the server stores it opaquely.
  Future<void> _provisionGroupKeyTo(String targetPubkey, String groupKey,
      {String keyId = 'gk1'}) async {
    if (targetPubkey.isEmpty) throw StateError('no target pubkey');
    final env = _sdk.wrapGroupKey(targetPubkey, groupKey);
    await callPrivateApi('POST', '/api/account/keys/envelope', body: {
      'target_pubkey': targetPubkey,
      'key_id': keyId,
      'ephemeral_pubkey': env['ephemeral_pubkey'],
      'wrapped_key': env['wrapped_key'],
    });
  }

  /// Re-seal the group key to this device when the server holds no envelope
  /// for it. The upload at registration fails while the mesh is down, so this
  /// retries it on every connect.
  Future<void> _ensureOwnEnvelope(String groupKey) async {
    try {
      final env = await callPrivateApi('GET', '/api/account/keys/envelope');
      if (!env.containsKey('error')) return;
      await _provisionGroupKeyTo(_sdk.identityPubkey ?? '', groupKey);
      _log('_ensureOwnEnvelope: re-provisioned this device');
    } catch (e) {
      _log('_ensureOwnEnvelope: deferred -> $e');
    }
  }

  /// Provision the group key to every device still waiting for it. Returns the
  /// number provisioned (0 if this device has no group key to share).
  Future<int> provisionPendingDevices() async {
    final groupKey = state.activeCluster?.groupKeyB64;
    if (groupKey == null || groupKey.isEmpty) {
      _log('provisionPendingDevices: no group key on this device');
      return 0;
    }
    var provisioned = 0;
    for (final device in await pendingDevices()) {
      final pubkey = device['pubkey']?.toString() ?? '';
      if (pubkey.isEmpty) continue;
      try {
        await _provisionGroupKeyTo(pubkey, groupKey);
        provisioned++;
        addActivity(ActivityLevel.success,
            'Shared the account key with ${device['node_id'] ?? 'a device'}');
      } catch (e) {
        _log('provisionPendingDevices: failed for $pubkey -> $e');
      }
    }
    return provisioned;
  }

  /// Create a fresh account key when no device holds one, and seal it to this
  /// device. Only safe when the server holds no envelope for any device in the
  /// Cluster: the caller checks that, because replacing a key another device
  /// still holds would split the Cluster between two keys.
  Future<void> createAccountKey() async {
    final active = state.activeCluster;
    if (active == null) throw StateError('no active Cluster');
    if (active.groupKeyB64?.isNotEmpty == true) {
      throw StateError('this device already holds the account key');
    }
    final groupKey = _sdk.generateGroupKey();
    await _provisionGroupKeyTo(_sdk.identityPubkey ?? '', groupKey);
    await _saveActiveCluster(active.copyWith(groupKeyB64: groupKey));
    addActivity(ActivityLevel.success, 'Created a new account key');
  }

  /// Fetch + unwrap this device's group-key envelope, persisting it to the
  /// keyring on success. Returns null if no owner has provisioned us yet.
  Future<String?> fetchGroupKey() async {
    try {
      final env = await callPrivateApi('GET', '/api/account/keys/envelope');
      if (env.containsKey('error')) return null;
      final key = _sdk.unwrapGroupKey(env);
      if (key == null) return null;
      final active = state.activeCluster;
      if (active != null && active.groupKeyB64 != key) {
        await _saveActiveCluster(active.copyWith(groupKeyB64: key));
      }
      return key;
    } catch (e) {
      _log('fetchGroupKey: unavailable -> $e');
      return null;
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
        _deviceNamed = false;
        if (await _joinNetwork()) await _recordTier1Epoch();
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
      final userId = state.storedPasskeyUserId ?? '';
      if (userId.isEmpty) {
        state = state.copyWith(
            isLoading: false, errorMessage: 'No passkey account stored');
        return false;
      }
      // The assertion must carry a server-issued, single-use, expiring
      // challenge bound to this account.
      final challenge = await _sdk.getPasskeyChallenge(userId);
      final assertion =
          await _passkey.signAssertion('lemonade-nexus.local', challenge);
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
        _deviceNamed = false;
        if (await _joinNetwork()) await _recordTier1Epoch();
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
  /// This is what populates the SDK's mesh config (assigns the tunnel IP +
  /// node id); without it [connectTunnel] has no config to bring up. Mirrors the
  /// macOS `joinAsEndpoint()`. Best-effort: a join failure leaves the user
  /// authenticated but without a tunnel.
  ///
  /// Returns true once the server has issued a node id (the join is usable).
  Future<bool> _joinNetwork() async {
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
      return join.success && join.nodeId != null;
    } catch (e) {
      // ln_join_network answers LnError.auth for every failure, unreachable
      // servers included, so this is never treated as a refusal: the account
      // stays and the recovery paths retry.
      _log('joinNetwork: FAILED -> $e');
      addActivity(ActivityLevel.warning, 'Network join failed: $e');
      return false;
    }
  }

  /// Names this device's endpoint after the machine while the server still
  /// shows its generated default ("endpoint-" and the node id prefix). A name
  /// set earlier, here or in another client, stays. The node is read and
  /// updated over the private API, so this runs once the mesh is up; it is
  /// retried by the periodic refresh until it has checked once.
  Future<void> _applyDefaultDeviceName() async {
    if (_deviceNamed) return;
    try {
      final nodeId = await _sdk.getNodeId();
      if (nodeId == null || nodeId.isEmpty) return;
      final node = await callPrivateApi('GET', '/api/tree/node/$nodeId');
      if (node.containsKey('error')) {
        _log('applyDefaultDeviceName: node read failed -> ${node['error']}');
        return;
      }
      final name = deviceNameToApply(
        currentHostname:
            (node['hostname'] ?? node['data']?['hostname'])?.toString(),
        nodeId: nodeId,
        machineName: machineDeviceName(Platform.localHostname),
      );
      if (name != null) {
        final resp = await callPrivateApi(
            'POST', '/api/tree/node/update/$nodeId',
            body: {'hostname': name});
        if (resp['success'] != true) {
          throw Exception(resp['error'] ?? 'the server refused the name');
        }
        addActivity(ActivityLevel.info, 'Named this device "$name"');
      }
      _deviceNamed = true;
    } catch (e) {
      _log('applyDefaultDeviceName: $e');
    }
  }

  /// Establishes the Ed25519 mesh identity for a passkey session.
  ///
  /// Passkey auth (Secure Enclave P-256) is auth-only; mesh node creation needs
  /// a separate Ed25519 identity. Bind this user's stored device identity,
  /// register it via an Ed25519 challenge so the server grants node-creation
  /// permission, then restore the passkey session token (Ed25519 auth returns
  /// its own).
  Future<void> _establishPasskeyMeshIdentity(String? passkeyToken) async {
    try {
      await _activateIdentity();
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
      addActivity(ActivityLevel.error,
          'This session has no device identity; mesh operations will fail: $e');
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

  /// Disconnect from the active Cluster and return to the login page. The
  /// keyring is preserved — the Cluster stays listed for a later Connect.
  Future<void> signOut() async {
    _deviceNamed = false;
    await _secureStore.clear();
    await disconnectFromServer(clearIdentity: true);
    state = state.copyWith(
      clearActiveCluster: true,
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
      activityLog: [],
    );
    addActivity(ActivityLevel.info, 'Signed out');
  }

  /// Refresh all data
  Future<void> refreshAllData() async {
    _log('refreshAllData: meshEnabled=${state.isMeshEnabled} '
        'connStatus=${state.connectionStatus.name} authed=${state.isAuthenticated}');
    // Mesh status first: the private-API refreshes below are gated on it, and
    // reading isMeshEnabled before it updates skipped them for the whole session.
    await refreshMeshStatus();
    await Future.wait([
      refreshHealth(),
      refreshStats(),
      refreshServers(),
      // /api/relay/list is a private-API endpoint reached through the mesh;
      // it 404s on the plain public connection.
      if (state.isMeshEnabled) refreshRelays(),
    ]);
    _log('refreshAllData done: isServerHealthy=${state.isServerHealthy} '
        'servers=${state.servers.length} stats=${state.stats != null}');
    // A manual dashboard refresh against a dead server self-heals here; the
    // periodic monitor covers the untouched case. _recoverConnection guards
    // its own re-entrancy.
    if (state.isAuthenticated && !state.isServerHealthy) {
      await _recoverConnection();
    }
  }

  static bool _sameJson(Object? a, Object? b) => jsonEncode(a) == jsonEncode(b);

  /// Refresh health status
  Future<void> refreshHealth() async {
    try {
      final h = await _sdk.health();
      // Every replacement of `state` rebuilds its watchers; skip unchanged polls.
      if (!_sameJson(state.healthStatus?.toJson(), h.toJson())) {
        state = state.copyWith(healthStatus: h);
      }
      // Runs every 5s — only worth a line when the server is NOT healthy.
      if (!state.isServerHealthy) {
        _log('refreshHealth: unhealthy (status=${h.status} service=${h.service})');
      }
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
    var needsRejoin = false;
    try {
      final meshStatus = await _sdk.getMeshStatus();
      needsRejoin = meshStatus.needsRejoin;
      final meshPeers = await _sdk.getMeshPeers();
      final unchanged =
          _sameJson(state.peerState.meshStatus?.toJson(), meshStatus.toJson()) &&
              _sameJson(state.peerState.meshPeers.map((p) => p.toJson()).toList(),
                  meshPeers.map((p) => p.toJson()).toList()) &&
              state.peerState.isMeshEnabled == meshStatus.isUp;
      if (!unchanged) {
        state = state.copyWith(
          peerState: state.peerState.copyWith(
            meshStatus: meshStatus,
            meshPeers: meshPeers,
            isMeshEnabled: meshStatus.isUp,
          ),
        );
      }
      if (!meshStatus.isUp) {
        _log('refreshMeshStatus: down (peers=${meshStatus.peerCount} '
            'online=${meshStatus.onlineCount})');
      }
    } catch (e) {
      state = state.copyWith(
        peerState: const PeerState(
          meshStatus: null,
          meshPeers: [],
        ),
      );
      _log('refreshMeshStatus: FAILED -> $e');
    }
    if (needsRejoin) await _rejoinAfterServerLeft();
  }

  /// The SDK moved the session, or could not. A silent move changed the
  /// server-issued token and may have advanced the Tier 1 epoch, so both are
  /// recorded; the user sees one activity line. A move that is not silent
  /// left no session, so the device joins again.
  Future<void> _onSessionMoved(SessionMoveEvent event) async {
    if (event.silent) {
      _log('sessionMoved: ${event.fromHost} -> ${event.toHost} '
          '(epoch ${event.epoch})');
      addActivity(ActivityLevel.info,
          'Moved to Tier 1 server ${event.toHost} (epoch ${event.epoch})');
      await _storeSessionToken();
      await _recordTier1Epoch();
      await refreshMeshStatus();
      return;
    }
    _log('sessionMoved: not silent (${event.error}); joining again');
    addActivity(ActivityLevel.warning,
        'The session server left Tier 1 (${event.error}); joining again');
    await _rejoinAfterServerLeft();
  }

  /// Joins again when the SDK reports that the session's Tier 1 server left
  /// the membership and it could not move the session by itself. The SDK
  /// has already dropped the token, so [_joinNetwork] authenticates with the
  /// Ed25519 identity through a current server. A password-only session has
  /// no identity to do that with and is left to the health monitor. At most
  /// one attempt per [_rejoinCooldown].
  Future<void> _rejoinAfterServerLeft() async {
    if (_isRecovering || !state.isAuthenticated) return;
    if (_sdk.identityPubkey == null || state.sessionToken == null) return;
    final last = _lastRejoinAttempt;
    if (last != null && DateTime.now().difference(last) < _rejoinCooldown) {
      return;
    }
    _lastRejoinAttempt = DateTime.now();
    _log('rejoinAfterServerLeft: the session server left Tier 1; joining again');
    if (!await _joinNetwork()) {
      _log('rejoinAfterServerLeft: join failed; next attempt after '
          '${_rejoinCooldown.inSeconds}s');
      return;
    }
    await _storeSessionToken();
    await _recordTier1Epoch();
    _log('rejoinAfterServerLeft: joined through a current Tier 1 server');
  }

  /// Persists the SDK's current server-issued token so a later restart does
  /// not replay one that no longer names a Tier 1 server.
  Future<void> _storeSessionToken() async {
    final token = await _sdk.getSessionToken();
    if (token == null) return;
    state = state.copyWith(
      authState: state.authState.copyWith(sessionToken: token),
    );
    await _secureStore.saveSession(StoredSession(
        token: token, username: state.username ?? '', userId: state.userId));
  }

  /// Generic authenticated call to a private-mesh API route, for views that
  /// exercise account-data endpoints (e.g. the Account dashboard). Throws on
  /// failure so the caller can surface the error inline.
  Future<Map<String, dynamic>> callPrivateApi(String method, String path,
      {Map<String, dynamic>? body}) {
    return _sdk.privateApiCall(method, path, body: body);
  }

  /// [callPrivateApi] for routes that answer with a JSON array.
  Future<List<Map<String, dynamic>>> callPrivateApiList(String method, String path,
      {Map<String, dynamic>? body}) {
    return _sdk.privateApiCallList(method, path, body: body);
  }

  /// The active Cluster's group node id — this device's endpoint's parent.
  Future<String?> clusterGroupId() async {
    final nodeId = state.userId;
    if (nodeId == null || nodeId.isEmpty) return null;
    try {
      final me = await callPrivateApi('GET', '/api/tree/node/$nodeId');
      final parent = me['parent_id']?.toString();
      return (parent == null || parent.isEmpty) ? null : parent;
    } catch (e) {
      _log('clusterGroupId: $e');
      return null;
    }
  }

  /// Devices (Endpoint nodes) in the active Cluster, each flagged with whether
  /// it still needs the account group key.
  Future<List<ClusterDevice>> listClusterDevices() async {
    final groupId = await clusterGroupId();
    if (groupId == null) return [];
    final children = await callPrivateApiList('GET', '/api/tree/children/$groupId');

    Set<String> waiting = {};
    try {
      waiting = (await pendingDevices())
          .map((d) => d['node_id']?.toString() ?? '')
          .where((id) => id.isNotEmpty)
          .toSet();
    } catch (e) {
      _log('listClusterDevices: pending lookup failed -> $e');
    }

    // Group admins, by key. A non-admin caller only sees its own entry, which
    // still answers whether this device is an admin.
    final adminKeys = <String>{};
    try {
      for (final a in await nodeAssignments(groupId)) {
        final perms = (a['permissions'] as List?)?.map((p) => p.toString()) ?? const [];
        if (perms.contains('admin')) {
          adminKeys.add(canonicalPrincipal(a['management_pubkey']?.toString() ?? ''));
        }
      }
    } catch (e) {
      _log('listClusterDevices: group assignments lookup failed -> $e');
    }

    final devices = <ClusterDevice>[];
    for (final node in children) {
      if ((node['node_type'] ?? node['type'])?.toString().toLowerCase() !=
          'endpoint') {
        continue;
      }
      final id = node['id']?.toString() ?? '';
      if (id.isEmpty) continue;
      final mgmt = node['mgmt_pubkey']?.toString() ?? '';
      devices.add(ClusterDevice(
        nodeId: id,
        hostname: (node['hostname'] ?? node['data']?['hostname'])?.toString() ?? id,
        tunnelIp: (node['tunnel_ip'] ?? node['data']?['tunnel_ip'])?.toString(),
        needsKey: waiting.contains(id),
        isThisDevice: id == state.userId,
        mgmtPubkey: mgmt,
        isAdmin: mgmt.isNotEmpty && adminKeys.contains(canonicalPrincipal(mgmt)),
      ));
    }
    return devices;
  }

  /// A node's assignments: every entry when this device can edit the node,
  /// otherwise only this device's own entry.
  Future<List<Map<String, dynamic>>> nodeAssignments(String nodeId) async {
    final node = await callPrivateApi('GET', '/api/tree/node/$nodeId');
    if (node.containsKey('error')) throw Exception(node['error']);
    return ((node['assignments'] as List?) ?? const [])
        .map((a) => Map<String, dynamic>.from(a as Map))
        .toList();
  }

  /// Set exactly [permissions] for [pubkey] on [nodeId]; an empty list removes
  /// the entry. The server allows this only for an admin of the node or its
  /// group, and only for devices that joined that group. Throws with the
  /// server's reason when refused.
  Future<void> setMemberPermissions(
      String nodeId, String pubkey, List<String> permissions) async {
    final resp = await callPrivateApi('POST', '/api/tree/node/assignments/$nodeId',
        body: {'pubkey': pubkey, 'permissions': permissions});
    if (resp['success'] != true) {
      throw Exception(resp['error'] ?? 'the server refused the change');
    }
    addActivity(ActivityLevel.info, 'Updated access on $nodeId');
  }

  /// Remove a device from the active Cluster (owner-only; revokes its key).
  Future<bool> removeClusterDevice(String nodeId) async {
    try {
      await callPrivateApi('POST', '/api/tree/node/delete/$nodeId');
      addActivity(ActivityLevel.info, 'Removed device $nodeId');
      return true;
    } catch (e) {
      _log('removeClusterDevice: $e');
      addActivity(ActivityLevel.error, 'Could not remove device: $e');
      return false;
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
      await startMeshPort();
    } catch (e) {
      state = state.copyWith(errorMessage: 'Failed to enable mesh: $e');
      addActivity(ActivityLevel.error, 'Failed to enable mesh: $e');
      _log('enableMesh: FAILED -> $e');
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  // =========================================================================
  // Mesh port
  // =========================================================================

  /// Starts the loopback mesh port through the SDK. The group loopback
  /// certificate lives in the app support directory. When lemond on this
  /// machine already owns the port, the app shows that and does not retry.
  Future<void> startMeshPort() async {
    try {
      final support = await AppPaths.supportDir();
      await _sdk.startMeshPort(certDir: '${support.path}/certs/group-loopback');
      addActivity(ActivityLevel.info, 'Mesh port started');
    } on SdkException catch (e) {
      final message = e.error == LnError.portInUse
          ? 'Port 13306 is in use by another process, for example lemond'
          : 'Cannot start the mesh port: ${e.error.name}';
      state = state.copyWith(meshPortStatus: MeshPortStatus(error: message));
      addActivity(ActivityLevel.warning, message);
      return;
    } catch (e) {
      _log('startMeshPort: FAILED -> $e');
      return;
    }
    await refreshMeshPortStatus();
  }

  /// Stops the mesh port. Safe to call when it is not running.
  Future<void> stopMeshPort() async {
    try {
      await _sdk.stopMeshPort();
    } catch (e) {
      _log('stopMeshPort: FAILED -> $e');
    }
    state = state.copyWith(meshPortStatus: MeshPortStatus.stopped);
  }

  /// Reads the mesh port status. Keeps a start error visible while the port
  /// is not running.
  Future<void> refreshMeshPortStatus() async {
    if (!state.isConnected) return;
    if (!state.meshPortStatus.running && state.meshPortStatus.error.isNotEmpty) return;
    try {
      final status = await _sdk.getMeshPortStatus();
      state = state.copyWith(meshPortStatus: status);
    } catch (e) {
      _log('refreshMeshPortStatus: FAILED -> $e');
    }
  }

  /// Sets the mesh port selection: "auto", a node ID, or null to clear it.
  Future<void> setMeshPortSelection(String? target) async {
    try {
      await _sdk.setMeshPortSelection(target);
    } on SdkException catch (e) {
      state = state.copyWith(errorMessage: 'Cannot select that device: ${e.error.name}');
    } catch (e) {
      _log('setMeshPortSelection: FAILED -> $e');
    }
    await refreshMeshPortStatus();
  }

  /// Disable P2P mesh networking.
  Future<void> disableMesh() async {
    state = state.copyWith(isLoading: true);
    _log('disableMesh: start');
    try {
      await stopMeshPort();
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
  /// The server we last used, or null if nothing is remembered.
  ({String host, int port, bool useTls})? rememberedServer() {
    for (final c in state.clusters) {
      if (c.serverHost.isNotEmpty && c.serverPort != 0) {
        return (host: c.serverHost, port: c.serverPort, useTls: c.useTls);
      }
    }
    final s = state.settings;
    if (s.serverHost.isEmpty || s.serverHost == 'localhost') return null;
    return (host: s.serverHost, port: s.serverPort, useTls: s.useTls);
  }

  /// Sweep DNS for servers (slow — walks every region). Pass [connectToBest]
  /// false to refresh the list without switching the current connection.
  Future<void> discoverNearestServer({bool connectToBest = true}) async {
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
        if (!connectToBest) {
          _log('discoverNearestServer: list refreshed only (no switch)');
          return;
        }
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

  /// Starts the periodic refresh: mesh status (local) and the health probe that
  /// drives auto-reconnect.
  ///
  /// Runs for the notifier's lifetime and no-ops until the user is authed. When
  /// the connected server stops answering `/api/health`, it kicks off
  /// [_recoverConnection]. Cancelled in [dispose].
  void _startHealthMonitor() {
    _healthTimer?.cancel();
    _healthTimer = Timer.periodic(_healthInterval, (_) async {
      if (!state.isAuthenticated || _isRecovering) return;
      // The one periodic refresh for the app; views no longer run their own.
      await refreshMeshStatus();
      await refreshMeshPortStatus();
      await refreshHealth();
      await _recordTier1Epoch();
      if (!_deviceNamed && state.isMeshEnabled) await _applyDefaultDeviceName();
      if (state.isAuthenticated && !state.isServerHealthy) {
        await _recoverConnection();
      }
    });
  }

  /// Manually trigger a reconnect (bypasses the auto-recovery cooldown/backoff).
  Future<void> reconnect() => _recoverConnection(force: true);

  /// Recovers the control-plane connection after the current server goes down.
  ///
  /// Session tokens are per-server JWTs, so failover to a different server can't
  /// reuse the old token — instead we drop the dead client (and its tunnel),
  /// re-discover a live server via DNS, re-bind the preserved Ed25519 identity,
  /// and re-join to obtain a fresh server-issued token (which also rebuilds the
  /// tunnel). Guarded against re-entrancy, rate-limited, and bounded: after
  /// [_maxRecoveryFailures] it stops auto-retrying until a manual [reconnect].
  Future<void> _recoverConnection({bool force = false}) async {
    if (_isRecovering || !state.isAuthenticated) return;
    if (!force) {
      final last = _lastRecoveryAttempt;
      if (last != null && DateTime.now().difference(last) < _recoveryCooldown) {
        return;
      }
      if (_recoveryFailures >= _maxRecoveryFailures) return;
    }
    // A cross-server re-join self-authenticates with the Ed25519 identity; a
    // password-only session has none, so it cannot re-join silently. A lost
    // connection is still not a refusal: the account and the client stay, the
    // health dot shows the outage, and the probe clears it when the server
    // answers again. Only the server refusing the credentials signs out.
    if (_sdk.identityPubkey == null) {
      _lastRecoveryAttempt = DateTime.now();
      _recoveryFailures++;
      _log('recoverConnection: no identity; waiting for the server '
          '(failures=$_recoveryFailures)');
      if (_recoveryFailures == 1) {
        addActivity(ActivityLevel.warning,
            'Connection lost — waiting for the server; sign in again to reconnect now');
      }
      return;
    }

    _isRecovering = true;
    _lastRecoveryAttempt = DateTime.now();
    if (force) _recoveryFailures = 0;
    _log('recoverConnection: start (failures=$_recoveryFailures force=$force)');
    addActivity(ActivityLevel.warning, 'Connection lost — reconnecting…');
    state = state.copyWith(connectionStatus: ConnectionStatus.connecting);
    try {
      // Drop the dead client + tunnel, but keep the identity for the re-join.
      await stopMeshPort();
      _sdk.disconnect();
      // DNS/SEIP discovery health-probes as it goes, so dead servers are skipped
      // and connectToServer brings up a fresh client on a reachable one.
      await discoverNearestServer();
      if (!state.isConnected) {
        throw StateError('no reachable server found');
      }
      await _sdk.setIdentity();
      if (!await _joinNetwork()) {
        throw StateError('re-join failed');
      }
      // Persist the new server-issued token so a later restart doesn't replay
      // the dead one.
      await _storeSessionToken();
      await _recordTier1Epoch();
      await refreshAllData();
      state = state.copyWith(connectionStatus: ConnectionStatus.connected);
      _recoveryFailures = 0;
      addActivity(ActivityLevel.success, 'Reconnected');
      _log('recoverConnection: success');
    } catch (e) {
      if (isAuthenticationRefusal(e)) {
        // HTTP 401/403: the network refused this device's credentials, so
        // retrying cannot help. Every other failure keeps the account.
        _log('recoverConnection: the server refused the session -> $e');
        addActivity(ActivityLevel.error,
            'The server refused this session — please sign in again');
        await signOut();
        return;
      }
      _recoveryFailures++;
      state = state.copyWith(connectionStatus: ConnectionStatus.error);
      _log('recoverConnection: FAILED ($_recoveryFailures) -> $e');
      if (_recoveryFailures >= _maxRecoveryFailures) {
        addActivity(ActivityLevel.error,
            'Could not reconnect after $_recoveryFailures attempts');
      }
    } finally {
      _isRecovering = false;
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
    _healthTimer?.cancel();
    _sessionMoves?.cancel();
    try {
      _sdk.dispose();
    } catch (e) {
      // Ignore dispose errors
    }
    super.dispose();
  }
}
