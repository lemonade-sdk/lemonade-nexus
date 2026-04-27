/// @title Test Mocks
/// @description Mock classes for testing Lemonade Nexus.
///
/// Uses mockito for creating mock implementations of:
/// - LemonadeNexusSdk
/// - LemonadeNexusFfi
/// - AppNotifier
/// - Services

import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:riverpod/riverpod.dart';

// Import the actual classes to mock
import 'package:lemonade_nexus/src/sdk/sdk.dart';
import 'package:lemonade_nexus/src/sdk/ffi_bindings.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/state/providers.dart';

// Generate mocks using build_runner
// Run: flutter pub run build_runner build --delete-conflicting-outputs
@GenerateMocks([
  LemonadeNexusSdk,
  LemonadeNexusFfi,
  AppNotifier,
  AuthService,
  TunnelService,
  DiscoveryService,
  TreeService,
])
void _generateMocks() {}

// The generated mocks will be in mocks.mocks.dart

/// Mock implementation of LemonadeNexusSdk for testing.
class MockSdk extends Mock implements LemonadeNexusSdk {
  MockSdk() {
    // Set up default stub behaviors
    when(this.dispose()).thenReturn(null);
    when(this.identityPubkey).thenReturn(null);
  }

  /// Pre-configured response for health checks.
  void mockHealth({bool healthy = true}) {
    when(this.health()).thenAnswer((_) async {
      if (healthy) {
        return HealthResponse(status: 'ok', version: '1.0.0', uptime: 1000);
      } else {
        throw SdkException(LnError.connect, message: 'Server unavailable');
      }
    });
  }

  /// Pre-configured response for authentication.
  void mockAuth({
    bool success = true,
    String? userId,
    String? sessionToken,
    String? error,
  }) {
    when(this.authPassword(any, any)).thenAnswer((_) async {
      return AuthResponse(
        authenticated: success,
        userId: userId,
        sessionToken: sessionToken,
        error: error,
      );
    });
  }

  /// Pre-configured response for tunnel status.
  void mockTunnelStatus({
    bool isUp = false,
    String? tunnelIp,
    String? serverEndpoint,
  }) {
    when(this.getTunnelStatus()).thenAnswer((_) async {
      return TunnelStatus(
        isUp: isUp,
        tunnelIp: tunnelIp,
        serverEndpoint: serverEndpoint,
      );
    });
  }

  /// Pre-configured response for mesh status.
  void mockMeshStatus({
    bool isUp = false,
    int peerCount = 0,
    int onlineCount = 0,
  }) {
    when(this.getMeshStatus()).thenAnswer((_) async {
      return MeshStatus(
        isUp: isUp,
        peerCount: peerCount,
        onlineCount: onlineCount,
        totalRxBytes: 0,
        totalTxBytes: 0,
        peers: [],
      );
    });
  }

  /// Pre-configured response for server list.
  void mockServers({List<ServerInfo>? servers}) {
    when(this.listServers()).thenAnswer((_) async {
      return servers ?? [];
    });
  }

  /// Pre-configured response for connect.
  void mockConnect({bool success = true}) {
    if (success) {
      when(this.connect(any, any)).thenAnswer((_) async => null);
    } else {
      when(this.connect(any, any)).thenThrow(
        SdkException(LnError.connect, message: 'Connection failed'),
      );
    }
  }
}

/// Mock implementation of AppNotifier for testing.
class MockAppNotifier extends Mock implements AppNotifier {
  AppState _state = AppState.initial;

  @override
  AppState get state => _state;

  @override
  set state(AppState newState) {
    _state = newState;
  }

  /// Update state and notify listeners.
  void updateState(AppState newState) {
    _state = newState;
  }

  /// Set authentication state.
  void setAuthenticated(bool isAuthenticated) {
    _state = _state.copyWith(
      authState: _state.authState.copyWith(
        isAuthenticated: isAuthenticated,
      ),
    );
  }

  /// Set connection status.
  void setConnectionStatus(ConnectionStatus status) {
    _state = _state.copyWith(connectionStatus: status);
  }

  /// Set tunnel status.
  void setTunnelStatus(TunnelStatus? status) {
    _state = _state.copyWith(tunnelStatus: status);
  }

  /// Add activity entry.
  void addActivityEntry(ActivityEntry entry) {
    final updatedLog = [entry, ..._state.activityLog];
    if (updatedLog.length > 50) {
      updatedLog.removeRange(50, updatedLog.length);
    }
    _state = _state.copyWith(activityLog: updatedLog);
  }
}

/// Mock implementation of LemonadeNexusFfi for low-level testing.
class MockFfi extends Mock implements LemonadeNexusFfi {
  MockFfi() {
    // Default: library loads successfully
    when(this.toString()).thenReturn('MockFfi');
  }
}

/// Creates a mock ProviderContainer for testing.
ProviderContainer createMockContainer({
  Map<ProviderBase, dynamic> providers = const {},
}) {
  final overrides = providers.entries
      .map((e) => e.key.overrideWithValue(e.value))
      .toList();

  final container = ProviderContainer(overrides: overrides);
  addTearDown(container.dispose);
  return container;
}

/// Fake implementation of LemonadeNexusSdk for integration testing.
class FakeSdk implements LemonadeNexusSdk {
  bool _isConnected = false;
  bool _isAuthenticated = false;
  bool _isTunnelUp = false;
  bool _isMeshEnabled = false;
  String? _host;
  int? _port;
  String? _username;
  String? _sessionToken;

  final List<TreeNode> _treeNodes = [];
  final List<ServerInfo> _servers = [];
  final List<MeshPeer> _meshPeers = [];

  @override
  Future<void> connect(String host, int port) async {
    _host = host;
    _port = port;
    _isConnected = true;
  }

  @override
  Future<void> connectTls(String host, int port) async {
    _host = host;
    _port = port;
    _isConnected = true;
  }

  @override
  void dispose() {
    _isConnected = false;
    _isAuthenticated = false;
  }

  @override
  Future<AuthResponse> authPassword(String username, String password) async {
    if (username.isEmpty || password.isEmpty) {
      return AuthResponse(
        authenticated: false,
        error: 'Invalid credentials',
      );
    }
    _username = username;
    _isAuthenticated = true;
    _sessionToken = 'test_session_${DateTime.now().millisecondsSinceEpoch}';
    return AuthResponse(
      authenticated: true,
      userId: 'user_test_123',
      sessionToken: _sessionToken,
    );
  }

  @override
  Future<HealthResponse> health() async {
    if (!_isConnected) {
      throw SdkException(LnError.connect, message: 'Not connected');
    }
    return HealthResponse(status: 'ok', version: '1.0.0', uptime: 1000);
  }

  @override
  Future<TunnelStatus> getTunnelStatus() async {
    return TunnelStatus(
      isUp: _isTunnelUp,
      tunnelIp: _isTunnelUp ? '10.0.0.1' : null,
      serverEndpoint: _isTunnelUp ? '$_host:$_port' : null,
    );
  }

  @override
  Future<MeshStatus> getMeshStatus() async {
    return MeshStatus(
      isUp: _isMeshEnabled,
      peerCount: _meshPeers.length,
      onlineCount: _meshPeers.where((p) => p.isOnline).length,
      totalRxBytes: 1024,
      totalTxBytes: 2048,
      peers: _meshPeers,
    );
  }

  @override
  Future<List<MeshPeer>> getMeshPeers() async {
    return _meshPeers;
  }

  @override
  Future<List<ServerInfo>> listServers() async {
    return _servers;
  }

  @override
  String? get identityPubkey => _isAuthenticated ? 'test_pubkey_base64' : null;

  @override
  Future<void> setSessionToken(String token) async {
    _sessionToken = token;
  }

  @override
  Future<String?> getSessionToken() async {
    return _sessionToken;
  }

  /// Helper method to add a fake mesh peer.
  void addMeshPeer({
    required String nodeId,
    String? hostname,
    bool isOnline = true,
  }) {
    _meshPeers.add(MeshPeer(
      nodeId: nodeId,
      hostname: hostname,
      wgPubkey: 'peer_pubkey_${nodeId.substring(0, 8)}',
      tunnelIp: '10.0.0.${_meshPeers.length + 2}',
      isOnline: isOnline,
      keepalive: 25,
    ));
  }

  /// Helper method to add a fake server.
  void addServer({
    required String id,
    required String host,
    int port = 9100,
    String region = 'test-region',
    bool available = true,
  }) {
    _servers.add(ServerInfo(
      id: id,
      host: host,
      port: port,
      region: region,
      available: available,
    ));
  }

  /// Set tunnel state for testing.
  void setTunnelState(bool isUp) {
    _isTunnelUp = isUp;
  }

  /// Set mesh state for testing.
  void setMeshState(bool enabled) {
    _isMeshEnabled = enabled;
  }
}
