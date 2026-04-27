/// @title State Management Tests
/// @description Tests for Riverpod state management (AppState and AppNotifier).
///
/// Coverage Target: 85%
/// Priority: High

import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../fixtures/fixtures.dart';
import '../helpers/mocks.dart';

void main() {
  group('AuthState Tests', () {
    test('should create initial unauthenticated state', () {
      const authState = const AuthState();

      expect(authState.isAuthenticated, isFalse);
      expect(authState.username, isNull);
      expect(authState.userId, isNull);
      expect(authState.sessionToken, isNull);
    });

    test('should create authenticated state', () {
      final authState = AuthState(
        isAuthenticated: true,
        username: 'testuser',
        userId: 'user_123',
        sessionToken: 'sess_abc',
        publicKeyBase64: 'pubkey_base64',
        authenticatedAt: DateTime.now(),
      );

      expect(authState.isAuthenticated, isTrue);
      expect(authState.username, equals('testuser'));
      expect(authState.userId, equals('user_123'));
    });

    test('should copyWith and update fields', () {
      const initial = AuthState();

      final updated = initial.copyWith(
        isAuthenticated: true,
        username: 'newuser',
      );

      expect(updated.isAuthenticated, isTrue);
      expect(updated.username, equals('newuser'));
      expect(initial.isAuthenticated, isFalse); // Original unchanged
    });

    test('initial should be unauthenticated', () {
      expect(AuthState.initial.isAuthenticated, isFalse);
    });

    test('createTest should create valid test state', () {
      final authState = AuthStateTest.createTest();

      expect(authState.isAuthenticated, isTrue);
      expect(authState.username, equals('testuser'));
    });
  });

  group('PeerState Tests', () {
    test('should create initial state', () {
      const peerState = const PeerState();

      expect(peerState.isMeshEnabled, isFalse);
      expect(peerState.meshStatus, isNull);
      expect(peerState.meshPeers, isEmpty);
    });

    test('should copyWith and update fields', () {
      const initial = PeerState();

      final updated = initial.copyWith(
        isMeshEnabled: true,
      );

      expect(updated.isMeshEnabled, isTrue);
      expect(initial.isMeshEnabled, isFalse); // Original unchanged
    });

    test('should calculate onlineCount', () {
      final peerState = PeerState(
        meshPeers: [
          MeshPeer(
            nodeId: 'peer_1',
            wgPubkey: 'key1',
            isOnline: true,
            keepalive: 25,
          ),
          MeshPeer(
            nodeId: 'peer_2',
            wgPubkey: 'key2',
            isOnline: false,
            keepalive: 25,
          ),
          MeshPeer(
            nodeId: 'peer_3',
            wgPubkey: 'key3',
            isOnline: true,
            keepalive: 25,
          ),
        ],
      );

      expect(peerState.onlineCount, equals(2));
      expect(peerState.totalCount, equals(3));
    });

    test('initial should have empty peers', () {
      expect(PeerState.initial.meshPeers, isEmpty);
    });
  });

  group('Settings Tests', () {
    test('should create with default values', () {
      const settings = const Settings();

      expect(settings.serverHost, equals('localhost'));
      expect(settings.serverPort, equals(9100));
      expect(settings.autoDiscoveryEnabled, isTrue);
      expect(settings.autoConnectOnLaunch, isFalse);
      expect(settings.useTls, isFalse);
      expect(settings.darkModeEnabled, isTrue);
    });

    test('should copyWith and update fields', () {
      const initial = Settings();

      final updated = initial.copyWith(
        serverHost: '192.168.1.100',
        serverPort: 8080,
        autoDiscoveryEnabled: false,
      );

      expect(updated.serverHost, equals('192.168.1.100'));
      expect(updated.serverPort, equals(8080));
      expect(updated.autoDiscoveryEnabled, isFalse);
      expect(initial.serverHost, equals('localhost')); // Original unchanged
    });

    test('should calculate endpoint', () {
      const settings = Settings(serverHost: 'example.com', serverPort: 9100);

      expect(settings.endpoint, equals('example.com:9100'));
    });

    test('createTest should create valid test settings', () {
      final settings = SettingsTest.createTest(
        serverHost: 'test.example.com',
        serverPort: 443,
      );

      expect(settings.serverHost, equals('test.example.com'));
      expect(settings.serverPort, equals(443));
    });
  });

  group('AppState Tests', () {
    test('should create initial state', () {
      const appState = AppState.initial;

      expect(appState.connectionStatus, equals(ConnectionStatus.disconnected));
      expect(appState.authState.isAuthenticated, isFalse);
      expect(appState.isTunnelUp, isFalse);
      expect(appState.isMeshEnabled, isFalse);
      expect(appState.isConnected, isFalse);
      expect(appState.servers, isEmpty);
      expect(appState.treeNodes, isEmpty);
    });

    test('should copyWith and update fields', () {
      final initial = AppStateTest.createTest();

      final updated = initial.copyWith(
        connectionStatus: ConnectionStatus.connected,
        isLoading: true,
      );

      expect(updated.connectionStatus, equals(ConnectionStatus.connected));
      expect(updated.isLoading, isTrue);
      expect(initial.connectionStatus, equals(ConnectionStatus.disconnected));
    });

    test('isAuthenticated should reflect authState', () {
      final authenticatedState = AppStateTest.createTest(
        authState: AuthStateTest.createTest(isAuthenticated: true),
      );

      expect(authenticatedState.isAuthenticated, isTrue);
    });

    test('isTunnelUp should handle null tunnelStatus', () {
      final state = AppStateTest.createTest(tunnelStatus: null);
      expect(state.isTunnelUp, isFalse);
    });

    test('isTunnelUp should reflect tunnelStatus', () {
      final state = AppStateTest.createTest(
        tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
      );
      expect(state.isTunnelUp, isTrue);
    });

    test('should get tunnelIP from tunnelStatus', () {
      final state = AppStateTest.createTest(
        tunnelStatus: ModelFactory.createTunnelStatus(tunnelIp: '10.0.0.5'),
      );
      expect(state.tunnelIP, equals('10.0.0.5'));
    });

    test('should get meshStatus', () {
      final meshStatus = ModelFactory.createMeshStatus(peerCount: 5);
      final state = AppStateTest.createTest(
        peerState: PeerState(
          isMeshEnabled: true,
          meshStatus: meshStatus,
        ),
      );
      expect(state.meshStatus, equals(meshStatus));
    });

    test('should get meshPeers', () {
      final peers = [
        ModelFactory.createMeshPeer(nodeId: 'peer_1'),
        ModelFactory.createMeshPeer(nodeId: 'peer_2'),
      ];
      final state = AppStateTest.createTest(
        peerState: PeerState(meshPeers: peers),
      );
      expect(state.meshPeers.length, equals(2));
    });

    test('should add activity entries', () {
      final state = AppStateTest.createTest();
      final entry = ActivityEntry(
        id: '1',
        message: 'Test activity',
        level: ActivityLevel.info,
        timestamp: DateTime.now(),
      );

      final updated = state.copyWith(
        activityLog: [entry, ...state.activityLog],
      );

      expect(updated.activityLog.length, equals(1));
      expect(updated.activityLog.first.message, equals('Test activity'));
    });

    test('should maintain activity log limit', () {
      // Create state with 50 activities
      final manyActivities = List.generate(
        50,
        (i) => ActivityEntry(
          id: '$i',
          message: 'Activity $i',
          level: ActivityLevel.info,
          timestamp: DateTime.now(),
        ),
      );

      final state = AppStateTest.createTest(activityLog: manyActivities);
      expect(state.activityLog.length, equals(50));

      // Add one more - should remove oldest
      final newEntry = ActivityEntry(
        id: 'new',
        message: 'New activity',
        level: ActivityLevel.info,
        timestamp: DateTime.now(),
      );
      final updated = state.copyWith(
        activityLog: [newEntry, ...state.activityLog],
      );

      expect(updated.activityLog.length, equals(50)); // Still 50
      expect(updated.activityLog.first.message, equals('New activity'));
    });
  });

  group('ActivityEntry Tests', () {
    test('should create info entry', () {
      final entry = ActivityEntry.info('Test info message');

      expect(entry.level, equals(ActivityLevel.info));
      expect(entry.message, equals('Test info message'));
      expect(entry.id, isNotEmpty);
    });

    test('should create success entry', () {
      final entry = ActivityEntry.success('Operation completed');

      expect(entry.level, equals(ActivityLevel.success));
      expect(entry.message, equals('Operation completed'));
    });

    test('should create warning entry', () {
      final entry = ActivityEntry.warning('Low disk space');

      expect(entry.level, equals(ActivityLevel.warning));
    });

    test('should create error entry', () {
      final entry = ActivityEntry.error('Connection failed');

      expect(entry.level, equals(ActivityLevel.error));
      expect(entry.message, equals('Connection failed'));
    });

    test('timestamp should be recent', () {
      final before = DateTime.now();
      final entry = ActivityEntry.info('Test');
      final after = DateTime.now();

      expect(entry.timestamp.isAfter(before), isTrue);
      expect(entry.timestamp.isBefore(after), isTrue);
    });
  });

  group('SidebarItem Tests', () {
    test('should have correct labels', () {
      expect(SidebarItem.dashboard.label, equals('Dashboard'));
      expect(SidebarItem.tunnel.label, equals('Tunnel'));
      expect(SidebarItem.peers.label, equals('Peers'));
      expect(SidebarItem.network.label, equals('Network'));
      expect(SidebarItem.endpoints.label, equals('Endpoints'));
      expect(SidebarItem.servers.label, equals('Servers'));
      expect(SidebarItem.certificates.label, equals('Certificates'));
      expect(SidebarItem.relays.label, equals('Relays'));
      expect(SidebarItem.settings.label, equals('Settings'));
    });

    test('should have icons', () {
      expect(SidebarItem.dashboard.icon, isNotNull);
      expect(SidebarItem.tunnel.icon, isNotNull);
      expect(SidebarItem.peers.icon, isNotNull);
    });
  });

  group('ConnectionStatus Enum Tests', () {
    test('should have all values', () {
      expect(ConnectionStatus.values.length, equals(4));
      expect(ConnectionStatus.values, contains(ConnectionStatus.disconnected));
      expect(ConnectionStatus.values, contains(ConnectionStatus.connecting));
      expect(ConnectionStatus.values, contains(ConnectionStatus.connected));
      expect(ConnectionStatus.values, contains(ConnectionStatus.error));
    });
  });

  group('ActivityLevel Enum Tests', () {
    test('should have all values', () {
      expect(ActivityLevel.values.length, equals(4));
      expect(ActivityLevel.values, contains(ActivityLevel.info));
      expect(ActivityLevel.values, contains(ActivityLevel.success));
      expect(ActivityLevel.values, contains(ActivityLevel.warning));
      expect(ActivityLevel.values, contains(ActivityLevel.error));
    });
  });

  group('AppNotifier Tests (with Mock)', () {
    late MockAppNotifier mockNotifier;
    late FakeSdk fakeSdk;

    setUp(() {
      fakeSdk = FakeSdk();
      mockNotifier = MockAppNotifier();
    });

    test('should initialize with default state', () {
      expect(mockNotifier.state, isNotNull);
      expect(mockNotifier.state.authState.isAuthenticated, isFalse);
    });

    test('should update authentication state', () {
      mockNotifier.setAuthenticated(true);

      expect(mockNotifier.state.authState.isAuthenticated, isTrue);
    });

    test('should update connection status', () {
      mockNotifier.setConnectionStatus(ConnectionStatus.connected);

      expect(mockNotifier.state.connectionStatus, equals(ConnectionStatus.connected));
    });

    test('should update tunnel status', () {
      final tunnelStatus = ModelFactory.createTunnelStatus(
        isUp: true,
        tunnelIp: '10.0.0.1',
      );
      mockNotifier.setTunnelStatus(tunnelStatus);

      expect(mockNotifier.state.tunnelStatus, equals(tunnelStatus));
    });

    test('should add activity entry', () {
      final entry = ActivityEntry.success('Test success');
      mockNotifier.addActivityEntry(entry);

      expect(mockNotifier.state.activityLog.length, equals(1));
      expect(mockNotifier.state.activityLog.first.level, equals(ActivityLevel.success));
    });

    test('should maintain activity log order (newest first)', () {
      mockNotifier.addActivityEntry(ActivityEntry.info('First'));
      mockNotifier.addActivityEntry(ActivityEntry.info('Second'));
      mockNotifier.addActivityEntry(ActivityEntry.info('Third'));

      expect(mockNotifier.state.activityLog.length, equals(3));
      expect(mockNotifier.state.activityLog.first.message, equals('Third'));
      expect(mockNotifier.state.activityLog.last.message, equals('First'));
    });
  });

  group('Riverpod Provider Tests', () {
    late ProviderContainer container;

    setUp(() {
      container = createTestContainer();
    });

    tearDown(() {
      container.dispose();
    });

    test('sdkProvider should create SDK instance', () {
      final sdk = container.read(sdkProvider);
      expect(sdk, isNotNull);
    });

    test('settingsProvider should return default settings', () {
      final settings = container.read(settingsProvider);
      expect(settings, isNotNull);
      expect(settings.serverHost, equals('localhost'));
    });

    test('isLoadingProvider should return bool', () {
      final isLoading = container.read(isLoadingProvider);
      expect(isLoading, isA<bool>());
    });

    test('errorMessageProvider should return nullable string', () {
      final errorMessage = container.read(errorMessageProvider);
      expect(errorMessage, isNull); // Initially null
    });

    test('selectedSidebarItemProvider should return dashboard', () {
      final item = container.read(selectedSidebarItemProvider);
      expect(item, equals(SidebarItem.dashboard));
    });

    test('activityLogProvider should return empty list initially', () {
      final log = container.read(activityLogProvider);
      expect(log, isA<List<ActivityEntry>>());
      expect(log, isEmpty);
    });

    test('serversProvider should return empty list initially', () {
      final servers = container.read(serversProvider);
      expect(servers, isA<List<ServerInfo>>());
      expect(servers, isEmpty);
    });

    test('relaysProvider should return empty list initially', () {
      final relays = container.read(relaysProvider);
      expect(relays, isA<List<RelayInfo>>());
      expect(relays, isEmpty);
    });

    test('certificatesProvider should return empty list initially', () {
      final certs = container.read(certificatesProvider);
      expect(certs, isA<List<CertStatus>>());
      expect(certs, isEmpty);
    });

    test('treeNodesProvider should return empty list initially', () {
      final nodes = container.read(treeNodesProvider);
      expect(nodes, isA<List<TreeNode>>());
      expect(nodes, isEmpty);
    });

    test('rootNodeProvider should return null initially', () {
      final rootNode = container.read(rootNodeProvider);
      expect(rootNode, isNull);
    });

    test('connectionStatusProvider should return disconnected', () {
      final status = container.read(connectionStatusProvider);
      expect(status, equals(ConnectionStatus.disconnected));
    });

    test('peerStateProvider should return initial state', () {
      final peerState = container.read(peerStateProvider);
      expect(peerState.isMeshEnabled, isFalse);
    });

    test('tunnelStatusProvider should return null initially', () {
      final status = container.read(tunnelStatusProvider);
      expect(status, isNull);
    });

    test('healthStatusProvider should return null initially', () {
      final health = container.read(healthStatusProvider);
      expect(health, isNull);
    });

    test('statsProvider should return null initially', () {
      final stats = container.read(statsProvider);
      expect(stats, isNull);
    });

    test('trustStatusProvider should return null initially', () {
      final trust = container.read(trustStatusProvider);
      expect(trust, isNull);
    });
  });

  group('ThemeProvider Tests', () {
    late ThemeNotifier themeNotifier;

    setUp(() {
      themeNotifier = ThemeNotifier();
    });

    tearDown(() {
      themeNotifier.dispose();
    });

    test('should initialize with system theme', () {
      expect(themeNotifier.state, equals(ThemeMode.system));
    });

    test('should set theme to dark', () {
      themeNotifier.setTheme(ThemeMode.dark);
      expect(themeNotifier.state, equals(ThemeMode.dark));
    });

    test('should set theme to light', () {
      themeNotifier.setTheme(ThemeMode.light);
      expect(themeNotifier.state, equals(ThemeMode.light));
    });

    test('should toggle from system to dark', () {
      themeNotifier.toggleDarkMode();
      expect(themeNotifier.state, equals(ThemeMode.dark));
    });

    test('should toggle from dark to light', () {
      themeNotifier.setTheme(ThemeMode.dark);
      themeNotifier.toggleDarkMode();
      expect(themeNotifier.state, equals(ThemeMode.light));
    });

    test('should toggle from light to dark', () {
      themeNotifier.setTheme(ThemeMode.light);
      themeNotifier.toggleDarkMode();
      expect(themeNotifier.state, equals(ThemeMode.dark));
    });
  });

  group('AuthService Tests', () {
    late FakeSdk fakeSdk;
    late AuthService authService;
    late MockAppNotifier mockNotifier;

    setUp(() {
      fakeSdk = FakeSdk();
      mockNotifier = MockAppNotifier();

      // Create AuthService with fake dependencies
      authService = AuthService(fakeSdk, mockNotifier);
    });

    test('isAuthenticated should return false initially', () {
      expect(authService.isAuthenticated, isFalse);
    });

    test('username should return null initially', () {
      expect(authService.username, isNull);
    });

    test('userId should return null initially', () {
      expect(authService.userId, isNull);
    });
  });

  group('TunnelService Tests', () {
    late FakeSdk fakeSdk;
    late TunnelService tunnelService;
    late MockAppNotifier mockNotifier;

    setUp(() {
      fakeSdk = FakeSdk();
      mockNotifier = MockAppNotifier();
      tunnelService = TunnelService(fakeSdk, mockNotifier);
    });

    test('should have initial status', () {
      expect(tunnelService.status, isNull);
      expect(tunnelService.isTunnelUp, isFalse);
      expect(tunnelService.isMeshEnabled, isFalse);
      expect(tunnelService.tunnelIp, isNull);
    });
  });

  group('DiscoveryService Tests', () {
    late FakeSdk fakeSdk;
    late DiscoveryService discoveryService;
    late MockAppNotifier mockNotifier;

    setUp(() {
      fakeSdk = FakeSdk();
      mockNotifier = MockAppNotifier();
      discoveryService = DiscoveryService(fakeSdk, mockNotifier);
    });

    test('should have default server settings', () {
      expect(discoveryService.serverHost, equals('localhost'));
      expect(discoveryService.serverPort, equals(9100));
      expect(discoveryService.isConnected, isFalse);
    });

    test('should return empty servers list initially', () {
      expect(discoveryService.servers, isEmpty);
    });

    test('should return empty relays list initially', () {
      expect(discoveryService.relays, isEmpty);
    });

    test('should return connection status', () {
      expect(discoveryService.connectionStatus, equals(ConnectionStatus.disconnected));
    });
  });

  group('TreeService Tests', () {
    late FakeSdk fakeSdk;
    late TreeService treeService;
    late MockAppNotifier mockNotifier;

    setUp(() {
      fakeSdk = FakeSdk();
      mockNotifier = MockAppNotifier();
      treeService = TreeService(fakeSdk, mockNotifier);
    });

    test('should have null root node initially', () {
      expect(treeService.rootNode, isNull);
    });

    test('should return empty tree nodes list', () {
      expect(treeService.treeNodes, isEmpty);
    });

    test('should return null trust status initially', () {
      expect(treeService.trustStatus, isNull);
    });
  });

  group('AppConfig Tests', () {
    test('should create with default values', () {
      const config = AppConfig(
        apiHost: 'api.lemonade-nexus.com',
        apiPort: 443,
        useTls: true,
      );

      expect(config.apiHost, equals('api.lemonade-nexus.com'));
      expect(config.apiPort, equals(443));
      expect(config.useTls, isTrue);
    });

    test('should calculate HTTPS endpoint', () {
      const config = AppConfig(
        apiHost: 'example.com',
        apiPort: 443,
        useTls: true,
      );

      expect(config.endpoint, equals('https://example.com:443'));
    });

    test('should calculate HTTP endpoint', () {
      const config = AppConfig(
        apiHost: 'localhost',
        apiPort: 8080,
        useTls: false,
      );

      expect(config.endpoint, equals('http://localhost:8080'));
    });
  });
}
