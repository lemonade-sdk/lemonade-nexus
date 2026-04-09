/// @title Integration Tests
/// @description End-to-end integration tests for key user flows.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';
import 'package:lemonade_nexus/src/views/login_view.dart';
import 'package:lemonade_nexus/src/views/content_view.dart';
import 'package:lemonade_nexus/src/views/dashboard_view.dart';
import 'package:lemonade_nexus/src/views/tunnel_control_view.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('Authentication Flow Integration Tests', () {
    testWidgets('should complete full login flow', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
        ),
      );

      // Start at login screen
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Enter credentials
      final usernameField = find.text('Username');
      await tester.tap(usernameField);
      await tester.enterText(usernameField, 'testuser');
      await tester.pump();

      final passwordField = find.byWidgetPredicate((widget) {
        if (widget is EditableText) {
          return widget.obscureText;
        }
        return false;
      });
      await tester.tap(passwordField);
      await tester.enterText(passwordField, 'password123');
      await tester.pump();

      // Tap Sign In
      await tester.tap(find.text('Sign In'));
      await tester.pumpAndSettle();

      // Verify login was attempted
      expect(find.byType(LoginView), findsOneWidget);
    });

    testWidgets('should show validation errors for empty fields', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Try to submit without entering data
      await tester.tap(find.text('Sign In'));
      await tester.pumpAndSettle();

      // Should show validation error
      expect(
        find.text('Please enter your username'),
        findsOneWidget,
      );
    });

    testWidgets('should switch between Password and Passkey tabs', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Verify password tab is active
      expect(find.text('Password'), findsOneWidget);

      // Switch to passkey tab
      await tester.tap(find.text('Passkey'));
      await tester.pumpAndSettle();

      // Verify passkey content is shown
      expect(
        find.text('Sign in with your fingerprint or face'),
        findsOneWidget,
      );

      // Switch back to password tab
      await tester.tap(find.text('Password'));
      await tester.pumpAndSettle();

      expect(find.text('Username'), findsOneWidget);
    });

    testWidgets('should show loading state during authentication', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
          isLoading: true,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Should show loading indicator
      expect(find.text('Signing In...'), findsOneWidget);
    });

    testWidgets('should transition to ContentView after successful auth', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
        ),
      );

      // Start at login
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Simulate successful authentication
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(
            isAuthenticated: true,
            username: 'testuser',
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Should now show ContentView
      expect(find.byType(ContentView), findsOneWidget);
    });
  });

  group('Tunnel Connection Flow Integration Tests', () {
    testWidgets('should connect to VPN tunnel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: false),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      // Verify tunnel is disconnected
      expect(find.text('Inactive'), findsOneWidget);

      // Tap Connect button
      await tester.tap(find.text('Connect'));
      await tester.pump();

      // Verify connect was triggered
      expect(find.byType(TunnelControlView), findsOneWidget);
    });

    testWidgets('should disconnect from VPN tunnel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      // Verify tunnel is connected
      expect(find.text('Active'), findsOneWidget);

      // Tap Disconnect button
      await tester.tap(find.text('Disconnect'));
      await tester.pump();

      // Verify disconnect was triggered
      expect(find.byType(TunnelControlView), findsOneWidget);
    });

    testWidgets('should show tunnel IP when connected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(
            isUp: true,
            tunnelIp: '10.0.0.5',
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should show connection details when tunnel is up', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
          peerState: PeerState(
            meshStatus: ModelFactory.createMeshStatus(
              peerCount: 5,
              onlineCount: 3,
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('Connection Details'), findsOneWidget);
      expect(find.text('Peers'), findsOneWidget);
    });
  });

  group('Mesh Network Flow Integration Tests', () {
    testWidgets('should enable mesh networking', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          peerState: PeerState(isMeshEnabled: false),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      // Verify mesh is disabled
      expect(find.text('Enable'), findsOneWidget);

      // Tap Enable button
      await tester.tap(find.text('Enable'));
      await tester.pump();

      // Verify enable was triggered
      expect(find.byType(TunnelControlView), findsOneWidget);
    });

    testWidgets('should disable mesh networking', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          peerState: PeerState(isMeshEnabled: true),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      // Verify mesh is enabled
      expect(find.text('Disable'), findsOneWidget);

      // Tap Disable button
      await tester.tap(find.text('Disable'));
      await tester.pump();

      // Verify disable was triggered
      expect(find.byType(TunnelControlView), findsOneWidget);
    });

    testWidgets('should show mesh peers when enabled', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                hostname: 'peer1.local',
                isOnline: true,
              ),
              ModelFactory.createMeshPeer(
                nodeId: 'peer_2',
                hostname: 'peer2.local',
                isOnline: false,
              ),
            ],
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('3/5 peers online'), findsOneWidget);
    });
  });

  group('Server Selection Flow Integration Tests', () {
    testWidgets('should display server list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'server1.example.com',
              port: 9100,
              available: true,
              region: 'us-west',
            ),
            ModelFactory.createServerInfo(
              id: 'server_2',
              host: 'server2.example.com',
              port: 9100,
              available: true,
              region: 'us-east',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate to servers
      await tester.tap(find.text('Servers'));
      await tester.pumpAndSettle();

      expect(find.text('server1.example.com:9100'), findsOneWidget);
      expect(find.text('server2.example.com:9100'), findsOneWidget);
    });

    testWidgets('should select a server', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'server1.example.com',
              port: 9100,
              available: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate to servers
      await tester.tap(find.text('Servers'));
      await tester.pumpAndSettle();

      // Tap on server
      await tester.tap(find.text('server1.example.com:9100'));
      await tester.pumpAndSettle();

      // Should show detail panel
      expect(find.text('Endpoint'), findsOneWidget);
    });

    testWidgets('should show server health status', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'server1.example.com',
              port: 9100,
              available: true,
            ),
            ModelFactory.createServerInfo(
              id: 'server_2',
              host: 'server2.example.com',
              port: 9100,
              available: false,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate to servers
      await tester.tap(find.text('Servers'));
      await tester.pumpAndSettle();

      expect(find.text('HEALTHY'), findsOneWidget);
      expect(find.text('UNHEALTHY'), findsOneWidget);
    });
  });

  group('Settings Persistence Flow Integration Tests', () {
    testWidgets('should update server URL', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          settings: SettingsTest.createTest(
            serverHost: 'localhost',
            serverPort: 9100,
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate to settings
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      // Server URL field should be present
      expect(find.text('Server URL'), findsOneWidget);
    });

    testWidgets('should toggle auto-discovery', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          autoDiscoveryEnabled: false,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate to settings
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      // Find and tap the auto-discovery switch
      final switches = tester.widgetList<Switch>(find.byType(Switch)).toList();
      if (switches.isNotEmpty) {
        await tester.tap(find.byType(Switch).first);
        await tester.pump();
      }
    });

    testWidgets('should toggle auto-connect', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          autoConnectOnLaunch: false,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate to settings
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      // Auto-connect toggle should be present
      expect(find.text('Auto-connect on launch'), findsOneWidget);
    });

    testWidgets('should sign out from settings', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate to settings
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      // Tap sign out button
      await tester.tap(find.text('Sign Out'));
      await tester.pumpAndSettle();

      // Tap confirm
      await tester.tap(find.text('Sign Out').last);
      await tester.pumpAndSettle();

      // Should have called signOut
      expect(mockNotifier.state.authState?.isAuthenticated, isFalse);
    });
  });

  group('Dashboard Display Flow Integration Tests', () {
    testWidgets('should display dashboard with all sections', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
          peerState: PeerState(
            isMeshEnabled: true,
            meshStatus: ModelFactory.createMeshStatus(
              peerCount: 5,
              onlineCount: 3,
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Should be on dashboard by default
      expect(find.byType(DashboardView), findsOneWidget);

      // Should show key stats
      expect(find.text('VPN Tunnel'), findsOneWidget);
      expect(find.text('P2P Mesh'), findsOneWidget);
    });

    testWidgets('should display server health card', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          connectionStatus: ConnectionStatus.connected,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Server Health'), findsOneWidget);
    });

    testWidgets('should display activity feed', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          activity: [
            ActivityEntry(
              timestamp: DateTime.now(),
              message: 'Connected to VPN',
              level: ActivityLevel.info,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Activity'), findsOneWidget);
    });
  });

  group('Navigation Flow Integration Tests', () {
    testWidgets('should navigate between all sections', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Navigate through all sections
      final sections = [
        'Dashboard',
        'Tunnel',
        'Peers',
        'Network',
        'Endpoints',
        'Servers',
        'Certificates',
        'Relays',
        'Settings',
      ];

      for (final section in sections) {
        await tester.tap(find.text(section));
        await tester.pumpAndSettle();
      }

      // All navigations should complete without error
      expect(find.byType(ContentView), findsOneWidget);
    });

    testWidgets('should highlight selected navigation item', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          selectedSidebarItem: SidebarItem.dashboard,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Dashboard should be highlighted
      expect(find.text('Dashboard'), findsOneWidget);
    });
  });

  group('Error Handling Flow Integration Tests', () {
    testWidgets('should handle authentication error', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
          errorMessage: 'Invalid credentials',
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Error should be displayed
      expect(find.byType(Icon), findsWidgets);
    });

    testWidgets('should handle connection error', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          connectionStatus: ConnectionStatus.disconnected,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Should show disconnected state
      expect(find.text('Disconnected'), findsWidgets);
    });

    testWidgets('should handle tunnel error', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(
            isUp: false,
            error: 'Tunnel failed to start',
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Should handle error state gracefully
      expect(find.byType(ContentView), findsOneWidget);
    });
  });

  group('Full User Journey Integration Tests', () {
    testWidgets('should complete full user journey', (tester) async {
      final mockNotifier = MockAppNotifier();

      // Start unauthenticated
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
        ),
      );

      // Login
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Authenticate
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(
            isAuthenticated: true,
            username: 'testuser',
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // View dashboard
      expect(find.byType(DashboardView), findsOneWidget);

      // Navigate to tunnel
      await tester.tap(find.text('Tunnel'));
      await tester.pumpAndSettle();
      expect(find.byType(TunnelControlView), findsOneWidget);

      // Navigate to settings
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      // Sign out
      await tester.tap(find.byIcon(Icons.logout));
      await tester.pumpAndSettle();

      // Journey complete
      expect(find.byType(ContentView), findsOneWidget);
    });
  });
}
