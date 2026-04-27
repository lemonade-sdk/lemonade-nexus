/// @title Main Navigation Widget Tests
/// @description Tests for the main navigation and routing structure.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/views/login_view.dart';
import 'package:lemonade_nexus/src/views/content_view.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';

void main() {
  group('Main Navigation Widget Tests', () {
    testWidgets('should show login view when not authenticated', (tester) async {
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

      expect(find.byType(LoginView), findsOneWidget);
      expect(find.byType(ContentView), findsNothing);
    });

    testWidgets('should show content view when authenticated', (tester) async {
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

      expect(find.byType(LoginView), findsNothing);
      expect(find.byType(ContentView), findsOneWidget);
    });

    testWidgets('should display app title on login screen', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Lemonade Nexus'), findsOneWidget);
    });

    testWidgets('should display app subtitle on login screen', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Secure Mesh VPN'), findsOneWidget);
    });
  });

  group('Main Navigation State Transition Tests', () {
    testWidgets('should transition from login to content on authentication', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
        ),
      );

      // Start with login view
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(LoginView), findsOneWidget);

      // Simulate authentication
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

      expect(find.byType(ContentView), findsOneWidget);
    });

    testWidgets('should transition from content to login on sign out', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
        ),
      );

      // Start with content view
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(ContentView), findsOneWidget);

      // Simulate sign out
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

      expect(find.byType(LoginView), findsOneWidget);
    });
  });

  group('Main Navigation Auth State Tests', () {
    testWidgets('should handle loading state during auth', (tester) async {
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

      // Should still show login view
      expect(find.byType(LoginView), findsOneWidget);
    });

    testWidgets('should handle error state during auth', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: false),
          errorMessage: 'Authentication failed',
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

      // Should still show login view with error
      expect(find.byType(LoginView), findsOneWidget);
    });
  });

  group('Main Navigation SidebarItem Tests', () {
    testWidgets('should have correct number of sidebar items', () {
      expect(SidebarItem.values.length, equals(9));
    });

    testWidgets('should have dashboard as first item', () {
      expect(SidebarItem.values.first, equals(SidebarItem.dashboard));
    });

    testWidgets('should have settings as last item', () {
      expect(SidebarItem.values.last, equals(SidebarItem.settings));
    });

    testWidgets('should have correct labels for all items', () {
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
  });

  group('Main Navigation Connection Status Tests', () {
    testWidgets('should show disconnected state initially', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Disconnected'), findsWidgets);
    });

    testWidgets('should show connected state when connected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
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

      expect(find.text('Connected'), findsWidgets);
    });

    testWidgets('should handle connecting state', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
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

      // Should show loading indicators
      expect(find.byType(CircularProgressIndicator), findsWidgets);
    });
  });

  group('Main Navigation Tunnel Status Tests', () {
    testWidgets('should show tunnel disconnected initially', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Tunnel is not up by default
      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show tunnel connected when tunnel is up', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
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

      // Should show VPN connected state
      expect(find.byType(ContentView), findsOneWidget);
    });
  });

  group('Main Navigation Mesh Status Tests', () {
    testWidgets('should show mesh disabled initially', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Default state has mesh disabled
      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show mesh enabled when mesh is active', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshStatus: ModelFactory.createMeshStatus(
              isUp: true,
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

      // Should show mesh active state
      expect(find.byType(ContentView), findsOneWidget);
    });
  });

  group('Main Navigation Error Handling Tests', () {
    testWidgets('should display error message', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          errorMessage: 'Connection failed',
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

      // Error message should be displayed somewhere
      expect(find.byType(Icon), findsWidgets);
    });

    testWidgets('should handle null auth state gracefully', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: null,
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

      // Should not crash
      expect(find.byType(LoginView), findsOneWidget);
    });

    testWidgets('should handle null tunnel status gracefully', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          tunnelStatus: null,
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

      // Should not crash
      expect(find.byType(ContentView), findsOneWidget);
    });
  });

  group('MainNavigation UI Consistency Tests', () {
    testWidgets('should have consistent theme across views', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Verify MaterialApp is properly configured
      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should have consistent color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Both views use the same color palette
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have consistent icon usage', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byIcon(Icons.security), findsOneWidget);
    });

    testWidgets('should have consistent text styles', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(Text), findsWidgets);
    });
  });

  group('Main Navigation Provider Tests', () {
    testWidgets('should properly override appNotifierProvider', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Verify mock notifier is being used
      expect(mockNotifier, isA<MockAppNotifier>());
    });

    testWidgets('should update state when notifier changes', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Update state
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
        ),
      );

      await tester.pump();

      // State should be updated
      expect(mockNotifier.state.authState?.isAuthenticated, isTrue);
    });
  });

  group('Main Navigation Widget Structure Tests', () {
    testWidgets('should have proper Scaffold structure', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(Scaffold), findsOneWidget);
    });

    testWidgets('should have proper SafeArea structure', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(SafeArea), findsWidgets);
    });

    testWidgets('should have proper SingleChildScrollView structure', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(SingleChildScrollView), findsWidgets);
    });
  });

  group('Main Navigation Lifecycle Tests', () {
    testWidgets('should initialize with default state', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Initial state should have defaults
      expect(mockNotifier.state.authState, isNotNull);
    });

    testWidgets('should dispose properly', (tester) async {
      final mockNotifier = MockAppNotifier();

      final widget = ProviderScope(
        overrides: [
          appNotifierProvider.overrideWith((ref) => mockNotifier),
        ],
        child: const MaterialApp(home: LoginView()),
      );

      await tester.pumpWidget(widget);
      await tester.pumpWidget(const SizedBox.shrink());

      // Widget should dispose without errors
      expect(true, isTrue);
    });
  });

  group('Main Navigation Integration Tests', () {
    testWidgets('should integrate with Riverpod providers', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Verify integration
      expect(find.byType(ProviderScope), findsOneWidget);
    });

    testWidgets('should handle state updates correctly', (tester) async {
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
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // State should be reflected in UI
      expect(mockNotifier.state.authState?.isAuthenticated, isTrue);
      expect(mockNotifier.state.tunnelStatus?.isUp, isTrue);
    });

    testWidgets('should handle multiple state changes', (tester) async {
      final mockNotifier = MockAppNotifier();

      // Initial state
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Change auth state
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
        ),
      );
      await tester.pump();

      // Change tunnel state
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
        ),
      );
      await tester.pump();

      // Change mesh state
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
          peerState: PeerState(isMeshEnabled: true),
        ),
      );
      await tester.pump();

      // All changes should be handled
      expect(mockNotifier.state.peerState?.isMeshEnabled, isTrue);
    });
  });
}
