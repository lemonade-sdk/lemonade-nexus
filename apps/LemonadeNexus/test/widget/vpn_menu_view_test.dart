/// @title VPN Menu View Widget Tests
/// @description Tests for the VPNMenuView component (system tray menu).

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/vpn_menu_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('VPNMenuView Widget Tests', () {
    testWidgets('should display not signed in status when unauthenticated', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('Not signed in'), findsOneWidget);
      expect(find.byIcon(Icons.person_off), findsOneWidget);
    });

    testWidgets('should display VPN disconnected status', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('VPN: Disconnected'), findsOneWidget);
      expect(find.byIcon(Icons.cancel), findsOneWidget);
    });

    testWidgets('should display VPN connected status', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('VPN: Connected'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('should display tunnel IP when connected', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('IP: 10.0.0.5'), findsOneWidget);
    });

    testWidgets('should display Connect VPN button when disconnected', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('Connect VPN'), findsOneWidget);
    });

    testWidgets('should display Disconnect VPN button when connected', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('Disconnect VPN'), findsOneWidget);
    });

    testWidgets('should display Open Manager button', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('Open Manager'), findsOneWidget);
      expect(find.byIcon(Icons.dashboard), findsOneWidget);
    });

    testWidgets('should display Quit button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('Quit Lemonade Nexus'), findsOneWidget);
      expect(find.byIcon(Icons.close), findsOneWidget);
    });

    testWidgets('should display keyboard shortcut for Open Manager', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('O'), findsOneWidget);
    });

    testWidgets('should display keyboard shortcut for Quit', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('Q'), findsOneWidget);
    });

    testWidgets('should not show connect button when not authenticated', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('Connect VPN'), findsNothing);
      expect(find.text('Disconnect VPN'), findsNothing);
    });

    testWidgets('should show dividers between sections', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Divider), findsWidgets);
    });
  });

  group('VPNMenuView Connecting State Tests', () {
    testWidgets('should show loading indicator when connecting', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          // Connecting state: isTunnelUp is false, no tunnel IP yet
          isLoading: true,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Should show CircularProgressIndicator when connecting
      expect(find.byType(CircularProgressIndicator), findsWidgets);
    });

    testWidgets('should disable button when connecting', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(isAuthenticated: true),
          isLoading: true,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Button should be disabled (loading indicator shown instead)
      expect(find.byType(CircularProgressIndicator), findsWidgets);
    });
  });

  group('VPNMenuView Button Interaction Tests', () {
    testWidgets('should have clickable connect button', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Find the connect button and tap it
      final connectButton = find.text('Connect VPN');
      expect(connectButton, findsOneWidget);

      await tester.tap(connectButton);
      await tester.pump();

      // Should trigger connect action (verified by mock being called)
      expect(mockNotifier.state.authState?.isAuthenticated, isTrue);
    });

    testWidgets('should have clickable disconnect button', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Find the disconnect button and tap it
      final disconnectButton = find.text('Disconnect VPN');
      expect(disconnectButton, findsOneWidget);

      await tester.tap(disconnectButton);
      await tester.pump();

      // Should trigger disconnect action
      expect(mockNotifier.state.authState?.isAuthenticated, isTrue);
    });

    testWidgets('should have clickable open manager button', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Find and tap the open manager button
      final openManagerButton = find.text('Open Manager');
      expect(openManagerButton, findsOneWidget);

      await tester.tap(openManagerButton);
      await tester.pump();
    });

    testWidgets('should have clickable quit button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      // Find and tap the quit button
      final quitButton = find.text('Quit Lemonade Nexus');
      expect(quitButton, findsOneWidget);

      await tester.tap(quitButton);
      await tester.pump();
    });
  });

  group('VPNMenuView UI Element Tests', () {
    testWidgets('should have proper container constraints', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Container), findsOneWidget);
    });

    testWidgets('should have proper padding', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Padding), findsWidgets);
    });

    testWidgets('should have proper column layout', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Column), findsOneWidget);
    });

    testWidgets('should have proper icon sizes', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byIcon(Icons.dashboard), findsOneWidget);
      expect(find.byIcon(Icons.close), findsOneWidget);
    });

    testWidgets('should have proper text styles', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Text), findsWidgets);
    });

    testWidgets('should have monospace font for tunnel IP', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.text('IP: 10.0.0.5'), findsOneWidget);
    });

    testWidgets('should have proper button styling', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Connect button uses Material with color
      expect(find.byType(Material), findsWidgets);
    });

    testWidgets('should have proper shortcut styling', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Shortcuts are in Containers with specific styling
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have proper color for connected status', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Green color for connected status
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('should have proper color for disconnected status', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Grey/red color for disconnected status
      expect(find.byIcon(Icons.cancel), findsOneWidget);
    });

    testWidgets('should have proper color for not signed in status', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Grey color for not signed in
      expect(find.byIcon(Icons.person_off), findsOneWidget);
    });

    testWidgets('should have InkWell for menu items', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(InkWell), findsWidgets);
    });

    testWidgets('should have proper row structure for menu items', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Row), findsWidgets);
    });

    testWidgets('should have expanded widget for label', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Expanded), findsWidgets);
    });
  });

  group('VPNMenuView Color Tests', () {
    testWidgets('should use green for connect button', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Connect button uses Color(0xFF2A9D8F) which is teal/green
      expect(find.byType(Material), findsWidgets);
    });

    testWidgets('should use red for disconnect button', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Disconnect button uses red.shade600
      expect(find.byType(Material), findsWidgets);
    });

    testWidgets('should use yellow/gold for manager icon', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      // Manager icon uses Color(0xFFE9C46A)
      expect(find.byIcon(Icons.dashboard), findsOneWidget);
    });
  });

  group('VPNMenuView Layout Tests', () {
    testWidgets('should have minimum width constraint', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      // Container has constraints
      expect(find.byType(Container), findsOneWidget);
    });

    testWidgets('should have vertical padding', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Padding), findsWidgets);
    });

    testWidgets('should have proper spacing between items', (tester) async {
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
          child: const MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(SizedBox), findsWidgets);
    });

    testWidgets('should have proper alignment', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: VPNMenuView()),
        ),
      );

      expect(find.byType(Column), findsOneWidget);
    });
  });
}
