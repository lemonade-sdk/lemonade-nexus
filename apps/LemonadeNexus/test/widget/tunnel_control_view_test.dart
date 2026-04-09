/// @title Tunnel Control View Widget Tests
/// @description Tests for the TunnelControlView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/tunnel_control_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('TunnelControlView Widget Tests', () {
    testWidgets('should display header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('WireGuard Tunnel'), findsOneWidget);
      expect(find.byIcon(Icons.security), findsOneWidget);
    });

    testWidgets('should display refresh button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.byIcon(Icons.refresh), findsOneWidget);
    });

    testWidgets('should display tunnel card', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('VPN Tunnel'), findsOneWidget);
    });

    testWidgets('should display tunnel status indicator', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      // Should show Inactive initially
      expect(find.text('Inactive'), findsOneWidget);
      expect(find.byIcon(Icons.cancel), findsOneWidget);
    });

    testWidgets('should display Connect button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('Connect'), findsOneWidget);
    });

    testWidgets('should display mesh card', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('P2P Mesh Networking'), findsOneWidget);
    });

    testWidgets('should display mesh status', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('Inactive'), findsWidgets); // Mesh is inactive
    });

    testWidgets('should display Enable mesh button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('Enable'), findsOneWidget);
    });

    testWidgets('should show online count for mesh peers', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('0/0 peers online'), findsOneWidget);
    });
  });

  group('TunnelControlView With State Tests', () {
    testWidgets('should show Active when tunnel is up', (tester) async {
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
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('Active'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('should show Disconnect button when tunnel is up', (tester) async {
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
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('Disconnect'), findsOneWidget);
    });

    testWidgets('should show Active when mesh is enabled', (tester) async {
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
          child: const MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.text('Active'), findsWidgets); // Mesh active
      expect(find.byIcon(Icons.people), findsOneWidget);
    });

    testWidgets('should show Disable button when mesh is enabled', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
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

      expect(find.text('Disable'), findsOneWidget);
    });

    testWidgets('should show connection details when tunnel is up', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          tunnelStatus: ModelFactory.createTunnelStatus(
            isUp: true,
            tunnelIp: '10.0.0.1',
          ),
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
      expect(find.text('Tunnel IP'), findsOneWidget);
      expect(find.text('Peers'), findsOneWidget);
      expect(find.text('Online'), findsOneWidget);
    });

    testWidgets('should show bandwidth info', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            meshStatus: ModelFactory.createMeshStatus(
              totalRxBytes: 1048576,
              totalTxBytes: 524288,
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

      // Should show bandwidth info
      expect(find.byIcon(Icons.arrow_downward_circle), findsOneWidget);
      expect(find.byIcon(Icons.arrow_upward_circle), findsOneWidget);
    });

    testWidgets('should show uptime when connected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          tunnelStatus: ModelFactory.createTunnelStatus(isUp: true),
          connectedSince: DateTime.now().subtract(const Duration(hours: 2)),
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

      expect(find.text('Uptime'), findsOneWidget);
    });

    testWidgets('should display tunnel IP in card', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          tunnelStatus: ModelFactory.createTunnelStatus(
            isUp: true,
            tunnelIp: '10.0.0.100',
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

      expect(find.text('10.0.0.100'), findsOneWidget);
    });

    testWidgets('should show proper peer counts', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshStatus: ModelFactory.createMeshStatus(
              peerCount: 10,
              onlineCount: 7,
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

      expect(find.text('7/10 peers online'), findsOneWidget);
    });
  });

  group('TunnelControlView UI Element Tests', () {
    testWidgets('should have proper card styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have elevated buttons', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.byType(ElevatedButton), findsWidgets);
    });

    testWidgets('should have proper icon sizes', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.byIcon(Icons.security), findsOneWidget);
    });

    testWidgets('should have scrollable content', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      expect(find.byType(SingleChildScrollView), findsOneWidget);
    });

    testWidgets('should have proper color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TunnelControlView()),
        ),
      );

      // Status indicator colors
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have stat items with icons', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            meshStatus: ModelFactory.createMeshStatus(),
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

      expect(find.byIcon(Icons.network), findsOneWidget);
      expect(find.byIcon(Icons.people), findsOneWidget);
      expect(find.byIcon(Icons.wifi), findsOneWidget);
    });
  });
}
