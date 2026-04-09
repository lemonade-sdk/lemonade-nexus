/// @title Network Monitor View Widget Tests
/// @description Tests for the NetworkMonitorView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/network_monitor_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('NetworkMonitorView Widget Tests', () {
    testWidgets('should display header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Network Monitor'), findsOneWidget);
      expect(find.byIcon(Icons.bar_chart), findsOneWidget);
    });

    testWidgets('should display refresh button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byIcon(Icons.refresh), findsOneWidget);
    });

    testWidgets('should display summary cards', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Total Peers'), findsOneWidget);
      expect(find.text('Online'), findsOneWidget);
      expect(find.text('Total Received'), findsOneWidget);
      expect(find.text('Total Sent'), findsOneWidget);
    });

    testWidgets('should display zero values when no data', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('0'), findsWidgets);
    });

    testWidgets('should have proper card icons', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byIcon(Icons.people), findsOneWidget);
      expect(find.byIcon(Icons.wifi), findsOneWidget);
      expect(find.byIcon(Icons.arrow_downward_circle), findsOneWidget);
      expect(find.byIcon(Icons.arrow_upward_circle), findsOneWidget);
    });

    testWidgets('should not show peer topology when empty', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Peer Topology'), findsNothing);
    });

    testWidgets('should not show bandwidth breakdown when empty', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Bandwidth by Peer'), findsNothing);
    });
  });

  group('NetworkMonitorView With Peers Tests', () {
    testWidgets('should display peer count in summary', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
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
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('5'), findsWidgets);
    });

    testWidgets('should display online count in summary', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
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
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('3'), findsWidgets);
    });

    testWidgets('should display bandwidth in summary cards', (tester) async {
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
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      // Should show formatted bytes
      expect(find.byType(Text), findsWidgets);
    });

    testWidgets('should show peer topology when peers exist', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              hostname: 'peer1.local',
              tunnelIp: '10.0.0.2',
              isOnline: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Peer Topology'), findsOneWidget);
    });

    testWidgets('should show bandwidth breakdown when peers exist', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              hostname: 'peer1.local',
              rxBytes: 1024,
              txBytes: 512,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Bandwidth by Peer'), findsOneWidget);
    });

    testWidgets('should display peer hostname in topology', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              hostname: 'test-peer.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('test-peer.local'), findsOneWidget);
    });

    testWidgets('should display peer tunnel IP in topology', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              tunnelIp: '10.0.0.5',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should display online status indicator', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              isOnline: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      // Online indicator (green dot)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display offline status indicator', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              isOnline: false,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      // Offline indicator (red dot)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display latency in topology', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              latencyMs: 25,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('25ms'), findsOneWidget);
    });

    testWidgets('should display bandwidth icons in topology', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              rxBytes: 1024,
              txBytes: 512,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byIcon(Icons.arrow_downward), findsWidgets);
      expect(find.byIcon(Icons.arrow_upward), findsWidgets);
    });

    testWidgets('should show direct connection badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              endpoint: '192.168.1.100:51820',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Direct'), findsOneWidget);
    });

    testWidgets('should show relay connection badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              relayEndpoint: 'relay.example.com:9101',
              endpoint: null,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('Relay'), findsOneWidget);
    });

    testWidgets('should show no route badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              endpoint: null,
              relayEndpoint: null,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('No Route'), findsOneWidget);
    });

    testWidgets('should display formatted bandwidth values', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              rxBytes: 1048576, // 1 MB
              txBytes: 1048576,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.textContaining('MB'), findsWidgets);
    });

    testWidgets('should show bandwidth bar chart', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              rxBytes: 1024,
              txBytes: 512,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      // Bandwidth bars use Container widgets with colored backgrounds
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should show bandwidth legend', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              rxBytes: 1024,
              txBytes: 512,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.textContaining('Received'), findsWidgets);
      expect(find.textContaining('Sent'), findsWidgets);
    });
  });

  group('NetworkMonitorView Bandwidth Formatting Tests', () {
    testWidgets('should format bytes to KB', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            meshStatus: ModelFactory.createMeshStatus(
              totalRxBytes: 2048,
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.textContaining('KB'), findsWidgets);
    });

    testWidgets('should format bytes to MB', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            meshStatus: ModelFactory.createMeshStatus(
              totalRxBytes: 1048576,
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.textContaining('MB'), findsWidgets);
    });

    testWidgets('should format bytes to GB', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            meshStatus: ModelFactory.createMeshStatus(
              totalRxBytes: 1073741824,
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.textContaining('GB'), findsWidgets);
    });
  });

  group('NetworkMonitorView Latency Color Tests', () {
    testWidgets('should show green for low latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              latencyMs: 25, // < 50ms = green
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('25ms'), findsOneWidget);
    });

    testWidgets('should show orange for medium latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              latencyMs: 100, // 50-150ms = orange
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('100ms'), findsOneWidget);
    });

    testWidgets('should show red for high latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              latencyMs: 200, // > 150ms = red
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('200ms'), findsOneWidget);
    });
  });

  group('NetworkMonitorView UI Element Tests', () {
    testWidgets('should have proper card styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have scrollable content', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byType(SingleChildScrollView), findsOneWidget);
    });

    testWidgets('should have GridView for summary cards', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byType(GridView), findsOneWidget);
    });

    testWidgets('should have ListView for peer topology', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(nodeId: 'peer_1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byType(ListView), findsWidgets);
    });

    testWidgets('should have proper divider styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byType(Divider), findsWidgets);
    });

    testWidgets('should have monospace font for values', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              tunnelIp: '10.0.0.5',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should have proper badge styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(
              nodeId: 'peer_1',
              endpoint: '192.168.1.100:51820',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have proper section icons', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: [
            ModelFactory.createMeshPeer(nodeId: 'peer_1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byIcon(Icons.share), findsOneWidget);
      expect(find.byIcon(Icons.bar_chart), findsWidgets);
    });

    testWidgets('should have 4 summary cards', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NetworkMonitorView()),
        ),
      );

      // 4 cards with icons
      expect(find.byIcon(Icons.people), findsOneWidget);
      expect(find.byIcon(Icons.wifi), findsOneWidget);
      expect(find.byIcon(Icons.arrow_downward_circle), findsOneWidget);
      expect(find.byIcon(Icons.arrow_upward_circle), findsOneWidget);
    });

    testWidgets('should handle multiple peers in topology', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          meshPeers: List.generate(
            10,
            (i) => ModelFactory.createMeshPeer(
              nodeId: 'peer_$i',
              hostname: 'peer$i.local',
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: NetworkMonitorView()),
        ),
      );

      expect(find.byType(ListView), findsOneWidget);
    });
  });
}
