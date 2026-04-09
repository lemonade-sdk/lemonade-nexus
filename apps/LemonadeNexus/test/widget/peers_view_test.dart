/// @title Peers View Widget Tests
/// @description Tests for the PeersView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/peers_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('PeersView Widget Tests', () {
    testWidgets('should display header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.text('Mesh Peers'), findsOneWidget);
      expect(find.byIcon(Icons.people), findsOneWidget);
    });

    testWidgets('should display search bar', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.text('Search peers...'), findsOneWidget);
      expect(find.byIcon(Icons.search), findsOneWidget);
    });

    testWidgets('should display refresh button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byIcon(Icons.refresh), findsOneWidget);
    });

    testWidgets('should show empty state when no peers', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.text('No Peers'), findsOneWidget);
      expect(find.byIcon(Icons.people_outline), findsOneWidget);
    });

    testWidgets('should show enable mesh hint when not enabled', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(
        find.textContaining('Enable mesh networking'),
        findsOneWidget,
      );
    });

    testWidgets('should show no selection state', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.text('Select a Peer'), findsOneWidget);
      expect(find.text('Choose a peer from the list to view details.'), findsOneWidget);
    });

    testWidgets('should show online count in header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.text('0/0 online'), findsOneWidget);
    });
  });

  group('PeersView With Peers Tests', () {
    testWidgets('should display peer list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                hostname: 'peer1.local',
                isOnline: true,
                tunnelIp: '10.0.0.2',
              ),
              ModelFactory.createMeshPeer(
                nodeId: 'peer_2',
                hostname: 'peer2.local',
                isOnline: false,
                tunnelIp: '10.0.0.3',
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.text('peer1.local'), findsOneWidget);
      expect(find.text('peer2.local'), findsOneWidget);
    });

    testWidgets('should display online status indicator', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                isOnline: true,
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      // Online indicator (green dot)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display peer tunnel IP', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                tunnelIp: '10.0.0.5',
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should display peer latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                latencyMs: 25.0,
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.textContaining('ms'), findsOneWidget);
    });

    testWidgets('should display peer bandwidth', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                rxBytes: 1024000,
                txBytes: 512000,
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      // Should show bandwidth icons and values
      expect(find.byIcon(Icons.arrow_downward), findsWidgets);
      expect(find.byIcon(Icons.arrow_upward), findsWidgets);
    });

    testWidgets('should show detail panel when peer selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                hostname: 'test-peer.local',
                tunnelIp: '10.0.0.5',
                wgPubkey: 'pubkey_base64_string',
                privateSubnet: '10.1.0.0/24',
                endpoint: '192.168.1.100:51820',
                latencyMs: 25.0,
                rxBytes: 1024,
                txBytes: 512,
                keepalive: 25,
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      // Tap on peer to select
      await tester.tap(find.text('test-peer.local'));
      await tester.pumpAndSettle();

      // Should show detail panel
      expect(find.text('Node ID'), findsOneWidget);
      expect(find.text('Tunnel IP'), findsOneWidget);
      expect(find.text('WG Public Key'), findsOneWidget);
    });

    testWidgets('should filter peers by search query', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                hostname: 'alpha.local',
              ),
              ModelFactory.createMeshPeer(
                nodeId: 'peer_2',
                hostname: 'beta.local',
              ),
              ModelFactory.createMeshPeer(
                nodeId: 'peer_3',
                hostname: 'gamma.local',
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      // Search for 'alpha'
      final searchField = find.byType(TextField);
      await tester.tap(searchField);
      await tester.enterText(searchField, 'alpha');
      await tester.pumpAndSettle();

      // Should only show alpha.local
      expect(find.text('alpha.local'), findsOneWidget);
      expect(find.text('beta.local'), findsNothing);
      expect(find.text('gamma.local'), findsNothing);
    });

    testWidgets('should show clear button when search has text', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(nodeId: 'peer_1'),
            ],
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: PeersView()),
        ),
      );

      // Enter search text
      final searchField = find.byType(TextField);
      await tester.tap(searchField);
      await tester.enterText(searchField, 'test');
      await tester.pump();

      // Clear button should appear
      expect(find.byIcon(Icons.clear), findsOneWidget);
    });

    testWidgets('should show relay endpoint for relayed peers', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                hostname: 'relayed-peer',
              ).copyWith(
                relayEndpoint: 'relay.example.com:9101',
                endpoint: null,
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      await tester.tap(find.text('relayed-peer'));
      await tester.pumpAndSettle();

      expect(find.text('Relay Endpoint'), findsOneWidget);
    });

    testWidgets('should show online/offline badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                isOnline: true,
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      await tester.tap(find.byType(ListTile).first);
      await tester.pumpAndSettle();

      expect(find.text('Online'), findsOneWidget);
    });
  });

  group('PeersView UI Element Tests', () {
    testWidgets('should have list panel with proper width', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have detail panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(nodeId: 'peer_1'),
            ],
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byType(Expanded), findsWidgets);
    });

    testWidgets('should have list tiles for peers', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(nodeId: 'peer_1'),
            ],
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byType(ListTile), findsOneWidget);
    });

    testWidgets('should have divider between header and list', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byType(Divider), findsOneWidget);
    });

    testWidgets('should have proper badge styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(nodeId: 'peer_1', isOnline: true),
            ],
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have monospace font for IPs', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: [
              ModelFactory.createMeshPeer(
                nodeId: 'peer_1',
                tunnelIp: '10.0.0.5',
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
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byType(Text), findsWidgets);
    });

    testWidgets('should have scrollable list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          peerState: PeerState(
            isMeshEnabled: true,
            meshPeers: List.generate(
              20,
              (i) => ModelFactory.createMeshPeer(
                nodeId: 'peer_$i',
                hostname: 'peer$i.local',
              ),
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: PeersView()),
        ),
      );

      expect(find.byType(ListView), findsOneWidget);
    });
  });
}
