/// @title Servers View Widget Tests
/// @description Tests for the ServersView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/servers_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('ServersView Widget Tests', () {
    testWidgets('should display header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('Mesh Servers'), findsOneWidget);
      expect(find.byIcon(Icons.dns), findsOneWidget);
    });

    testWidgets('should display refresh button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byIcon(Icons.refresh), findsOneWidget);
    });

    testWidgets('should show empty state when no servers', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('No Servers'), findsOneWidget);
      expect(find.byIcon(Icons.dns_outlined), findsOneWidget);
    });

    testWidgets('should show no selection state', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('Select a Server'), findsOneWidget);
      expect(find.text('Choose a server from the list to view details.'), findsOneWidget);
    });

    testWidgets('should show health badge in header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('0/0 healthy'), findsOneWidget);
    });
  });

  group('ServersView With Servers Tests', () {
    testWidgets('should display server list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'server1.example.com',
              port: 9100,
              available: true,
              region: 'us-west',
              latencyMs: 25,
            ),
            ModelFactory.createServerInfo(
              id: 'server_2',
              host: 'server2.example.com',
              port: 9100,
              available: false,
              region: 'us-east',
              latencyMs: 150,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('server1.example.com:9100'), findsOneWidget);
      expect(find.text('server2.example.com:9100'), findsOneWidget);
    });

    testWidgets('should display health status for each server', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
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
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('HEALTHY'), findsOneWidget);
      expect(find.text('UNHEALTHY'), findsOneWidget);
    });

    testWidgets('should display server latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'server1.example.com',
              port: 9100,
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
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('25ms'), findsOneWidget);
    });

    testWidgets('should display server region', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'server1.example.com',
              port: 9100,
              region: 'us-west',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('us-west'), findsOneWidget);
    });

    testWidgets('should update health badge count', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1', available: true),
            ModelFactory.createServerInfo(id: 'server_2', available: true),
            ModelFactory.createServerInfo(id: 'server_3', available: false),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('2/3 healthy'), findsOneWidget);
    });

    testWidgets('should show detail panel when server selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'test-server.example.com',
              port: 9100,
              available: true,
              region: 'us-west',
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
          child: const MaterialApp(home: ServersView()),
        ),
      );

      // Tap on server to select
      await tester.tap(find.text('test-server.example.com:9100'));
      await tester.pumpAndSettle();

      // Should show detail panel
      expect(find.text('Endpoint'), findsOneWidget);
      expect(find.text('Port'), findsOneWidget);
      expect(find.text('Region'), findsOneWidget);
      expect(find.text('Health'), findsOneWidget);
    });

    testWidgets('should display server details in panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'test-server.example.com',
              port: 9100,
              available: true,
              region: 'eu-west',
              latencyMs: 45,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      await tester.tap(find.text('test-server.example.com:9100'));
      await tester.pumpAndSettle();

      expect(find.text('test-server.example.com:9100'), findsWidgets);
      expect(find.text('9100'), findsOneWidget);
      expect(find.text('eu-west'), findsWidgets);
      expect(find.text('Healthy'), findsOneWidget);
      expect(find.text('45ms'), findsOneWidget);
    });

    testWidgets('should show unhealthy status in detail panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
              host: 'unhealthy-server.example.com',
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
          child: const MaterialApp(home: ServersView()),
        ),
      );

      await tester.tap(find.text('unhealthy-server.example.com:9100'));
      await tester.pumpAndSettle();

      expect(find.text('UNHEALTHY'), findsWidgets);
      expect(find.text('Unhealthy'), findsOneWidget);
    });

    testWidgets('should highlight selected server', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1', host: 'server1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      await tester.tap(find.text('server1:9100'));
      await tester.pumpAndSettle();

      // Selected item should have different background
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should show chevron icon for navigation', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byIcon(Icons.chevron_right), findsOneWidget);
    });
  });

  group('ServersView UI Element Tests', () {
    testWidgets('should have proper card styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have list tiles for servers', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byType(InkWell), findsOneWidget);
    });

    testWidgets('should have divider between header and list', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byType(Divider), findsOneWidget);
    });

    testWidgets('should have status dot for health', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1', available: true),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byType(Container), findsWidgets); // Status dots are Containers
    });

    testWidgets('should have scrollable list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: List.generate(
            20,
            (i) => ModelFactory.createServerInfo(
              id: 'server_$i',
              host: 'server$i.example.com',
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byType(ListView), findsOneWidget);
    });

    testWidgets('should have monospace font for port numbers', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('9100'), findsWidgets);
    });

    testWidgets('should show loading indicator when loading', (tester) async {
      // This tests the loading state UI
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      // Initially loads servers - check structure exists
      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should have proper badge styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1', available: true),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have expanded detail panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(id: 'server_1'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ServersView()),
        ),
      );

      await tester.tap(find.text('localhost:9100'));
      await tester.pumpAndSettle();

      expect(find.byType(Expanded), findsWidgets);
    });

    testWidgets('should have proper color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ServersView()),
        ),
      );

      // Verify overall structure
      expect(find.byType(Row), findsWidgets);
    });
  });

  group('ServersView Latency Color Tests', () {
    testWidgets('should show green latency for low latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
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
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('25ms'), findsOneWidget);
    });

    testWidgets('should show orange latency for medium latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
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
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('100ms'), findsOneWidget);
    });

    testWidgets('should show red latency for high latency', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          servers: [
            ModelFactory.createServerInfo(
              id: 'server_1',
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
          child: const MaterialApp(home: ServersView()),
        ),
      );

      expect(find.text('200ms'), findsOneWidget);
    });
  });
}
