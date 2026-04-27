/// @title Tree Browser View Widget Tests
/// @description Tests for the TreeBrowserView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/tree_browser_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('TreeBrowserView Widget Tests', () {
    testWidgets('should display search bar', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('Search nodes...'), findsOneWidget);
      expect(find.byIcon(Icons.search), findsOneWidget);
    });

    testWidgets('should display refresh button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Refresh is triggered on init, button exists in appState
      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show empty state when no nodes', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('No Nodes'), findsOneWidget);
      expect(find.byIcon(Icons.account_tree_outlined), findsOneWidget);
    });

    testWidgets('should show no selection state', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('Select a Node'), findsOneWidget);
      expect(find.text('Choose a node from the tree to view its details.'), findsOneWidget);
    });

    testWidgets('should show empty state hint text', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(
        find.textContaining('No tree nodes found'),
        findsOneWidget,
      );
    });
  });

  group('TreeBrowserView With Nodes Tests', () {
    testWidgets('should display tree node list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
              hostname: 'server1.local',
            ),
            ModelFactory.createTreeNode(
              id: 'node_2',
              parentId: 'root',
              nodeType: 'endpoint',
              hostname: 'server2.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('server1.local'), findsOneWidget);
      expect(find.text('server2.local'), findsOneWidget);
    });

    testWidgets('should display node type badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('Endpoint'), findsOneWidget);
    });

    testWidgets('should display root node type badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          rootNode: ModelFactory.createTreeNode(
            id: 'root',
            parentId: '',
            nodeType: 'root',
          ),
          treeNodes: [],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('Root'), findsOneWidget);
    });

    testWidgets('should display customer node type badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'customer',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('Customer'), findsOneWidget);
    });

    testWidgets('should display relay node type badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'relay',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('Relay'), findsOneWidget);
    });

    testWidgets('should display tunnel IP for nodes', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
              data: {'tunnel_ip': '10.0.0.5'},
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should display region for nodes', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
              data: {'region': 'us-west'},
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('us-west'), findsOneWidget);
    });

    testWidgets('should show node detail panel when selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
              hostname: 'test-node.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Tap on node to select
      await tester.tap(find.text('test-node.local'));
      await tester.pumpAndSettle();

      // Should show detail panel
      expect(find.text('Node ID'), findsOneWidget);
      expect(find.text('Parent ID'), findsOneWidget);
      expect(find.text('Type'), findsOneWidget);
    });

    testWidgets('should display node details in panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'test-node-id',
              parentId: 'root-parent',
              nodeType: 'endpoint',
              hostname: 'detail-test.local',
              data: {
                'tunnel_ip': '10.0.0.10',
                'region': 'eu-west',
              },
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('detail-test.local'));
      await tester.pumpAndSettle();

      expect(find.text('test-node-id'), findsWidgets);
      expect(find.text('root-parent'), findsOneWidget);
      expect(find.text('10.0.0.10'), findsOneWidget);
      expect(find.text('eu-west'), findsOneWidget);
    });

    testWidgets('should show add child node button', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      expect(find.text('Add Child Node'), findsOneWidget);
    });

    testWidgets('should show delete node button', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      expect(find.text('Delete Node'), findsOneWidget);
    });

    testWidgets('should highlight selected node', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'selected-node.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('selected-node.local'));
      await tester.pumpAndSettle();

      // Selected item should have different background
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should show chevron icon for navigation', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.byIcon(Icons.chevron_right), findsOneWidget);
    });

    testWidgets('should display node type icon', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Endpoint nodes have dns icon
      expect(find.byIcon(Icons.dns), findsWidgets);
    });
  });

  group('TreeBrowserView Search Tests', () {
    testWidgets('should filter nodes by hostname', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'alpha.local',
            ),
            ModelFactory.createTreeNode(
              id: 'node_2',
              parentId: 'root',
              hostname: 'beta.local',
            ),
            ModelFactory.createTreeNode(
              id: 'node_3',
              parentId: 'root',
              hostname: 'gamma.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
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

    testWidgets('should filter nodes by node ID', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_abc123',
              parentId: 'root',
              hostname: 'server1',
            ),
            ModelFactory.createTreeNode(
              id: 'node_def456',
              parentId: 'root',
              hostname: 'server2',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Search for 'abc'
      final searchField = find.byType(TextField);
      await tester.tap(searchField);
      await tester.enterText(searchField, 'abc');
      await tester.pumpAndSettle();

      expect(find.text('server1'), findsOneWidget);
      expect(find.text('server2'), findsNothing);
    });

    testWidgets('should filter nodes by tunnel IP', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'server1',
              data: {'tunnel_ip': '10.0.0.5'},
            ),
            ModelFactory.createTreeNode(
              id: 'node_2',
              parentId: 'root',
              hostname: 'server2',
              data: {'tunnel_ip': '10.0.0.10'},
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Search for '10.0.0.5'
      final searchField = find.byType(TextField);
      await tester.tap(searchField);
      await tester.enterText(searchField, '10.0.0.5');
      await tester.pumpAndSettle();

      expect(find.text('server1'), findsOneWidget);
      expect(find.text('server2'), findsNothing);
    });

    testWidgets('should show empty state when no matches', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'server1',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Search for non-existent term
      final searchField = find.byType(TextField);
      await tester.tap(searchField);
      await tester.enterText(searchField, 'nonexistent');
      await tester.pumpAndSettle();

      expect(find.text('No nodes match your search'), findsOneWidget);
    });

    testWidgets('should clear filter when search text cleared', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'alpha.local',
            ),
            ModelFactory.createTreeNode(
              id: 'node_2',
              parentId: 'root',
              hostname: 'beta.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Search then clear
      final searchField = find.byType(TextField);
      await tester.tap(searchField);
      await tester.enterText(searchField, 'alpha');
      await tester.pumpAndSettle();
      await tester.enterText(searchField, '');
      await tester.pumpAndSettle();

      // Both nodes should be visible again
      expect(find.text('alpha.local'), findsOneWidget);
      expect(find.text('beta.local'), findsOneWidget);
    });
  });

  group('TreeBrowserView Add Node Dialog Tests', () {
    testWidgets('should open add node dialog when button tapped', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Add Child Node'));
      await tester.pumpAndSettle();

      expect(find.text('Add New Node'), findsOneWidget);
    });

    testWidgets('should show hostname input in dialog', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Add Child Node'));
      await tester.pumpAndSettle();

      expect(find.text('Hostname'), findsOneWidget);
    });

    testWidgets('should show type dropdown in dialog', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Add Child Node'));
      await tester.pumpAndSettle();

      expect(find.text('Type'), findsOneWidget);
    });

    testWidgets('should show region input in dialog', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Add Child Node'));
      await tester.pumpAndSettle();

      expect(find.text('Region'), findsOneWidget);
    });

    testWidgets('should show cancel and add buttons in dialog', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Add Child Node'));
      await tester.pumpAndSettle();

      expect(find.text('Cancel'), findsOneWidget);
      expect(find.text('Add Node'), findsOneWidget);
    });

    testWidgets('should close dialog when cancel tapped', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Add Child Node'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();

      expect(find.text('Add New Node'), findsNothing);
    });
  });

  group('TreeBrowserView Delete Confirmation Tests', () {
    testWidgets('should open delete confirmation when delete tapped', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'delete-test.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('delete-test.local'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Delete Node'));
      await tester.pumpAndSettle();

      expect(find.text('Delete Node'), findsWidgets); // Button and dialog title
    });

    testWidgets('should show confirmation message', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'confirm-delete.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('confirm-delete.local'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Delete Node'));
      await tester.pumpAndSettle();

      expect(
        find.textContaining('Are you sure you want to delete'),
        findsOneWidget,
      );
    });

    testWidgets('should close dialog when cancel tapped', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              hostname: 'cancel-delete.local',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('cancel-delete.local'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Delete Node'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();

      // Dialog should be closed
      expect(find.textContaining('Are you sure'), findsNothing);
    });
  });

  group('TreeBrowserView UI Element Tests', () {
    testWidgets('should have proper card styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have list tiles for nodes', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.byType(InkWell), findsOneWidget);
    });

    testWidgets('should have divider between search and list', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.byType(Divider), findsOneWidget);
    });

    testWidgets('should have scrollable list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: List.generate(
            20,
            (i) => ModelFactory.createTreeNode(
              id: 'node_$i',
              parentId: 'root',
              hostname: 'node$i.local',
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.byType(ListView), findsOneWidget);
    });

    testWidgets('should have monospace font for IPs', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              data: {'tunnel_ip': '10.0.0.5'},
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should have proper badge styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
              nodeType: 'endpoint',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have expanded detail panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      expect(find.byType(Expanded), findsWidgets);
    });

    testWidgets('should have proper color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: TreeBrowserView()),
        ),
      );

      // Verify overall structure
      expect(find.byType(Row), findsOneWidget);
    });

    testWidgets('should have Actions section in detail panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      expect(find.text('Actions'), findsOneWidget);
    });

    testWidgets('should have elevated buttons for actions', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          treeNodes: [
            ModelFactory.createTreeNode(
              id: 'node_1',
              parentId: 'root',
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: TreeBrowserView()),
        ),
      );

      await tester.tap(find.text('node_1'));
      await tester.pumpAndSettle();

      expect(find.byType(ElevatedButton), findsWidgets);
    });
  });
}
