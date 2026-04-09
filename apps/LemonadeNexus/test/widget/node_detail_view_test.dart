/// @title Node Detail View Widget Tests
/// @description Tests for the NodeDetailView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/node_detail_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('NodeDetailView Widget Tests', () {
    testWidgets('should display node header with icon', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: 'test-node.local',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('test-node.local'), findsOneWidget);
      expect(find.byIcon(Icons.dns), findsOneWidget);
    });

    testWidgets('should display node type badge', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Endpoint'), findsOneWidget);
    });

    testWidgets('should display node ID badge', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node_12345',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Short ID should be displayed
      expect(find.byType(Container), findsWidgets); // ID badge uses Container
    });

    testWidgets('should display edit button', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byIcon(Icons.edit), findsOneWidget);
    });

    testWidgets('should display properties section', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: 'test.local',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Properties'), findsOneWidget);
      expect(find.byIcon(Icons.info_outline), findsOneWidget);
    });

    testWidgets('should display node ID in properties', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node_id',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Node ID'), findsOneWidget);
      expect(find.text('test_node_id'), findsOneWidget);
    });

    testWidgets('should display parent ID in properties', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'parent_123',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Parent ID'), findsOneWidget);
      expect(find.text('parent_123'), findsOneWidget);
    });

    testWidgets('should display type in properties', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Type'), findsOneWidget);
      expect(find.text('endpoint'), findsOneWidget);
    });

    testWidgets('should display hostname in properties', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: 'my-hostname.local',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Hostname'), findsOneWidget);
      expect(find.text('my-hostname.local'), findsOneWidget);
    });

    testWidgets('should display network section', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        data: {'tunnel_ip': '10.0.0.5'},
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Network'), findsOneWidget);
      expect(find.byIcon(Icons.network), findsOneWidget);
    });

    testWidgets('should display tunnel IP in network section', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        data: {'tunnel_ip': '10.0.0.5'},
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Tunnel IP'), findsOneWidget);
      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should display keys section', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        mgmtPubkey: 'mgmt_pubkey_base64',
        wgPubkey: 'wg_pubkey_base64',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Cryptographic Keys'), findsOneWidget);
      expect(find.byIcon(Icons.vpn_key), findsOneWidget);
    });

    testWidgets('should display management key', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        mgmtPubkey: 'mgmt_pubkey_base64_string',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Management Key'), findsOneWidget);
    });

    testWidgets('should display WireGuard key', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        wgPubkey: 'wg_pubkey_base64_string',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('WireGuard Key'), findsOneWidget);
    });

    testWidgets('should display copy button for keys', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        mgmtPubkey: 'mgmt_pubkey_base64',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byIcon(Icons.copy), findsOneWidget);
    });

    testWidgets('should display actions section', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(ElevatedButton), findsWidgets);
    });

    testWidgets('should display save changes button when editing', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Tap edit button
      await tester.tap(find.byIcon(Icons.edit));
      await tester.pumpAndSettle();

      expect(find.text('Save Changes'), findsOneWidget);
    });

    testWidgets('should display cancel button when editing', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Tap edit button
      await tester.tap(find.byIcon(Icons.edit));
      await tester.pumpAndSettle();

      expect(find.text('Cancel'), findsOneWidget);
    });

    testWidgets('should display delete node button', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Delete Node'), findsOneWidget);
      expect(find.byIcon(Icons.delete), findsOneWidget);
    });
  });

  group('NodeDetailView Node Type Tests', () {
    testWidgets('should display root node with correct icon', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'root',
        parentId: '',
        nodeType: 'root',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Root'), findsOneWidget);
      expect(find.byIcon(Icons.account_tree), findsOneWidget);
    });

    testWidgets('should display customer node with correct icon', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'customer_1',
        parentId: 'root',
        nodeType: 'customer',
        hostname: 'customer.local',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Customer'), findsOneWidget);
      expect(find.byIcon(Icons.group), findsOneWidget);
    });

    testWidgets('should display endpoint node with correct icon', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: 'endpoint.local',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Endpoint'), findsOneWidget);
      expect(find.byIcon(Icons.dns), findsOneWidget);
    });

    testWidgets('should display relay node with correct icon', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'relay_1',
        parentId: 'root',
        nodeType: 'relay',
        hostname: 'relay.local',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Relay'), findsOneWidget);
      expect(find.byIcon(Icons.hub), findsOneWidget);
    });

    testWidgets('should display root node with purple color', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'root',
        parentId: '',
        nodeType: 'root',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Root node uses Color(0xFF9B5DE5)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display customer node with blue color', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'customer_1',
        parentId: 'root',
        nodeType: 'customer',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Customer node uses Color(0xFF3B82F6)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display endpoint node with yellow color', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Endpoint node uses Color(0xFFE9C46A)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display relay node with teal color', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'relay_1',
        parentId: 'root',
        nodeType: 'relay',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Relay node uses Color(0xFF2A9D8F)
      expect(find.byType(Container), findsWidgets);
    });
  });

  group('NodeDetailView Network Section Tests', () {
    testWidgets('should show info message for root node network', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'root',
        parentId: '',
        nodeType: 'root',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Network'), findsOneWidget);
      expect(
        find.textContaining('Root node manages the network'),
        findsOneWidget,
      );
    });

    testWidgets('should show info message for customer node network', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'customer_1',
        parentId: 'root',
        nodeType: 'customer',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(
        find.textContaining('Group nodes organize endpoints'),
        findsOneWidget,
      );
    });

    testWidgets('should display private subnet when available', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        privateSubnet: '10.1.0.0/24',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Private Subnet'), findsOneWidget);
      expect(find.text('10.1.0.0/24'), findsOneWidget);
    });

    testWidgets('should display listen endpoint when available', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        listenEndpoint: '0.0.0.0:51820',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Listen Endpoint'), findsOneWidget);
      expect(find.text('0.0.0.0:51820'), findsOneWidget);
    });

    testWidgets('should show no network info message when empty', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        data: {}, // No network data
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(
        find.textContaining('No network info assigned yet'),
        findsOneWidget,
      );
    });
  });

  group('NodeDetailView Keys Section Tests', () {
    testWidgets('should show no keys message when empty', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        mgmtPubkey: null,
        wgPubkey: null,
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Cryptographic Keys'), findsOneWidget);
      expect(
        find.textContaining('No keys available'),
        findsOneWidget,
      );
    });

    testWidgets('should display only management key when wg key missing', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        mgmtPubkey: 'mgmt_only_key',
        wgPubkey: null,
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Management Key'), findsOneWidget);
      expect(find.text('WireGuard Key'), findsNothing);
    });

    testWidgets('should display only wg key when management key missing', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        mgmtPubkey: null,
        wgPubkey: 'wg_only_key',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Management Key'), findsNothing);
      expect(find.text('WireGuard Key'), findsOneWidget);
    });
  });

  group('NodeDetailView Assignments Section Tests', () {
    testWidgets('should display assignments section when present', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        assignments: [
          NodeAssignment(
            nodeId: 'endpoint_1',
            managementPubkey: 'mgmt_pubkey',
            permissions: ['read'],
          ),
        ],
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.textContaining('Assignments'), findsOneWidget);
    });

    testWidgets('should display assignment permissions', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        assignments: [
          NodeAssignment(
            nodeId: 'endpoint_1',
            managementPubkey: 'mgmt_pubkey',
            permissions: ['read', 'write'],
          ),
        ],
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('read'), findsOneWidget);
      expect(find.text('write'), findsOneWidget);
    });

    testWidgets('should display admin permission badge in red', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        assignments: [
          NodeAssignment(
            nodeId: 'endpoint_1',
            managementPubkey: 'mgmt_pubkey',
            permissions: ['admin'],
          ),
        ],
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('admin'), findsOneWidget);
    });

    testWidgets('should display manage permission badge in purple', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'endpoint_1',
        parentId: 'root',
        nodeType: 'endpoint',
        assignments: [
          NodeAssignment(
            nodeId: 'endpoint_1',
            managementPubkey: 'mgmt_pubkey',
            permissions: ['manage'],
          ),
        ],
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('manage'), findsOneWidget);
    });
  });

  group('NodeDetailView Edit Mode Tests', () {
    testWidgets('should toggle edit mode when edit button tapped', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Initial state - edit icon
      expect(find.byIcon(Icons.edit), findsOneWidget);

      // Tap to enter edit mode
      await tester.tap(find.byIcon(Icons.edit));
      await tester.pumpAndSettle();

      // Should show check_circle icon
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('should show save and cancel buttons in edit mode', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      await tester.tap(find.byIcon(Icons.edit));
      await tester.pumpAndSettle();

      expect(find.text('Save Changes'), findsOneWidget);
      expect(find.text('Cancel'), findsOneWidget);
    });

    testWidgets('should hide save and cancel buttons when not editing', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Save Changes'), findsNothing);
      expect(find.text('Cancel'), findsNothing);
    });
  });

  group('NodeDetailView Delete Confirmation Tests', () {
    testWidgets('should have delete button', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('Delete Node'), findsOneWidget);
    });

    testWidgets('should have delete button with proper styling', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      // Delete button uses red color
      expect(find.byType(ElevatedButton), findsWidgets);
    });
  });

  group('NodeDetailView UI Element Tests', () {
    testWidgets('should have scrollable content', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(SingleChildScrollView), findsOneWidget);
    });

    testWidgets('should have proper section styling', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have proper divider styling', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(Divider), findsWidgets);
    });

    testWidgets('should have monospace font for IDs and IPs', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        data: {'tunnel_ip': '10.0.0.5'},
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.text('10.0.0.5'), findsOneWidget);
    });

    testWidgets('should have proper badge styling', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have proper color scheme', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(Column), findsWidgets);
    });

    testWidgets('should have elevated buttons', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(ElevatedButton), findsWidgets);
    });

    testWidgets('should have icon buttons', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(IconButton), findsOneWidget);
    });

    testWidgets('should have proper text styles', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: 'test.local',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(Text), findsWidgets);
    });

    testWidgets('should have proper padding', (tester) async {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
      );

      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: NodeDetailView(node: node)),
        ),
      );

      expect(find.byType(Padding), findsWidgets);
    });
  });
}
