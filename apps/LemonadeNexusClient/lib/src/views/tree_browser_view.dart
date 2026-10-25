/// @title Tree Browser View
/// @description CRDT tree browser and editor.
///
/// Matches macOS TreeBrowserView.swift functionality:
/// - Tree node list with search
/// - Node detail panel
/// - Add node sheet
/// - Delete node confirmation
/// - Auto-refresh tree structure
library;

import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../state/cluster_keyring.dart' show canonicalPrincipal;
import '../sdk/lemonade_nexus_sdk.dart' show SdkException;
import '../sdk/models.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';
import 'invite_member_dialog.dart';
import 'networks_dialog.dart';

class TreeBrowserView extends ConsumerStatefulWidget {
  const TreeBrowserView({super.key});

  @override
  ConsumerState<TreeBrowserView> createState() => _TreeBrowserViewState();
}

class _TreeBrowserViewState extends ConsumerState<TreeBrowserView> {
  final _searchController = TextEditingController();
  String _searchText = '';
  TreeNode? _selectedNode;
  bool _isLoadingTree = false;
  List<TreeNode> _localTreeNodes = [];

  List<TreeNode> get filteredNodes {
    if (_searchText.isEmpty) {
      return _localTreeNodes;
    }
    return _localTreeNodes.where((node) {
      final hostname = node.data['hostname']?.toString() ?? '';
      final nodeId = node.id;
      final nodeType = node.nodeType;
      final tunnelIp = node.data['tunnel_ip']?.toString() ?? '';
      final region = node.data['region']?.toString() ?? '';

      return hostname.toLowerCase().contains(_searchText.toLowerCase()) ||
          nodeId.toLowerCase().contains(_searchText.toLowerCase()) ||
          nodeType.toLowerCase().contains(_searchText.toLowerCase()) ||
          tunnelIp.toLowerCase().contains(_searchText.toLowerCase()) ||
          region.toLowerCase().contains(_searchText.toLowerCase());
    }).toList();
  }

  @override
  void initState() {
    super.initState();
    // Defer the first fetch until after the view paints — the native call is
    // synchronous and would otherwise block (freeze) the navigation transition.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _loadTree();
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadTree() async {
    setState(() => _isLoadingTree = true);
    final notifier = ref.read(appNotifierProvider.notifier);
    await notifier.loadTree();
    if (notifier.currentState.rootNode != null) {
      setState(() {
        _localTreeNodes = [
          notifier.currentState.rootNode!,
          ...notifier.currentState.treeNodes,
        ];
      });
    }
    setState(() => _isLoadingTree = false);
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final scheme = Theme.of(context).colorScheme;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Tree List Panel
        Container(
          width: 350,
          decoration: BoxDecoration(
            color: scheme.surface,
            border: Border(right: BorderSide(color: scheme.outline, width: 1)),
          ),
          child: Column(
            children: [
              // Search Bar + invite
              Padding(
                padding: const EdgeInsets.all(12),
                child: Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _searchController
                          ..addListener(() => setState(() => _searchText = _searchController.text)),
                        decoration: const InputDecoration(
                          hintText: 'Search nodes...',
                          prefixIcon: Icon(Icons.search, size: 20),
                          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        ),
                        style: const TextStyle(fontSize: 13),
                      ),
                    ),
                    const SizedBox(width: 8),
                    IconButton.filled(
                      tooltip: 'Invite member',
                      icon: const Icon(Icons.add, size: 20),
                      style: IconButton.styleFrom(
                        backgroundColor: AppTheme.lemonYellowDark,
                        foregroundColor: Colors.black,
                      ),
                      onPressed: () => showInviteMemberDialog(context),
                    ),
                    const SizedBox(width: 4),
                    IconButton(
                      tooltip: 'Join another network',
                      icon: const Icon(Icons.hub_outlined, size: 20),
                      onPressed: () async {
                        await showNetworksDialog(context);
                        if (mounted) _loadTree();
                      },
                    ),
                  ],
                ),
              ),
              Divider(color: scheme.outline, height: 1),
              // List
              Expanded(
                child: _isLoadingTree
                    ? const Center(child: CircularProgressIndicator())
                    : filteredNodes.isEmpty
                        ? _buildEmptyState()
                        : ListView.builder(
                            padding: const EdgeInsets.all(8),
                            itemCount: filteredNodes.length,
                            itemBuilder: (context, index) => _buildNodeRow(filteredNodes[index]),
                          ),
              ),
            ],
          ),
        ),
        // Detail Panel
        Expanded(
          child: _selectedNode != null
              ? _buildDetailPanel(appState, _selectedNode!)
              : _buildNoSelectionState(),
        ),
      ],
    );
  }

  Widget _buildEmptyState() {
    return EmptyState(
      icon: Icons.account_tree,
      title: 'No Nodes',
      message: _searchText.isEmpty
          ? 'No tree nodes found. The network tree may be empty.'
          : 'No nodes match your search.',
    );
  }

  Widget _buildNodeRow(TreeNode node) {
    final isSelected = _selectedNode?.id == node.id;
    final nodeType = NodeType.fromRaw(node.nodeType);
    final scheme = Theme.of(context).colorScheme;

    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2, horizontal: 4),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isSelected
            ? AppTheme.lemonYellowDark.withValues(alpha: 0.15)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: InkWell(
        onTap: () => setState(() => _selectedNode = node),
        onSecondaryTapDown: (details) => _showNodeMenu(node, details.globalPosition),
        onLongPress: () {
          final box = context.findRenderObject() as RenderBox?;
          _showNodeMenu(node, box?.localToGlobal(Offset.zero) ?? Offset.zero);
        },
        child: Row(
          children: [
            Icon(
              nodeType.icon,
              color: _nodeColor(nodeType),
              size: 24,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    node.data['hostname']?.toString() ?? node.id,
                    style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      LemonBadge(text: nodeType.displayName, color: _nodeColor(nodeType)),
                      if (node.data['tunnel_ip'] != null) ...[
                        const SizedBox(width: 8),
                        Text(
                          node.data['tunnel_ip'] as String,
                          style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 10, fontFamily: 'monospace'),
                        ),
                      ],
                      if (node.data['region'] != null) ...[
                        const SizedBox(width: 8),
                        Icon(Icons.public, size: 10, color: scheme.onSurfaceVariant),
                        const SizedBox(width: 2),
                        Text(
                          node.data['region'] as String,
                          style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 10),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: scheme.onSurfaceVariant, size: 16),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailPanel(AppState appState, TreeNode node) {
    final nodeType = NodeType.fromRaw(node.nodeType);
    final scheme = Theme.of(context).colorScheme;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              Container(
                width: 56,
                height: 56,
                decoration: BoxDecoration(
                  color: _nodeColor(nodeType).withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(
                  nodeType.icon,
                  color: _nodeColor(nodeType),
                  size: 28,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      node.data['hostname']?.toString() ?? node.id,
                      style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 4),
                    LemonBadge(text: nodeType.displayName, color: _nodeColor(nodeType)),
                  ],
                ),
              ),
            ],
          ),
          Divider(color: scheme.outline, height: 24),
          // Details
          _buildDetailRow('Node ID', node.id),
          _buildDetailRow('Parent ID', node.parentId),
          _buildDetailRow('Owner ID', node.ownerId),
          _buildDetailRow('Type', node.nodeType),
          if (node.data['hostname'] != null) _buildDetailRow('Hostname', node.data['hostname'] as String),
          if (node.data['tunnel_ip'] != null) _buildDetailRow('Tunnel IP', node.data['tunnel_ip'] as String),
          if (node.data['region'] != null) _buildDetailRow('Region', node.data['region'] as String),
          _buildDetailRow('Version', '${node.version}'),
          _buildDetailRow('Created', node.createdAt),
          _buildDetailRow('Updated', node.updatedAt),
          // Actions
          const SizedBox(height: 24),
          const SectionHeader(title: 'Actions', icon: Icons.bolt_outlined),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () => _showAddNodeDialog(node.id),
                  icon: const Icon(Icons.add),
                  label: const Text('Add Child Node'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _confirmDeleteNode(node),
                  icon: const Icon(Icons.delete),
                  label: const Text('Delete Node'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppTheme.errorColor,
                    side: const BorderSide(color: AppTheme.errorColor, width: 1.5),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildNoSelectionState() {
    return const EmptyState(
      icon: Icons.account_tree,
      title: 'Select a Node',
      message: 'Choose a node from the tree to view its details.',
    );
  }

  Widget _buildDetailRow(String label, String value) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 100, child: Text(label, style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13))),
          Expanded(child: Text(value, style: const TextStyle(fontSize: 13, fontFamily: 'monospace'))),
        ],
      ),
    );
  }

  Color _nodeColor(NodeType type) {
    switch (type) {
      case NodeType.root:
        return AppTheme.infoColor;
      case NodeType.customer:
        return AppTheme.infoColor;
      case NodeType.endpoint:
        return AppTheme.lemonYellowDark;
      case NodeType.relay:
        return AppTheme.lemonGreen;
    }
  }

  void _showAddNodeDialog(String parentId) {
    final hostnameController = TextEditingController(text: _generateHostname());
    String selectedType = 'endpoint';
    String region = _detectRegion();

    showDialog(
      context: context,
      builder: (context) {
        final scheme = Theme.of(context).colorScheme;
        return StatefulBuilder(
          builder: (context, setDialogState) => AlertDialog(
            backgroundColor: scheme.surface,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
              side: BorderSide(color: scheme.outline),
            ),
            title: const Text('Add New Node'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: hostnameController,
                  decoration: const InputDecoration(labelText: 'Hostname'),
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<String>(
                  initialValue: selectedType,
                  decoration: const InputDecoration(labelText: 'Type'),
                  dropdownColor: scheme.surface,
                  items: const [
                    DropdownMenuItem(value: 'root', child: Text('Root')),
                    DropdownMenuItem(value: 'customer', child: Text('Customer')),
                    DropdownMenuItem(value: 'endpoint', child: Text('Endpoint')),
                    DropdownMenuItem(value: 'relay', child: Text('Relay')),
                  ],
                  onChanged: (value) => setDialogState(() => selectedType = value!),
                ),
                const SizedBox(height: 12),
                TextField(
                  decoration: const InputDecoration(labelText: 'Region'),
                  controller: TextEditingController(text: region),
                ),
                const SizedBox(height: 12),
                Text('Parent ID: $parentId', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11, fontFamily: 'monospace')),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Cancel'),
              ),
              ElevatedButton(
                onPressed: () async {
                  Navigator.pop(context);
                  final notifier = ref.read(appNotifierProvider.notifier);
                  await notifier.createChildNode(
                    parentId: parentId,
                    nodeType: selectedType,
                    hostname: hostnameController.text.isEmpty ? null : hostnameController.text,
                  );
                  _loadTree();
                },
                child: const Text('Add Node'),
              ),
            ],
          ),
        );
      },
    );
  }

  /// This account's own permissions on [node] (the tree returns this
  /// account's entry even when it hides the others).
  Set<String> _ownPermissions(TreeNode node) {
    final own = ref.read(appNotifierProvider).publicKeyBase64;
    if (own == null || own.isEmpty) return {};
    final canon = canonicalPrincipal(own);
    return {
      for (final a in node.assignments ?? const <NodeAssignment>[])
        if (canonicalPrincipal(a.managementPubkey) == canon) ...a.permissions,
    };
  }

  /// True when this account holds admin on [node] or a loaded ancestor.
  bool _administers(TreeNode node) {
    final byId = {for (final n in _localTreeNodes) n.id: n};
    final seen = <String>{};
    TreeNode? current = node;
    while (current != null && seen.add(current.id)) {
      if (_ownPermissions(current).contains('admin')) return true;
      current = byId[current.parentId];
    }
    return false;
  }

  /// The server makes the final decision; these only decide which menu
  /// entries are enabled.
  bool _canInviteInto(TreeNode node) =>
      node.nodeType == 'customer' &&
      (_ownPermissions(node).contains('add_child') || _administers(node));

  bool _canMove(TreeNode node) {
    if (node.nodeType == 'endpoint') {
      return _ownPermissions(node).contains('delete_node') || _administers(node);
    }
    if (node.nodeType == 'customer') {
      final parent = _localTreeNodes.where((n) => n.id == node.parentId);
      final topLevel = parent.isEmpty || parent.first.nodeType == 'root';
      return !topLevel && _administers(node);
    }
    return false;
  }

  Future<void> _showNodeMenu(TreeNode node, Offset position) async {
    final name = node.data['hostname']?.toString() ?? node.hostname ?? node.id;
    final choice = await showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(position.dx, position.dy, position.dx, position.dy),
      items: [
        if (node.nodeType == 'customer')
          PopupMenuItem(
            value: 'invite',
            enabled: _canInviteInto(node),
            child: const ListTile(
              dense: true,
              leading: Icon(Icons.person_add_alt_1, size: 18),
              title: Text('Invite user to group'),
            ),
          ),
        if (node.nodeType == 'customer' || node.nodeType == 'endpoint')
          PopupMenuItem(
            value: 'move',
            enabled: _canMove(node),
            child: const ListTile(
              dense: true,
              leading: Icon(Icons.drive_file_move_outline, size: 18),
              title: Text('Move to group…'),
            ),
          ),
      ],
    );
    if (!mounted || choice == null) return;
    if (choice == 'invite') {
      await showInviteMemberDialog(context, targetNodeId: node.id, targetLabel: name);
    } else if (choice == 'move') {
      await _showMoveDialog(node);
    }
  }

  /// Groups [node] may move under: every loaded group except its current
  /// parent, itself, and its descendants. The server checks the rights.
  List<TreeNode> _moveTargets(TreeNode node) {
    final byId = {for (final n in _localTreeNodes) n.id: n};
    bool under(TreeNode candidate) {
      final seen = <String>{};
      TreeNode? current = candidate;
      while (current != null && seen.add(current.id)) {
        if (current.id == node.id) return true;
        current = byId[current.parentId];
      }
      return false;
    }

    return _localTreeNodes
        .where((n) => n.nodeType == 'customer' && n.id != node.parentId && !under(n))
        .toList();
  }

  Future<void> _showMoveDialog(TreeNode node) async {
    final targets = _moveTargets(node);
    final target = await showDialog<TreeNode>(
      context: context,
      builder: (context) {
        final scheme = Theme.of(context).colorScheme;
        return SimpleDialog(
          backgroundColor: scheme.surface,
          title: Text('Move "${node.data['hostname'] ?? node.id}" to group'),
          children: targets.isEmpty
              ? [
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: Text('No other group is available.',
                        style: TextStyle(color: scheme.onSurfaceVariant)),
                  ),
                ]
              : [
                  for (final t in targets)
                    SimpleDialogOption(
                      onPressed: () => Navigator.pop(context, t),
                      child: Text(t.data['hostname']?.toString() ?? t.hostname ?? t.id),
                    ),
                ],
        );
      },
    );
    if (!mounted || target == null) return;
    try {
      await ref.read(appNotifierProvider.notifier).moveNode(node.id, target.id);
      await _loadTree();
    } catch (e) {
      if (!mounted) return;
      final reason = e is SdkException ? (e.message ?? e.toString()) : e.toString();
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Could not move the node: $reason'),
        backgroundColor: AppTheme.errorColor,
      ));
    }
  }

  void _confirmDeleteNode(TreeNode node) {
    showDialog(
      context: context,
      builder: (context) {
        final scheme = Theme.of(context).colorScheme;
        return AlertDialog(
          backgroundColor: scheme.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: scheme.outline),
          ),
          title: const Text('Delete Node'),
          content: Text(
            "Are you sure you want to delete \"${node.data['hostname'] ?? node.id}\"?",
            style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () async {
                Navigator.pop(context);
                final notifier = ref.read(appNotifierProvider.notifier);
                await notifier.deleteNode(nodeId: node.id);
                setState(() {
                  _selectedNode = null;
                  _localTreeNodes.removeWhere((n) => n.id == node.id);
                });
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.errorColor,
                foregroundColor: Colors.white,
              ),
              child: const Text('Delete'),
            ),
          ],
        );
      },
    );
  }

  String _generateHostname() {
    final base = DateTime.now().millisecondsSinceEpoch.toString().substring(5);
    final suffix = Random().nextInt(9000) + 1000;
    return 'node-$base-$suffix';
  }

  String _detectRegion() {
    final tz = DateTime.now().timeZoneName.toLowerCase();
    if (tz.contains('america/los_angeles') || tz.contains('america/denver') ||
        tz.contains('america/phoenix') || tz.contains('america/anchorage')) {
      return 'us-west';
    } else if (tz.contains('america/chicago') || tz.contains('america/indiana')) {
      return 'us-central';
    } else if (tz.contains('america/new_york') || tz.contains('america/detroit')) {
      return 'us-east';
    } else if (tz.contains('europe/')) {
      return 'eu-west';
    } else if (tz.contains('asia/tokyo') || tz.contains('asia/seoul')) {
      return 'ap-northeast';
    } else if (tz.contains('asia/')) {
      return 'ap-southeast';
    } else if (tz.contains('australia/') || tz.contains('pacific/auckland')) {
      return 'ap-south';
    } else if (tz.contains('america/sao_paulo') || tz.contains('america/argentina')) {
      return 'sa-east';
    }
    return 'unknown';
  }
}

/// Node type enumeration matching macOS
enum NodeType {
  root,
  customer,
  endpoint,
  relay;

  String get displayName {
    switch (this) {
      case root:
        return 'Root';
      case customer:
        return 'Customer';
      case endpoint:
        return 'Endpoint';
      case relay:
        return 'Relay';
    }
  }

  IconData get icon {
    switch (this) {
      case root:
        return Icons.account_tree;
      case customer:
        return Icons.group;
      case endpoint:
        return Icons.dns;
      case relay:
        return Icons.hub;
    }
  }

  static NodeType fromRaw(String raw) {
    switch (raw.toLowerCase()) {
      case 'root':
        return NodeType.root;
      case 'customer':
        return NodeType.customer;
      case 'endpoint':
        return NodeType.endpoint;
      case 'relay':
        return NodeType.relay;
      default:
        return NodeType.endpoint;
    }
  }
}
