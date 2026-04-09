/// @title Tree Browser View
/// @description CRDT tree browser and editor.
///
/// Matches macOS TreeBrowserView.swift functionality:
/// - Tree node list with search
/// - Node detail panel
/// - Add node sheet
/// - Delete node confirmation
/// - Auto-refresh tree structure

import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';

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
  bool _showingAddSheet = false;
  bool _showingDeleteConfirmation = false;
  String _rootId = 'root';
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
    _loadTree();
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
    if (notifier.state.rootNode != null) {
      setState(() {
        _localTreeNodes = [notifier.state.rootNode!, ...notifier.state.treeNodes];
      });
    }
    setState(() => _isLoadingTree = false);
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);

    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Tree List Panel
        Container(
          width: 350,
          decoration: const BoxDecoration(
            color: Color(0xFF1A1A2E),
            border: Border(right: BorderSide(color: Color(0xFF2D3748), width: 1)),
          ),
          child: Column(
            children: [
              // Search Bar
              Padding(
                padding: const EdgeInsets.all(12),
                child: TextField(
                  controller: _searchController
                    ..addListener(() => setState(() => _searchText = _searchController.text)),
                  decoration: InputDecoration(
                    hintText: 'Search nodes...',
                    hintStyle: TextStyle(color: Colors.white.withOpacity(0.4)),
                    prefixIcon: const Icon(Icons.search, color: Color(0xFF718096), size: 20),
                    filled: true,
                    fillColor: const Color(0xFF2D3748),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                      borderSide: BorderSide.none,
                    ),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  ),
                  style: const TextStyle(color: Colors.white, fontSize: 13),
                ),
              ),
              const Divider(color: Color(0xFF2D3748), height: 1),
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
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.account_tree_outlined, size: 48, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('No Nodes', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text(
              _searchText.isEmpty
                  ? 'No tree nodes found. The network tree may be empty.'
                  : 'No nodes match your search.',
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNodeRow(TreeNode node) {
    final isSelected = _selectedNode?.id == node.id;
    final nodeType = NodeType.fromRaw(node.nodeType);

    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2, horizontal: 4),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isSelected ? const Color(0xFFE9C46A).withOpacity(0.15) : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: InkWell(
        onTap: () => setState(() => _selectedNode = node),
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
                    style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      _buildBadge(text: nodeType.displayName, color: _nodeColor(nodeType)),
                      if (node.data['tunnel_ip'] != null) ...[
                        const SizedBox(width: 8),
                        Text(
                          node.data['tunnel_ip'] as String,
                          style: const TextStyle(color: Color(0xFF718096), fontSize: 10, fontFamily: 'monospace'),
                        ),
                      ],
                      if (node.data['region'] != null) ...[
                        const SizedBox(width: 8),
                        Icon(Icons.public, size: 10, color: const Color(0xFF718096)),
                        const SizedBox(width: 2),
                        Text(
                          node.data['region'] as String,
                          style: const TextStyle(color: Color(0xFF718096), fontSize: 10),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: Color(0xFF718096), size: 16),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailPanel(AppState appState, TreeNode node) {
    final nodeType = NodeType.fromRaw(node.nodeType);

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
                  color: _nodeColor(nodeType).withOpacity(0.15),
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
                      style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 4),
                    _buildBadge(text: nodeType.displayName, color: _nodeColor(nodeType)),
                  ],
                ),
              ),
            ],
          ),
          const Divider(color: Color(0xFF2D3748), height: 24),
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
          const Text('Actions', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () => _showAddNodeDialog(appState, node.id),
                  icon: const Icon(Icons.add),
                  label: const Text('Add Child Node'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFE9C46A),
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () => _confirmDeleteNode(appState, node),
                  icon: const Icon(Icons.delete),
                  label: const Text('Delete Node'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.red.shade600,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
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
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.account_tree_outlined, size: 64, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('Select a Node', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Text('Choose a node from the tree to view its details.', style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 14), textAlign: TextAlign.center),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 100, child: Text(label, style: const TextStyle(color: Color(0xFF718096), fontSize: 13))),
          Expanded(child: Text(value, style: const TextStyle(color: Colors.white, fontSize: 13, fontFamily: 'monospace'))),
        ],
      ),
    );
  }

  Widget _buildBadge({required String text, required Color color}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        text,
        style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.bold),
      ),
    );
  }

  Color _nodeColor(NodeType type) {
    switch (type) {
      case NodeType.root:
        return const Color(0xFF9B5DE5);
      case NodeType.customer:
        return const Color(0xFF3B82F6);
      case NodeType.endpoint:
        return const Color(0xFFE9C46A);
      case NodeType.relay:
        return const Color(0xFF2A9D8F);
      default:
        return Colors.grey;
    }
  }

  void _showAddNodeDialog(String parentId) {
    final hostnameController = TextEditingController(text: _generateHostname());
    String selectedType = 'endpoint';
    String region = _detectRegion();

    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          backgroundColor: const Color(0xFF1A1A2E),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: const BorderSide(color: Color(0xFF2D3748)),
          ),
          title: const Text('Add New Node', style: TextStyle(color: Colors.white)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: hostnameController,
                decoration: InputDecoration(
                  labelText: 'Hostname',
                  labelStyle: const TextStyle(color: Color(0xFFA0AEC0)),
                  filled: true,
                  fillColor: const Color(0xFF2D3748),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: BorderSide.none,
                  ),
                ),
                style: const TextStyle(color: Colors.white),
              ),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                value: selectedType,
                decoration: InputDecoration(
                  labelText: 'Type',
                  labelStyle: const TextStyle(color: Color(0xFFA0AEC0)),
                  filled: true,
                  fillColor: const Color(0xFF2D3748),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: BorderSide.none,
                  ),
                ),
                dropdownColor: const Color(0xFF2D3748),
                style: const TextStyle(color: Colors.white),
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
                decoration: InputDecoration(
                  labelText: 'Region',
                  labelStyle: const TextStyle(color: Color(0xFFA0AEC0)),
                  filled: true,
                  fillColor: const Color(0xFF2D3748),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: BorderSide.none,
                  ),
                ),
                controller: TextEditingController(text: region),
                style: const TextStyle(color: Colors.white),
              ),
              const SizedBox(height: 12),
              Text('Parent ID: $parentId', style: const TextStyle(color: Color(0xFF718096), fontSize: 11, fontFamily: 'monospace')),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: Color(0xFFA0AEC0))),
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
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFE9C46A),
                foregroundColor: Colors.black,
              ),
              child: const Text('Add Node'),
            ),
          ],
        ),
      ),
    );
  }

  void _confirmDeleteNode(TreeNode node) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1A1A2E),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: Color(0xFF2D3748)),
        ),
        title: const Text('Delete Node', style: TextStyle(color: Colors.white)),
        content: Text(
          'Are you sure you want to delete "${node.data['hostname'] ?? node.id}'?',
          style: const TextStyle(color: Color(0xFFA0AEC0), fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel', style: TextStyle(color: Color(0xFFA0AEC0))),
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
              backgroundColor: Colors.red.shade600,
              foregroundColor: Colors.white,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
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

  String get icon {
    switch (this) {
      case root:
        return 'account_tree';
      case customer:
        return 'group';
      case endpoint:
        return 'dns';
      case relay:
        return 'hub';
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
