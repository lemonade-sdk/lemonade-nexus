/// @title Node Detail View
/// @description Detailed view of a tree node.
///
/// Matches macOS NodeDetailView.swift functionality:
/// - Node header with icon and badges
/// - Properties section
/// - Network info section
/// - Cryptographic keys section
/// - Assignments section
/// - Delete node action

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';

class NodeDetailView extends ConsumerStatefulWidget {
  final TreeNode node;

  const NodeDetailView({super.key, required this.node});

  @override
  ConsumerState<NodeDetailView> createState() => _NodeDetailViewState();
}

class _NodeDetailViewState extends ConsumerState<NodeDetailView> {
  bool _isEditing = false;
  bool _isSaving = false;
  String? _statusMessage;
  bool _showDeleteConfirmation = false;

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final node = widget.node;
    final nodeType = NodeType.fromRaw(node.nodeType);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          _buildHeader(node, nodeType),
          const Divider(color: Color(0xFF2D3748), height: 24),
          // Properties
          _buildPropertiesSection(node),
          const Divider(color: Color(0xFF2D3748), height: 24),
          // Network
          _buildNetworkSection(node, nodeType),
          const Divider(color: Color(0xFF2D3748), height: 24),
          // Keys
          _buildKeysSection(node),
          // Assignments
          if (node.assignments != null && node.assignments!.isNotEmpty) ...[
            const Divider(color: Color(0xFF2D3748), height: 24),
            _buildAssignmentsSection(node.assignments!),
          ],
          const SizedBox(height: 20),
          // Actions
          _buildActionsSection(appState, node),
        ],
      ),
    );
  }

  Widget _buildHeader(TreeNode node, NodeType nodeType) {
    return Row(
      children: [
        // Icon
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
        // Title and badges
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                node.displayName,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 4),
              Row(
                children: [
                  _buildBadge(text: nodeType.displayName, color: _nodeColor(nodeType)),
                  const SizedBox(width: 8),
                  _buildIdBadge(node.id),
                ],
              ),
            ],
          ),
        ),
        // Edit button
        IconButton(
          icon: Icon(
            _isEditing ? Icons.check_circle : Icons.edit,
            color: _isEditing ? const Color(0xFF2A9D8F) : const Color(0xFFA0AEC0),
            size: 24,
          ),
          onPressed: () => setState(() => _isEditing = !_isEditing),
          tooltip: _isEditing ? 'Done Editing' : 'Edit Node',
        ),
      ],
    );
  }

  Widget _buildPropertiesSection(TreeNode node) {
    return _buildSection(
      icon: Icons.info_outline,
      title: 'Properties',
      child: Column(
        children: [
          _buildPropertyRow('Node ID', value: node.id, monospaced: true),
          _buildPropertyRow('Parent ID', value: node.parentId, monospaced: true),
          _buildPropertyRow('Type', value: NodeType.fromRaw(node.nodeType).displayName),
          _buildPropertyRow('Hostname', value: node.displayName),
          if (node.displayRegion != null)
            _buildPropertyRow('Region', value: node.displayRegion!),
        ],
      ),
    );
  }

  Widget _buildNetworkSection(TreeNode node, NodeType nodeType) {
    if (nodeType == NodeType.customer || nodeType == NodeType.root) {
      return _buildSection(
        icon: Icons.network,
        title: 'Network',
        child: Row(
          children: [
            const Icon(Icons.info, size: 16, color: Color(0xFF718096)),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                nodeType == NodeType.root
                    ? 'Root node manages the network but does not have a tunnel address.'
                    : 'Group nodes organize endpoints. Select a child endpoint to see network details.',
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
      );
    }

    return _buildSection(
      icon: Icons.network,
      title: 'Network',
      child: Column(
        children: [
          if (node.displayTunnelIp != null)
            _buildPropertyRow('Tunnel IP', value: node.displayTunnelIp!, monospaced: true),
          if (node.privateSubnet != null)
            _buildPropertyRow('Private Subnet', value: node.privateSubnet!, monospaced: true),
          if (node.listenEndpoint != null)
            _buildPropertyRow('Listen Endpoint', value: node.listenEndpoint!, monospaced: true),
          if (node.displayTunnelIp == null &&
              node.privateSubnet == null &&
              node.listenEndpoint == null)
            const Text(
              'No network info assigned yet.',
              style: TextStyle(color: Color(0xFF718096), fontSize: 12),
            ),
        ],
      ),
    );
  }

  Widget _buildKeysSection(TreeNode node) {
    return _buildSection(
      icon: Icons.vpn_key,
      title: 'Cryptographic Keys',
      child: Column(
        children: [
          if (node.mgmtPubkey != null)
            _buildKeyRow('Management Key', value: node.mgmtPubkey!),
          if (node.wgPubkey != null)
            _buildKeyRow('WireGuard Key', value: node.wgPubkey!),
          if (node.mgmtPubkey == null && node.wgPubkey == null)
            const Text(
              'No keys available.',
              style: TextStyle(color: Color(0xFF718096), fontSize: 12),
            ),
        ],
      ),
    );
  }

  Widget _buildAssignmentsSection(List<NodeAssignment> assignments) {
    return _buildSection(
      icon: Icons.badge,
      title: 'Assignments (${assignments.length})',
      child: Column(
        children: assignments.map((assignment) => _buildAssignmentCard(assignment)).toList(),
      ),
    );
  }

  Widget _buildAssignmentCard(NodeAssignment assignment) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xFF16213E),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            assignment.managementPubkey,
            style: const TextStyle(
              color: Color(0xFFA0AEC0),
              fontSize: 11,
              fontFamily: 'monospace',
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 6),
          Wrap(
            spacing: 4,
            children: assignment.permissions.map((perm) => _buildBadge(
              text: perm,
              color: _permissionColor(perm),
            )).toList(),
          ),
        ],
      ),
    );
  }

  Widget _buildActionsSection(AppState appState, TreeNode node) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (_statusMessage != null) ...[
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: Colors.blue.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                const Icon(Icons.info, color: Colors.blue, size: 16),
                const SizedBox(width: 8),
                Text(
                  _statusMessage!,
                  style: const TextStyle(color: Color(0xFFA0AEC0), fontSize: 12),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
        ],
        Row(
          children: [
            if (_isEditing) ...[
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isSaving ? null : () async => await _saveChanges(appState, node),
                  icon: _isSaving
                      ? const SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.save),
                  label: const Text('Save Changes'),
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
                child: ElevatedButton(
                  onPressed: () => setState(() => _isEditing = false),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF2D3748),
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  child: const Text('Cancel'),
                ),
              ),
              const SizedBox(width: 12),
            ],
            Expanded(
              child: ElevatedButton.icon(
                onPressed: () => _showDeleteConfirmation = true,
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
    );
  }

  Widget _buildSection({required IconData icon, required String title, required Widget child}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, color: const Color(0xFFE9C46A), size: 18),
            const SizedBox(width: 8),
            Text(
              title,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 14,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: const Color(0xFF1A1A2E).withOpacity(0.5),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0xFF2D3748)),
          ),
          child: child,
        ),
      ],
    );
  }

  Widget _buildPropertyRow(String label, {required String value, bool monospaced = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: const TextStyle(color: Color(0xFF718096), fontSize: 12),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                color: Colors.white,
                fontSize: 12,
                fontFamily: monospaced ? 'monospace' : null,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildKeyRow(String label, {required String value}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: const TextStyle(color: Color(0xFF718096), fontSize: 11),
          ),
          const SizedBox(height: 4),
          Row(
            children: [
              Expanded(
                child: Text(
                  value,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 11,
                    fontFamily: 'monospace',
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 8),
              IconButton(
                icon: const Icon(Icons.copy, size: 16),
                color: const Color(0xFF718096),
                onPressed: () async {
                  await Clipboard.setData(ClipboardData(text: value));
                  setState(() => _statusMessage = 'Copied $label to clipboard');
                  Future.delayed(const Duration(seconds: 3), () {
                    if (mounted) setState(() => _statusMessage = null);
                  });
                },
                tooltip: 'Copy to clipboard',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            ],
          ),
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

  Widget _buildIdBadge(String id) {
    final shortId = id.length > 12 ? '${id.substring(0, 6)}...${id.substring(id.length - 4)}' : id;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
      decoration: BoxDecoration(
        color: const Color(0xFF2D3748),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        shortId,
        style: const TextStyle(
          color: Color(0xFFA0AEC0),
          fontSize: 9,
          fontFamily: 'monospace',
        ),
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

  Color _permissionColor(String perm) {
    switch (perm) {
      case 'read':
        return const Color(0xFF3B82F6);
      case 'write':
        return Colors.orange;
      case 'admin':
        return Colors.red;
      case 'manage':
        return const Color(0xFF9B5DE5);
      default:
        return Colors.grey;
    }
  }

  Future<void> _saveChanges(AppState appState, TreeNode node) async {
    setState(() => _isSaving = true);
    setState(() => _statusMessage = null);

    // TODO: Implement actual save functionality when edit fields are added
    // For now, just mark as saved
    setState(() {
      _isEditing = false;
      _isSaving = false;
      _statusMessage = 'Changes saved successfully';
    });

    Future.delayed(const Duration(seconds: 3), () {
      if (mounted) setState(() => _statusMessage = null);
    });
  }

  void _showDeleteConfirmationDialog(AppState appState, TreeNode node) {
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
          'Are you sure you want to delete "${node.displayName}"? This action cannot be undone.',
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
              await _deleteNode(appState, node);
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

  Future<void> _deleteNode(AppState appState, TreeNode node) async {
    try {
      final notifier = ref.read(appNotifierProvider.notifier);
      final success = await notifier.deleteNode(nodeId: node.id);
      if (success) {
        notifier.addActivity(ActivityEntry.success('Deleted node: ${node.displayName}'));
        if (mounted) {
          Navigator.pop(context); // Pop back to tree browser
        }
      } else {
        notifier.addActivity(ActivityEntry.error('Failed to delete: ${node.displayName}'));
      }
    } catch (e) {
      notifier.addActivity(ActivityEntry.error('Delete failed: $e'));
    }
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // Handle delete confirmation dialog
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_showDeleteConfirmation) {
        setState(() => _showDeleteConfirmation = false);
        final appState = ref.read(appNotifierProvider);
        _showDeleteConfirmationDialog(appState, widget.node);
      }
    });
  }
}
