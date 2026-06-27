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
import '../../theme/app_theme.dart';
import '../../theme/components.dart';
import 'tree_browser_view.dart' show NodeType;

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

  @override
  Widget build(BuildContext context) {
    final node = widget.node;
    final nodeType = NodeType.fromRaw(node.nodeType);
    final scheme = Theme.of(context).colorScheme;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          _buildHeader(node, nodeType),
          Divider(color: scheme.outline, height: 24),
          // Properties
          _buildPropertiesSection(node),
          Divider(color: scheme.outline, height: 24),
          // Network
          _buildNetworkSection(node, nodeType),
          Divider(color: scheme.outline, height: 24),
          // Keys
          _buildKeysSection(node),
          // Assignments
          if (node.assignments != null && node.assignments!.isNotEmpty) ...[
            Divider(color: scheme.outline, height: 24),
            _buildAssignmentsSection(node.assignments!),
          ],
          const SizedBox(height: 20),
          // Actions
          _buildActionsSection(node),
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
        // Title and badges
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                node.displayName,
                style: const TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 4),
              Row(
                children: [
                  LemonBadge(text: nodeType.displayName, color: _nodeColor(nodeType)),
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
            color: _isEditing
                ? AppTheme.lemonGreen
                : Theme.of(context).colorScheme.onSurfaceVariant,
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
      final scheme = Theme.of(context).colorScheme;
      return _buildSection(
        icon: Icons.lan,
        title: 'Network',
        child: Row(
          children: [
            Icon(Icons.info, size: 16, color: scheme.onSurfaceVariant),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                nodeType == NodeType.root
                    ? 'Root node manages the network but does not have a tunnel address.'
                    : 'Group nodes organize endpoints. Select a child endpoint to see network details.',
                style: TextStyle(
                  color: scheme.onSurfaceVariant,
                  fontSize: 12,
                ),
              ),
            ),
          ],
        ),
      );
    }

    return _buildSection(
      icon: Icons.lan,
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
            Text(
              'No network info assigned yet.',
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                fontSize: 12,
              ),
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
            Text(
              'No keys available.',
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                fontSize: 12,
              ),
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
        children: assignments.map(_buildAssignmentCard).toList(),
      ),
    );
  }

  Widget _buildAssignmentCard(NodeAssignment assignment) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: scheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              assignment.managementPubkey,
              style: TextStyle(
                color: scheme.onSurfaceVariant,
                fontSize: 11,
                fontFamily: 'monospace',
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 6),
            Wrap(
              spacing: 4,
              runSpacing: 4,
              children: assignment.permissions
                  .map((perm) => LemonBadge(
                        text: perm,
                        color: _permissionColor(perm),
                      ))
                  .toList(),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActionsSection(TreeNode node) {
    final scheme = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (_statusMessage != null) ...[
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppTheme.infoColor.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                const Icon(Icons.info, color: AppTheme.infoColor, size: 16),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _statusMessage!,
                    style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12),
                  ),
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
                  onPressed: _isSaving ? null : () => _saveChanges(node),
                  icon: _isSaving
                      ? const SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.save),
                  label: const Text('Save Changes'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.lemonYellowDark,
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
                    backgroundColor: scheme.surfaceContainerHighest,
                    foregroundColor: scheme.onSurface,
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
                onPressed: () => _showDeleteConfirmationDialog(node),
                icon: const Icon(Icons.delete),
                label: const Text('Delete Node'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.errorColor,
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
        SectionHeader(title: title, icon: icon),
        const SizedBox(height: 12),
        AppCard(child: child),
      ],
    );
  }

  Widget _buildPropertyRow(String label, {required String value, bool monospaced = false}) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
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
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11),
          ),
          const SizedBox(height: 4),
          Row(
            children: [
              Expanded(
                child: Text(
                  value,
                  style: const TextStyle(
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
                color: scheme.onSurfaceVariant,
                onPressed: () async {
                  await Clipboard.setData(ClipboardData(text: value));
                  if (!mounted) return;
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

  Widget _buildIdBadge(String id) {
    final scheme = Theme.of(context).colorScheme;
    final shortId = id.length > 12
        ? '${id.substring(0, 6)}...${id.substring(id.length - 4)}'
        : id;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        shortId,
        style: TextStyle(
          color: scheme.onSurfaceVariant,
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
        return AppTheme.infoColor;
      case NodeType.endpoint:
        return AppTheme.lemonYellowDark;
      case NodeType.relay:
        return AppTheme.lemonGreen;
    }
  }

  Color _permissionColor(String perm) {
    switch (perm) {
      case 'read':
        return AppTheme.infoColor;
      case 'write':
        return AppTheme.nodeOrange;
      case 'admin':
        return AppTheme.errorColor;
      case 'manage':
        return const Color(0xFF9B5DE5);
      default:
        return Colors.grey;
    }
  }

  Future<void> _saveChanges(TreeNode node) async {
    setState(() {
      _isSaving = true;
      _statusMessage = null;
    });

    // TODO: Implement actual save functionality when edit fields are added.
    // For now this is a placeholder; AppNotifier currently exposes no
    // "update node properties" entry point.
    await Future<void>.delayed(const Duration(milliseconds: 200));

    if (!mounted) return;
    setState(() {
      _isEditing = false;
      _isSaving = false;
      _statusMessage = 'Changes saved (not yet wired to SDK)';
    });

    Future.delayed(const Duration(seconds: 3), () {
      if (mounted) setState(() => _statusMessage = null);
    });
  }

  void _showDeleteConfirmationDialog(TreeNode node) {
    final scheme = Theme.of(context).colorScheme;
    showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: scheme.outline),
        ),
        title: const Text('Delete Node'),
        content: Text(
          'Are you sure you want to delete "${node.displayName}"? This action cannot be undone.',
          style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(dialogContext);
              _deleteNode(node);
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.errorColor,
              foregroundColor: Colors.white,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }

  Future<void> _deleteNode(TreeNode node) async {
    final notifier = ref.read(appNotifierProvider.notifier);
    try {
      final success = await notifier.deleteNode(nodeId: node.id);
      if (!mounted) return;
      if (success) {
        notifier.addActivity(
          ActivityLevel.success,
          'Deleted node: ${node.displayName}',
        );
        Navigator.pop(context); // Pop back to tree browser
      } else {
        notifier.addActivity(
          ActivityLevel.error,
          'Failed to delete: ${node.displayName}',
        );
      }
    } catch (e) {
      notifier.addActivity(ActivityLevel.error, 'Delete failed: $e');
    }
  }
}
