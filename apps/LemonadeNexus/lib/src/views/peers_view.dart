/// @title Peers View
/// @description Mesh peer list with status indicators.
///
/// Matches macOS PeersListView.swift functionality:
/// - Peer list with search
/// - Peer detail panel
/// - Online/offline status
/// - Bandwidth and latency display

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class PeersView extends ConsumerStatefulWidget {
  const PeersView({super.key});

  @override
  ConsumerState<PeersView> createState() => _PeersViewState();
}

class _PeersViewState extends ConsumerState<PeersView> {
  final _searchController = TextEditingController();
  String _searchQuery = '';
  MeshPeer? _selectedPeer;
  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    _startAutoRefresh();
  }

  @override
  void dispose() {
    _searchController.dispose();
    _refreshTimer?.cancel();
    super.dispose();
  }

  void _startAutoRefresh() {
    _refreshTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      ref.read(appNotifierProvider.notifier).refreshMeshStatus();
    });
  }

  List<MeshPeer> get _filteredPeers {
    final appState = ref.read(appNotifierProvider);
    if (_searchQuery.isEmpty) return appState.meshPeers;

    final query = _searchQuery.toLowerCase();
    return appState.meshPeers.where((peer) {
      final hostname = (peer.hostname ?? '').toLowerCase();
      final nodeId = peer.nodeId.toLowerCase();
      final tunnelIp = (peer.tunnelIp ?? '').toLowerCase();
      return hostname.contains(query) ||
          nodeId.contains(query) ||
          tunnelIp.contains(query);
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final appState = ref.watch(appNotifierProvider);
    final filteredPeers = _filteredPeers;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Peer list panel
        Container(
          width: 380,
          decoration: BoxDecoration(
            border: Border(
              right: BorderSide(
                color: scheme.outline,
                width: 1,
              ),
            ),
          ),
          child: Column(
            children: [
              // Header
              _buildListHeader(appState, filteredPeers),
              // Search bar
              _buildSearchBar(),
              Divider(color: scheme.outline, height: 1),
              // Peer list
              Expanded(
                child: filteredPeers.isEmpty
                    ? _buildEmptyState()
                    : ListView.builder(
                        padding: const EdgeInsets.all(8),
                        itemCount: filteredPeers.length,
                        itemBuilder: (context, index) {
                          return _buildPeerRow(filteredPeers[index]);
                        },
                      ),
              ),
            ],
          ),
        ),
        // Detail panel
        Expanded(
          child: _selectedPeer != null
              ? _buildDetailPanel(_selectedPeer!)
              : _buildNoSelectionState(),
        ),
      ],
    );
  }

  Widget _buildListHeader(AppState appState, List<MeshPeer> filteredPeers) {
    final scheme = Theme.of(context).colorScheme;
    final onlineCount = appState.meshPeers.where((p) => p.isOnline).length;
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          const SectionHeader(title: 'Mesh Peers', icon: Icons.people),
          const Spacer(),
          if (!appState.meshPeers.isEmpty)
            Text('$onlineCount/${appState.meshPeers.length} online', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 12)),
          const SizedBox(width: 8),
          IconButton(
            icon: const Icon(Icons.refresh, size: 18),
            color: scheme.onSurfaceVariant,
            onPressed: () => ref.read(appNotifierProvider.notifier).refreshMeshStatus(),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ],
      ),
    );
  }

  Widget _buildSearchBar() {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.all(12),
      child: TextField(
        controller: _searchController,
        decoration: InputDecoration(
          hintText: 'Search peers...',
          prefixIcon: Icon(Icons.search, color: scheme.onSurfaceVariant, size: 20),
          suffixIcon: _searchQuery.isNotEmpty
              ? IconButton(icon: const Icon(Icons.clear, size: 16), color: scheme.onSurfaceVariant, onPressed: () {
                  setState(() { _searchQuery = ''; _searchController.clear(); });
                })
              : null,
          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        ),
        style: const TextStyle(fontSize: 13),
        onChanged: (value) => setState(() => _searchQuery = value),
      ),
    );
  }

  Widget _buildEmptyState() {
    return EmptyState(
      icon: Icons.people_outline,
      title: 'No Peers',
      message: ref.read(appNotifierProvider).isMeshEnabled
          ? 'No mesh peers discovered yet. Other clients must join your network group.'
          : 'Enable mesh networking in the Tunnel tab to discover peers.',
    );
  }

  Widget _buildPeerRow(MeshPeer peer) {
    final scheme = Theme.of(context).colorScheme;
    final isSelected = _selectedPeer?.nodeId == peer.nodeId;
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2, horizontal: 4),
      decoration: BoxDecoration(
        color: isSelected ? AppTheme.lemonYellowDark.withValues(alpha: 0.15) : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: ListTile(
        onTap: () => setState(() => _selectedPeer = peer),
        leading: StatusDot(isHealthy: peer.isOnline),
        title: Text(
          peer.hostname?.isNotEmpty == true ? peer.hostname! : peer.nodeId.substring(0, peer.nodeId.length.clamp(0, 12)),
          style: TextStyle(fontSize: 13, fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Text(peer.tunnelIp ?? 'No IP', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11, fontFamily: 'monospace'), maxLines: 1, overflow: TextOverflow.ellipsis),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (peer.latencyMs != null && peer.latencyMs! >= 0) Text('${peer.latencyMs!.round()}ms', style: TextStyle(color: _getLatencyColor(peer.latencyMs!), fontSize: 11, fontFamily: 'monospace')),
            const SizedBox(width: 8),
            Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Row(mainAxisSize: MainAxisSize.min, children: [
                  Icon(Icons.arrow_downward, size: 10, color: scheme.onSurfaceVariant),
                  Text(_formatBytes(peer.rxBytes ?? 0), style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 9)),
                ]),
                Row(mainAxisSize: MainAxisSize.min, children: [
                  Icon(Icons.arrow_upward, size: 10, color: scheme.onSurfaceVariant),
                  Text(_formatBytes(peer.txBytes ?? 0), style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 9)),
                ]),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailPanel(MeshPeer peer) {
    final scheme = Theme.of(context).colorScheme;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildDetailHeader(peer),
          Divider(color: scheme.outline, height: 24),
          _buildDetailRow('Node ID', peer.nodeId, showCopy: true),
          _buildDetailRow('Tunnel IP', peer.tunnelIp ?? 'Not assigned'),
          _buildDetailRow('Private Subnet', peer.privateSubnet ?? 'Not assigned'),
          _buildDetailRow('WG Public Key', peer.wgPubkey.isNotEmpty ? '${peer.wgPubkey.substring(0, peer.wgPubkey.length.clamp(0, 20))}...' : 'Not available', showCopy: true),
          _buildDetailRow('Endpoint', peer.endpoint?.isNotEmpty == true ? peer.endpoint! : 'Unknown'),
          if (peer.relayEndpoint?.isNotEmpty == true) _buildDetailRow('Relay Endpoint', peer.relayEndpoint!),
          _buildDetailRow('Latency', peer.latencyMs != null && peer.latencyMs! >= 0 ? '${peer.latencyMs!.round()} ms' : 'Unknown'),
          _buildDetailRow('Last Handshake', (peer.lastHandshake ?? '').isNotEmpty ? peer.lastHandshake! : 'Never'),
          _buildDetailRow('Received', _formatBytes(peer.rxBytes ?? 0)),
          _buildDetailRow('Sent', _formatBytes(peer.txBytes ?? 0)),
          _buildDetailRow('Keepalive', '${peer.keepalive}s'),
        ],
      ),
    );
  }

  Widget _buildDetailHeader(MeshPeer peer) {
    final isOnline = peer.isOnline;
    final hostname = peer.hostname?.isNotEmpty == true ? peer.hostname! : 'Unnamed Peer';
    final accent = isOnline ? AppTheme.lemonGreen : AppTheme.errorColor;
    return Row(
      children: [
        Container(
          width: 48, height: 48,
          decoration: BoxDecoration(color: accent.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(12)),
          child: Icon(isOnline ? Icons.person : Icons.person_outline, color: accent, size: 24),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(hostname, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
              const SizedBox(height: 4),
              LemonBadge(text: isOnline ? 'Online' : 'Offline', color: accent),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildDetailRow(String label, String value, {bool showCopy = false}) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 140, child: Text(label, style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13))),
          Expanded(
            child: Row(
              children: [
                Expanded(child: Text(value, style: const TextStyle(fontSize: 13, fontFamily: 'monospace'), maxLines: 2, overflow: TextOverflow.ellipsis)),
                if (showCopy) IconButton(icon: const Icon(Icons.copy, size: 16), color: scheme.onSurfaceVariant, onPressed: () {}, padding: EdgeInsets.zero, constraints: const BoxConstraints()),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNoSelectionState() {
    return const EmptyState(
      icon: Icons.person_outline,
      title: 'Select a Peer',
      message: 'Choose a peer from the list to view details.',
    );
  }

  Color _getLatencyColor(double ms) {
    if (ms < 50) return AppTheme.lemonGreen;
    if (ms < 150) return AppTheme.nodeOrange;
    return AppTheme.errorColor;
  }

  String _formatBytes(int bytes) {
    if (bytes == 0) return '0 B';
    final kb = bytes / 1024;
    final mb = kb / 1024;
    final gb = mb / 1024;
    if (gb >= 1) return '${gb.toStringAsFixed(1)} GB';
    if (mb >= 1) return '${mb.toStringAsFixed(1)} MB';
    if (kb >= 1) return '${kb.toStringAsFixed(0)} KB';
    return '$bytes B';
  }

  String _formatRelativeTime(DateTime time) {
    final diff = DateTime.now().difference(time);
    if (diff.inSeconds < 60) return '${diff.inSeconds}s ago';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }
}
