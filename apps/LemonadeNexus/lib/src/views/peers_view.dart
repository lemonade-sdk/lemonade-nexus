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
    final appState = ref.watch(appNotifierProvider);
    final filteredPeers = _filteredPeers;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Peer list panel
        Container(
          width: 380,
          decoration: const BoxDecoration(
            color: Color(0xFF1A1A2E),
            border: Border(
              right: BorderSide(
                color: Color(0xFF2D3748),
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
              const Divider(color: Color(0xFF2D3748), height: 1),
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
    final onlineCount = appState.meshPeers.where((p) => p.isOnline).length;
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          const Icon(Icons.people, color: Color(0xFFE9C46A), size: 20),
          const SizedBox(width: 8),
          const Text('Mesh Peers', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
          const Spacer(),
          if (!appState.meshPeers.isEmpty)
            Text('$onlineCount/${appState.meshPeers.length} online', style: const TextStyle(color: Color(0xFFA0AEC0), fontSize: 12)),
          const SizedBox(width: 8),
          IconButton(
            icon: const Icon(Icons.refresh, size: 18),
            color: const Color(0xFFA0AEC0),
            onPressed: () => ref.read(appNotifierProvider.notifier).refreshMeshStatus(),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ],
      ),
    );
  }

  Widget _buildSearchBar() {
    return Padding(
      padding: const EdgeInsets.all(12),
      child: TextField(
        controller: _searchController,
        decoration: InputDecoration(
          hintText: 'Search peers...',
          hintStyle: TextStyle(color: Colors.white.withOpacity(0.4)),
          prefixIcon: const Icon(Icons.search, color: Color(0xFFA0AEC0), size: 20),
          suffixIcon: _searchQuery.isNotEmpty
              ? IconButton(icon: const Icon(Icons.clear, size: 16), color: const Color(0xFFA0AEC0), onPressed: () {
                  setState(() { _searchQuery = ''; _searchController.clear(); });
                })
              : null,
          filled: true,
          fillColor: const Color(0xFF2D3748),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        ),
        style: const TextStyle(color: Colors.white, fontSize: 13),
        onChanged: (value) => setState(() => _searchQuery = value),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.people_outline, size: 48, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('No Peers', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text(
              ref.read(appNotifierProvider).isMeshEnabled
                  ? 'No mesh peers discovered yet. Other clients must join your network group.'
                  : 'Enable mesh networking in the Tunnel tab to discover peers.',
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPeerRow(MeshPeer peer) {
    final isSelected = _selectedPeer?.nodeId == peer.nodeId;
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2, horizontal: 4),
      decoration: BoxDecoration(
        color: isSelected ? const Color(0xFFE9C46A).withOpacity(0.15) : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: ListTile(
        onTap: () => setState(() => _selectedPeer = peer),
        leading: _buildStatusDot(peer.isOnline),
        title: Text(
          peer.hostname?.isNotEmpty == true ? peer.hostname! : peer.nodeId.substring(0, peer.nodeId.length.clamp(0, 12)),
          style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Text(peer.tunnelIp ?? 'No IP', style: const TextStyle(color: Color(0xFF718096), fontSize: 11, fontFamily: 'monospace'), maxLines: 1, overflow: TextOverflow.ellipsis),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (peer.latencyMs != null && peer.latencyMs! >= 0) Text('${peer.latencyMs}ms', style: TextStyle(color: _getLatencyColor(peer.latencyMs!), fontSize: 11, fontFamily: 'monospace')),
            const SizedBox(width: 8),
            Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Row(mainAxisSize: MainAxisSize.min, children: [
                  const Icon(Icons.arrow_downward, size: 10, color: Color(0xFF718096)),
                  Text(_formatBytes(peer.rxBytes ?? 0), style: const TextStyle(color: Color(0xFF718096), fontSize: 9)),
                ]),
                Row(mainAxisSize: MainAxisSize.min, children: [
                  const Icon(Icons.arrow_upward, size: 10, color: Color(0xFF718096)),
                  Text(_formatBytes(peer.txBytes ?? 0), style: const TextStyle(color: Color(0xFF718096), fontSize: 9)),
                ]),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusDot(bool isOnline) {
    return Container(
      width: 10, height: 10,
      decoration: BoxDecoration(color: isOnline ? Colors.green : Colors.red, shape: BoxShape.circle, boxShadow: [
        BoxShadow(color: (isOnline ? Colors.green : Colors.red).withOpacity(0.5), blurRadius: 4, spreadRadius: 1),
      ]),
    );
  }

  Widget _buildDetailPanel(MeshPeer peer) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildDetailHeader(peer),
          const Divider(color: Color(0xFF2D3748), height: 24),
          _buildDetailRow('Node ID', peer.nodeId, showCopy: true),
          _buildDetailRow('Tunnel IP', peer.tunnelIp ?? 'Not assigned'),
          _buildDetailRow('Private Subnet', peer.privateSubnet ?? 'Not assigned'),
          _buildDetailRow('WG Public Key', (peer.wgPubkey ?? '').isNotEmpty ? '${peer.wgPubkey!.substring(0, peer.wgPubkey!.length.clamp(0, 20))}...' : 'Not available', showCopy: true),
          _buildDetailRow('Endpoint', peer.endpoint?.isNotEmpty == true ? peer.endpoint! : 'Unknown'),
          if (peer.relayEndpoint?.isNotEmpty == true) _buildDetailRow('Relay Endpoint', peer.relayEndpoint!),
          _buildDetailRow('Latency', peer.latencyMs != null && peer.latencyMs! >= 0 ? '${peer.latencyMs} ms' : 'Unknown'),
          _buildDetailRow('Last Handshake', peer.lastHandshake != null && peer.lastHandshake! > 0 ? _formatRelativeTime(DateTime.fromMillisecondsSinceEpoch(peer.lastHandshake! * 1000)) : 'Never'),
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
    return Row(
      children: [
        Container(
          width: 48, height: 48,
          decoration: BoxDecoration(color: (isOnline ? Colors.green : Colors.red).withOpacity(0.15), borderRadius: BorderRadius.circular(12)),
          child: Icon(isOnline ? Icons.person : Icons.person_outline, color: isOnline ? Colors.green : Colors.red, size: 24),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(hostname, style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold), maxLines: 1, overflow: TextOverflow.ellipsis),
              const SizedBox(height: 4),
              _buildBadge(text: isOnline ? 'Online' : 'Offline', color: isOnline ? Colors.green : Colors.red),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildDetailRow(String label, String value, {bool showCopy = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 140, child: Text(label, style: const TextStyle(color: Color(0xFF718096), fontSize: 13))),
          Expanded(
            child: Row(
              children: [
                Expanded(child: Text(value, style: const TextStyle(color: Colors.white, fontSize: 13, fontFamily: 'monospace'), maxLines: 2, overflow: TextOverflow.ellipsis)),
                if (showCopy) IconButton(icon: const Icon(Icons.copy, size: 16), color: const Color(0xFF718096), onPressed: () {}, padding: EdgeInsets.zero, constraints: const BoxConstraints()),
              ],
            ),
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
          Icon(Icons.person_outline, size: 64, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('Select a Peer', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Text('Choose a peer from the list to view details.', style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 14), textAlign: TextAlign.center),
        ],
      ),
    );
  }

  Widget _buildBadge({required String text, required Color color}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(color: color.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
      child: Text(text, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.bold)),
    );
  }

  Color _getLatencyColor(int ms) {
    if (ms < 50) return Colors.green;
    if (ms < 150) return Colors.orange;
    return Colors.red;
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
