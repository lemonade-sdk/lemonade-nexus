/// @title Network Monitor View
/// @description Network traffic monitoring and graphs.
///
/// Matches macOS NetworkMonitorView.swift functionality:
/// - Summary cards (peers, online, bandwidth)
/// - Peer topology list
/// - Bandwidth breakdown by peer
/// - Auto-refresh

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';

class NetworkMonitorView extends ConsumerStatefulWidget {
  const NetworkMonitorView({super.key});

  @override
  ConsumerState<NetworkMonitorView> createState() => _NetworkMonitorViewState();
}

class _NetworkMonitorViewState extends ConsumerState<NetworkMonitorView> {
  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    _startAutoRefresh();
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    super.dispose();
  }

  void _startAutoRefresh() {
    _refreshTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      ref.read(appNotifierProvider.notifier).refreshMeshStatus();
    });
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final peers = appState.meshPeers;
    final status = appState.meshStatus;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          _buildHeader(appState),

          const SizedBox(height: 24),

          // Summary cards
          _buildSummaryCards(status),

          const SizedBox(height: 24),

          // Peer topology
          if (peers.isNotEmpty) _buildPeerTopology(peers),

          const SizedBox(height: 24),

          // Bandwidth breakdown
          if (peers.isNotEmpty) _buildBandwidthBreakdown(peers),
        ],
      ),
    );
  }

  Widget _buildHeader(AppState appState) {
    return Row(
      children: [
        const Icon(Icons.bar_chart, color: Color(0xFFE9C46A), size: 24),
        const SizedBox(width: 12),
        const Text('Network Monitor', style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold)),
        const Spacer(),
        IconButton(
          icon: const Icon(Icons.refresh),
          color: const Color(0xFFA0AEC0),
          onPressed: () => ref.read(appNotifierProvider.notifier).refreshMeshStatus(),
          tooltip: 'Refresh',
        ),
      ],
    );
  }

  Widget _buildSummaryCards(MeshStatus? status) {
    return GridView.count(
      crossAxisCount: 4,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      mainAxisSpacing: 16,
      childAspectRatio: 2.5,
      children: [
        _buildSummaryCard(
          icon: Icons.people,
          title: 'Total Peers',
          value: '${status?.peerCount ?? 0}',
          color: const Color(0xFFE9C46A),
        ),
        _buildSummaryCard(
          icon: Icons.wifi,
          title: 'Online',
          value: '${status?.onlineCount ?? 0}',
          color: Colors.green,
        ),
        _buildSummaryCard(
          icon: Icons.arrow_downward_circle,
          title: 'Total Received',
          value: _formatBytes(status?.totalRxBytes ?? 0),
          color: Colors.blue,
        ),
        _buildSummaryCard(
          icon: Icons.arrow_upward_circle,
          title: 'Total Sent',
          value: _formatBytes(status?.totalTxBytes ?? 0),
          color: Colors.orange,
        ),
      ],
    );
  }

  Widget _buildSummaryCard({required IconData icon, required String title, required String value, required Color color}) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1A2E).withOpacity(0.5),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF2D3748)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: color.withOpacity(0.15), borderRadius: BorderRadius.circular(8)),
            child: Icon(icon, color: color, size: 22),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(title, style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 11)),
                const SizedBox(height: 2),
                Text(value, style: TextStyle(color: color, fontSize: 16, fontWeight: FontWeight.bold, fontFamily: 'monospace')),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPeerTopology(List<MeshPeer> peers) {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.share, color: Color(0xFFE9C46A), size: 18),
              const SizedBox(width: 8),
              const Text('Peer Topology', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
            ],
          ),
          const SizedBox(height: 12),
          ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: peers.length,
            separatorBuilder: (_, __) => const Divider(color: Color(0xFF2D3748), height: 1),
            itemBuilder: (context, index) => _buildPeerTopologyRow(peers[index]),
          ),
        ],
      ),
    );
  }

  Widget _buildPeerTopologyRow(MeshPeer peer) {
    final isOnline = peer.isOnline;
    final hostname = peer.hostname?.isNotEmpty == true ? peer.hostname! : peer.nodeId.substring(0, 12);
    final hasDirectEndpoint = peer.endpoint?.isNotEmpty == true;
    final hasRelayEndpoint = peer.relayEndpoint?.isNotEmpty == true;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          _buildStatusDot(isOnline),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(hostname, style: const TextStyle(color: Colors.white, fontSize: 13), maxLines: 1, overflow: TextOverflow.ellipsis),
                Text(peer.tunnelIp ?? 'No IP', style: const TextStyle(color: Color(0xFF718096), fontSize: 11, fontFamily: 'monospace')),
              ],
            ),
          ),
          // Connection type badge
          if (hasDirectEndpoint)
            _buildBadge(text: 'Direct', color: Colors.green)
          else if (hasRelayEndpoint)
            _buildBadge(text: 'Relay', color: Colors.orange)
          else
            _buildBadge(text: 'No Route', color: Colors.red),
          const SizedBox(width: 12),
          // Latency
          if (peer.latencyMs != null && peer.latencyMs! >= 0)
            SizedBox(
              width: 50,
              child: Text(
                '${peer.latencyMs}ms',
                style: TextStyle(
                  color: _getLatencyColor(peer.latencyMs!),
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
                textAlign: TextAlign.right,
              ),
            )
          else
            const SizedBox(width: 50, child: Text('--', style: TextStyle(color: Color(0xFF718096), fontSize: 11), textAlign: TextAlign.right)),
          const SizedBox(width: 8),
          // Bandwidth
          SizedBox(
            width: 70,
            child: Column(
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
          ),
        ],
      ),
    );
  }

  Widget _buildBandwidthBreakdown(List<MeshPeer> peers) {
    final totalRx = peers.fold<int>(0, (sum, p) => sum + (p.rxBytes ?? 0));
    final totalTx = peers.fold<int>(0, (sum, p) => sum + (p.txBytes ?? 0));
    final maxTotal = peers.map((p) => (p.rxBytes ?? 0) + (p.txBytes ?? 0)).reduce((a, b) => a > b ? a : b);

    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.bar_chart, color: Color(0xFFE9C46A), size: 18),
              const SizedBox(width: 8),
              const Text('Bandwidth by Peer', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
            ],
          ),
          const SizedBox(height: 16),
          ...peers.map((peer) => _buildPeerBandwidthRow(peer, maxTotal)),
          if (totalRx + totalTx > 0) ...[
            const SizedBox(height: 12),
            Row(
              children: [
                Row(children: [
                  Container(width: 8, height: 8, decoration: BoxDecoration(color: Colors.blue.withOpacity(0.7), borderRadius: BorderRadius.circular(2))),
                  const SizedBox(width: 4),
                  Text('Received (${_formatBytes(totalRx)})', style: const TextStyle(color: Color(0xFF718096), fontSize: 11)),
                ]),
                const SizedBox(width: 16),
                Row(children: [
                  Container(width: 8, height: 8, decoration: BoxDecoration(color: Colors.orange.withOpacity(0.7), borderRadius: BorderRadius.circular(2))),
                  const SizedBox(width: 4),
                  Text('Sent (${_formatBytes(totalTx)})', style: const TextStyle(color: Color(0xFF718096), fontSize: 11)),
                ]),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildPeerBandwidthRow(MeshPeer peer, int maxTotal) {
    final hostname = peer.hostname?.isNotEmpty == true ? peer.hostname! : peer.nodeId.substring(0, 12);
    final rxBytes = peer.rxBytes ?? 0;
    final txBytes = peer.txBytes ?? 0;
    final peerTotal = rxBytes + txBytes;
    final fraction = maxTotal > 0 ? peerTotal / maxTotal : 0.0;
    final rxFraction = peerTotal > 0 ? rxBytes / peerTotal : 0.5;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(hostname, style: const TextStyle(color: Colors.white, fontSize: 12), maxLines: 1, overflow: TextOverflow.ellipsis),
              const Spacer(),
              Text(_formatBytes(peerTotal), style: const TextStyle(color: Color(0xFFA0AEC0), fontSize: 11, fontFamily: 'monospace')),
            ],
          ),
          const SizedBox(height: 4),
          ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: SizedBox(
              height: 8,
              child: Row(
                children: [
                  SizedBox(width: (800 * fraction * rxFraction).clamp(0, 800.0), child: Container(decoration: BoxDecoration(color: Colors.blue.withOpacity(0.7)))),
                  SizedBox(width: (800 * fraction * (1 - rxFraction)).clamp(0, 800.0), child: Container(decoration: BoxDecoration(color: Colors.orange.withOpacity(0.7)))),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCard({required Widget child}) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1A2E).withOpacity(0.5),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF2D3748)),
      ),
      child: child,
    );
  }

  Widget _buildStatusDot(bool isOnline) {
    return Container(
      width: 10, height: 10,
      decoration: BoxDecoration(color: isOnline ? Colors.green : Colors.red, shape: BoxShape.circle),
    );
  }

  Widget _buildBadge({required String text, required Color color}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
      decoration: BoxDecoration(color: color.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
      child: Text(text, style: TextStyle(color: color, fontSize: 9, fontWeight: FontWeight.bold)),
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
}
