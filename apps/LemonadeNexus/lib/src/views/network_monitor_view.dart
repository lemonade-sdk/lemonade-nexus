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
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

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
        const SectionHeader(title: 'Network Monitor', icon: Icons.bar_chart),
        const Spacer(),
        IconButton(
          icon: const Icon(Icons.refresh, size: 20),
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
      crossAxisSpacing: 16,
      childAspectRatio: 2.5,
      children: [
        _buildSummaryCard(
          icon: Icons.people,
          title: 'Total Peers',
          value: '${status?.peerCount ?? 0}',
          color: AppTheme.lemonYellowDark,
        ),
        _buildSummaryCard(
          icon: Icons.wifi,
          title: 'Online',
          value: '${status?.onlineCount ?? 0}',
          color: AppTheme.lemonGreen,
        ),
        _buildSummaryCard(
          icon: Icons.arrow_circle_down,
          title: 'Total Received',
          value: _formatBytes(status?.totalRxBytes ?? 0),
          color: AppTheme.infoColor,
        ),
        _buildSummaryCard(
          icon: Icons.arrow_circle_up,
          title: 'Total Sent',
          value: _formatBytes(status?.totalTxBytes ?? 0),
          color: AppTheme.nodeOrange,
        ),
      ],
    );
  }

  Widget _buildSummaryCard({required IconData icon, required String title, required String value, required Color color}) {
    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: color.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(8)),
            child: Icon(icon, color: color, size: 22),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(title, style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11)),
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
    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: 'Peer Topology', icon: Icons.share),
          const SizedBox(height: 12),
          ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: peers.length,
            separatorBuilder: (_, __) => Divider(color: scheme.outline, height: 1),
            itemBuilder: (context, index) => _buildPeerTopologyRow(peers[index]),
          ),
        ],
      ),
    );
  }

  Widget _buildPeerTopologyRow(MeshPeer peer) {
    final scheme = Theme.of(context).colorScheme;
    final isOnline = peer.isOnline;
    final hostname = peer.hostname?.isNotEmpty == true ? peer.hostname! : peer.nodeId.substring(0, 12);
    final hasDirectEndpoint = peer.endpoint?.isNotEmpty == true;
    final hasRelayEndpoint = peer.relayEndpoint?.isNotEmpty == true;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          StatusDot(isHealthy: isOnline),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(hostname, style: const TextStyle(fontSize: 13), maxLines: 1, overflow: TextOverflow.ellipsis),
                Text(peer.tunnelIp ?? 'No IP', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11, fontFamily: 'monospace')),
              ],
            ),
          ),
          // Connection type badge
          if (hasDirectEndpoint)
            const LemonBadge(text: 'Direct', color: AppTheme.lemonGreen)
          else if (hasRelayEndpoint)
            const LemonBadge(text: 'Relay', color: AppTheme.nodeOrange)
          else
            const LemonBadge(text: 'No Route', color: AppTheme.errorColor),
          const SizedBox(width: 12),
          // Latency
          if (peer.latencyMs != null && peer.latencyMs! >= 0)
            SizedBox(
              width: 50,
              child: Text(
                '${peer.latencyMs!.round()}ms',
                style: TextStyle(
                  color: _getLatencyColor(peer.latencyMs!),
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
                textAlign: TextAlign.right,
              ),
            )
          else
            SizedBox(width: 50, child: Text('--', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11), textAlign: TextAlign.right)),
          const SizedBox(width: 8),
          // Bandwidth
          SizedBox(
            width: 70,
            child: Column(
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
          ),
        ],
      ),
    );
  }

  Widget _buildBandwidthBreakdown(List<MeshPeer> peers) {
    final scheme = Theme.of(context).colorScheme;
    final totalRx = peers.fold<int>(0, (sum, p) => sum + (p.rxBytes ?? 0));
    final totalTx = peers.fold<int>(0, (sum, p) => sum + (p.txBytes ?? 0));
    final maxTotal = peers.map((p) => (p.rxBytes ?? 0) + (p.txBytes ?? 0)).reduce((a, b) => a > b ? a : b);

    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: 'Bandwidth by Peer', icon: Icons.bar_chart),
          const SizedBox(height: 16),
          ...peers.map((peer) => _buildPeerBandwidthRow(peer, maxTotal)),
          if (totalRx + totalTx > 0) ...[
            const SizedBox(height: 12),
            Row(
              children: [
                Row(children: [
                  Container(width: 8, height: 8, decoration: BoxDecoration(color: AppTheme.infoColor.withValues(alpha: 0.7), borderRadius: BorderRadius.circular(2))),
                  const SizedBox(width: 4),
                  Text('Received (${_formatBytes(totalRx)})', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11)),
                ]),
                const SizedBox(width: 16),
                Row(children: [
                  Container(width: 8, height: 8, decoration: BoxDecoration(color: AppTheme.nodeOrange.withValues(alpha: 0.7), borderRadius: BorderRadius.circular(2))),
                  const SizedBox(width: 4),
                  Text('Sent (${_formatBytes(totalTx)})', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11)),
                ]),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildPeerBandwidthRow(MeshPeer peer, int maxTotal) {
    final scheme = Theme.of(context).colorScheme;
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
              Text(hostname, style: const TextStyle(fontSize: 12), maxLines: 1, overflow: TextOverflow.ellipsis),
              const Spacer(),
              Text(_formatBytes(peerTotal), style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11, fontFamily: 'monospace')),
            ],
          ),
          const SizedBox(height: 4),
          ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: SizedBox(
              height: 8,
              child: Row(
                children: [
                  SizedBox(width: (800 * fraction * rxFraction).clamp(0, 800.0), child: Container(decoration: BoxDecoration(color: AppTheme.infoColor.withValues(alpha: 0.7)))),
                  SizedBox(width: (800 * fraction * (1 - rxFraction)).clamp(0, 800.0), child: Container(decoration: BoxDecoration(color: AppTheme.nodeOrange.withValues(alpha: 0.7)))),
                ],
              ),
            ),
          ),
        ],
      ),
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
}
