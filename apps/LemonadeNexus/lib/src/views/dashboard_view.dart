/// @title Dashboard View
/// @description Main dashboard with connection status and stats.
///
/// Matches macOS DashboardView.swift functionality:
/// - Stats row with peer count, servers, relays, uptime
/// - Mesh status row with tunnel, peers, bandwidth
/// - Server health card
/// - Connection status card
/// - Network info card
/// - Trust card
/// - Recent activity section

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';

class DashboardView extends ConsumerStatefulWidget {
  const DashboardView({super.key});

  @override
  ConsumerState<DashboardView> createState() => _DashboardViewState();
}

class _DashboardViewState extends ConsumerState<DashboardView> {
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

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          _buildHeader(appState),

          const SizedBox(height: 24),

          // Stats Row
          _buildStatsRow(appState),

          const SizedBox(height: 20),

          // Mesh Status Row
          _buildMeshStatusRow(appState),

          const SizedBox(height: 20),

          // Health & Connection Cards
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: _buildServerHealthCard(appState),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildConnectionStatusCard(appState),
              ),
            ],
          ),

          const SizedBox(height: 20),

          // Trust & Network Info
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: _buildNetworkInfoCard(appState),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildTrustCard(appState),
              ),
            ],
          ),

          const SizedBox(height: 24),

          // Recent Activity
          _buildActivitySection(appState),
        ],
      ),
    );
  }

  Widget _buildHeader(AppState appState) {
    return Row(
      children: [
        const Icon(
          Icons.dashboard_outlined,
          color: Color(0xFFE9C46A),
          size: 24,
        ),
        const SizedBox(width: 12),
        const Text(
          'Dashboard',
          style: TextStyle(
            color: Colors.white,
            fontSize: 20,
            fontWeight: FontWeight.bold,
          ),
        ),
        const Spacer(),
        IconButton(
          icon: const Icon(Icons.refresh),
          color: const Color(0xFFA0AEC0),
          onPressed: () {
            ref.read(appNotifierProvider.notifier).refreshAllData();
          },
          tooltip: 'Refresh All Data',
        ),
      ],
    );
  }

  Widget _buildStatsRow(AppState appState) {
    return Row(
      children: [
        Expanded(
          child: _StatCard(
            icon: Icons.people,
            title: 'Peer Count',
            value: '${appState.stats?.peerCount ?? 0}',
            color: const Color(0xFFE9C46A),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _StatCard(
            icon: Icons.dns,
            title: 'Servers',
            value: '${appState.servers.length}',
            color: Colors.blue,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _StatCard(
            icon: Icons.wifi_tethering,
            title: 'Relays',
            value: '${appState.relays.length}',
            color: const Color(0xFF2A9D8F),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _StatCard(
            icon: Icons.access_time,
            title: 'Uptime',
            value: _formatUptime(appState.connectedSince),
            color: Colors.orange,
          ),
        ),
      ],
    );
  }

  String _formatUptime(DateTime? since) {
    if (since == null) return '--';
    final interval = DateTime.now().difference(since);
    final hours = interval.inHours;
    final minutes = interval.inMinutes % 60;
    if (hours > 0) {
      return '${hours}h ${minutes}m';
    }
    return '${minutes}m';
  }

  Widget _buildMeshStatusRow(AppState appState) {
    return Row(
      children: [
        // Tunnel status card
        Expanded(
          child: _buildCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildCardHeader('Tunnel', Icons.lock_shield),
                const Divider(color: Color(0xFF2D3748)),
                _buildLabeledContent(
                  'Status',
                  _buildBadge(
                    text: appState.isTunnelUp ? 'UP' : 'DOWN',
                    color: appState.isTunnelUp ? Colors.green : Colors.grey,
                  ),
                ),
                _buildLabeledContent(
                  'Mesh',
                  _buildBadge(
                    text: appState.isMeshEnabled ? 'ENABLED' : 'DISABLED',
                    color: appState.isMeshEnabled ? const Color(0xFF2A9D8F) : Colors.grey,
                  ),
                ),
                if (appState.meshStatus?.tunnelIp != null &&
                    appState.meshStatus!.tunnelIp!.isNotEmpty)
                  _buildLabeledContent(
                    'Mesh IP',
                    Text(
                      appState.meshStatus!.tunnelIp!,
                      style: const TextStyle(
                        color: Color(0xFFA0AEC0),
                        fontSize: 13,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(width: 16),

        // Mesh peers card
        Expanded(
          child: _buildCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildCardHeader('Mesh Peers', Icons.connect_without_contact),
                const Divider(color: Color(0xFF2D3748)),
                _buildLabeledContent(
                  'Online',
                  Text(
                    '${appState.meshStatus?.onlineCount ?? 0} / ${appState.meshStatus?.peerCount ?? 0}',
                    style: const TextStyle(
                      color: Color(0xFFA0AEC0),
                      fontSize: 13,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
                _buildLabeledContent(
                  'Direct',
                  Text(
                    '${appState.meshPeers.where((p) => (p.endpoint ?? '').isNotEmpty).length}',
                    style: const TextStyle(
                      color: Color(0xFF718096),
                      fontSize: 13,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
                _buildLabeledContent(
                  'Relayed',
                  Text(
                    '${appState.meshPeers.where((p) => (p.endpoint ?? '').isEmpty && (p.relayEndpoint ?? '').isNotEmpty).length}',
                    style: const TextStyle(
                      color: Color(0xFF718096),
                      fontSize: 13,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(width: 16),

        // Bandwidth card
        Expanded(
          child: _buildCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildCardHeader('Bandwidth', Icons.swap_horiz),
                const Divider(color: Color(0xFF2D3748)),
                _buildLabeledContent(
                  'Received',
                  Text(
                    _formatBytes(appState.meshStatus?.totalRxBytes ?? 0),
                    style: const TextStyle(
                      color: Colors.blue,
                      fontSize: 13,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
                _buildLabeledContent(
                  'Sent',
                  Text(
                    _formatBytes(appState.meshStatus?.totalTxBytes ?? 0),
                    style: const TextStyle(
                      color: Colors.orange,
                      fontSize: 13,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
                _buildLabeledContent(
                  'Total',
                  Text(
                    _formatBytes(
                      (appState.meshStatus?.totalRxBytes ?? 0) +
                          (appState.meshStatus?.totalTxBytes ?? 0),
                    ),
                    style: const TextStyle(
                      color: Color(0xFF718096),
                      fontSize: 13,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildServerHealthCard(AppState appState) {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'Server Health',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const Spacer(),
              _buildStatusDot(appState.isServerHealthy),
            ],
          ),
          const Divider(color: Color(0xFF2D3748)),
          if (appState.healthStatus != null) ...[
            _buildLabeledContent(
              'Status',
              _buildBadge(
                text: appState.healthStatus!.status.toUpperCase(),
                color: appState.isServerHealthy ? Colors.green : Colors.red,
              ),
            ),
            _buildLabeledContent(
              'Service',
              Text(
                appState.healthStatus!.service,
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ] else ...[
            Row(
              children: [
                Icon(
                  Icons.warning_amber,
                  size: 16,
                  color: Colors.orange.shade400,
                ),
                const SizedBox(width: 8),
                const Text(
                  'Unable to reach server',
                  style: TextStyle(
                    color: Color(0xFFA0AEC0),
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ],
          const SizedBox(height: 8),
          _buildLabeledContent(
            'URL',
            Text(
              '${appState.serverHost}:${appState.serverPort}',
              style: const TextStyle(
                color: Color(0xFF718096),
                fontSize: 11,
                fontFamily: 'monospace',
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildConnectionStatusCard(AppState appState) {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'Connection',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const Spacer(),
              _buildBadge(
                text: appState.isAuthenticated ? 'ACTIVE' : 'INACTIVE',
                color: appState.isAuthenticated ? const Color(0xFF2A9D8F) : Colors.grey,
              ),
            ],
          ),
          const Divider(color: Color(0xFF2D3748)),
          if (appState.tunnelIP != null)
            _buildLabeledContent(
              'Tunnel IP',
              Text(
                appState.tunnelIP!,
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          if (appState.userId != null)
            _buildLabeledContent(
              'User ID',
              Text(
                appState.userId!,
                style: const TextStyle(
                  color: Color(0xFF718096),
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          if (appState.publicKeyBase64 != null)
            _buildLabeledContent(
              'Public Key',
              Text(
                '${appState.publicKeyBase64!.substring(0, appState.publicKeyBase64!.length.clamp(0, 20))}...',
                style: const TextStyle(
                  color: Color(0xFF718096),
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          if (appState.connectedSince != null)
            _buildLabeledContent(
              'Connected Since',
              Text(
                _formatRelativeTime(appState.connectedSince!),
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 12,
                ),
              ),
            ),
          if (appState.isMeshEnabled) ...[
            const Divider(color: Color(0xFF2D3748)),
            _buildLabeledContent(
              'Mesh Peers',
              Text(
                '${appState.meshStatus?.onlineCount ?? 0}/${appState.meshStatus?.peerCount ?? 0} online',
                style: const TextStyle(
                  color: Color(0xFF718096),
                  fontSize: 12,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildNetworkInfoCard(AppState appState) {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Text(
                'Network',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const Divider(color: Color(0xFF2D3748)),
          if (appState.stats != null) ...[
            _buildLabeledContent(
              'Service',
              Text(
                appState.stats!.service,
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            _buildLabeledContent(
              'Peer Count',
              Text(
                '${appState.stats!.peerCount}',
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
              ),
            ),
            _buildLabeledContent(
              'Private API',
              _buildBadge(
                text: appState.stats!.privateApiEnabled ? 'ENABLED' : 'DISABLED',
                color: appState.stats!.privateApiEnabled
                    ? const Color(0xFF2A9D8F)
                    : Colors.grey,
              ),
            ),
          ] else
            const Text(
              'No stats available',
              style: TextStyle(
                color: Color(0xFF718096),
                fontSize: 13,
              ),
            ),
          const SizedBox(height: 8),
          _buildLabeledContent(
            'Mesh Servers',
            Text(
              '${appState.servers.where((s) => s.available).length}/${appState.servers.length} healthy',
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

  Widget _buildTrustCard(AppState appState) {
    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Text(
                'Trust Status',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const Divider(color: Color(0xFF2D3748)),
          if (appState.trustStatus != null) ...[
            _buildLabeledContent(
              'Our Tier',
              _buildBadge(
                text: 'TIER ${appState.trustStatus!.trustTier}',
                color: appState.trustStatus!.trustTier == 1
                    ? Colors.green
                    : Colors.orange,
              ),
            ),
            _buildLabeledContent(
              'Platform',
              Text(
                appState.trustStatus!.ourPlatform,
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 13,
                ),
              ),
            ),
            _buildLabeledContent(
              'TEE Required',
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    appState.trustStatus!.requireTee
                        ? Icons.check_circle
                        : Icons.cancel,
                    size: 16,
                    color: appState.trustStatus!.requireTee
                        ? Colors.green
                        : const Color(0xFF718096),
                  ),
                ],
              ),
            ),
            _buildLabeledContent(
              'Trusted Peers',
              Text(
                '${appState.trustStatus!.peerCount}',
                style: const TextStyle(
                  color: Color(0xFFA0AEC0),
                  fontSize: 13,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ] else
            const Text(
              'Trust data unavailable',
              style: TextStyle(
                color: Color(0xFF718096),
                fontSize: 13,
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildActivitySection(AppState appState) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            const Icon(
              Icons.list_alt,
              color: Color(0xFFE9C46A),
              size: 18,
            ),
            const SizedBox(width: 8),
            const Text(
              'Recent Activity',
              style: TextStyle(
                color: Colors.white,
                fontSize: 14,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        if (appState.activityLog.isEmpty)
          _buildCard(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Center(
                child: Text(
                  'No recent activity',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.4),
                    fontSize: 13,
                  ),
                ),
              ),
            ),
          )
        else
          _buildCard(
            child: Column(
              children: appState.activityLog.take(10).map((entry) {
                return _buildActivityRow(entry);
              }).toList(),
            ),
          ),
      ],
    );
  }

  Widget _buildActivityRow(ActivityEntry entry) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(
            color: const Color(0xFF2D3748),
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: _getActivityColor(entry.level),
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              entry.message,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 12,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          Text(
            _formatRelativeTime(entry.timestamp),
            style: const TextStyle(
              color: Color(0xFF718096),
              fontSize: 10,
            ),
          ),
        ],
      ),
    );
  }

  Color _getActivityColor(ActivityLevel level) {
    switch (level) {
      case ActivityLevel.info:
        return Colors.blue;
      case ActivityLevel.success:
        return Colors.green;
      case ActivityLevel.warning:
        return Colors.orange;
      case ActivityLevel.error:
        return Colors.red;
    }
  }

  String _formatRelativeTime(DateTime time) {
    final diff = DateTime.now().difference(time);
    if (diff.inSeconds < 60) {
      return '${diff.inSeconds}s ago';
    } else if (diff.inMinutes < 60) {
      return '${diff.inMinutes}m ago';
    } else if (diff.inHours < 24) {
      return '${diff.inHours}h ago';
    } else {
      return '${diff.inDays}d ago';
    }
  }

  String _formatBytes(int bytes) {
    final kb = bytes / 1024;
    final mb = kb / 1024;
    final gb = mb / 1024;

    if (gb >= 1) {
      return '${gb.toStringAsFixed(1)} GB';
    } else if (mb >= 1) {
      return '${mb.toStringAsFixed(1)} MB';
    } else if (kb >= 1) {
      return '${kb.toStringAsFixed(0)} KB';
    } else {
      return '$bytes B';
    }
  }

  Widget _buildCard({required Widget child}) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1A2E).withOpacity(0.5),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: const Color(0xFF2D3748),
          width: 1,
        ),
      ),
      child: child,
    );
  }

  Widget _buildCardHeader(String title, IconData icon) {
    return Row(
      children: [
        Icon(
          icon,
          color: const Color(0xFFE9C46A),
          size: 16,
        ),
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
    );
  }

  Widget _buildLabeledContent(String label, Widget value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(
              label,
              style: const TextStyle(
                color: Color(0xFF718096),
                fontSize: 12,
              ),
            ),
          ),
          Expanded(child: value),
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
        style: TextStyle(
          color: color,
          fontSize: 10,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }

  Widget _buildStatusDot(bool isHealthy) {
    return Container(
      width: 8,
      height: 8,
      decoration: BoxDecoration(
        color: isHealthy ? Colors.green : Colors.red,
        shape: BoxShape.circle,
      ),
    );
  }
}
