/// @title Tunnel Control View
/// @description WireGuard tunnel controls and status.
///
/// Matches macOS TunnelControlView.swift functionality:
/// - Tunnel connect/disconnect toggle
/// - Mesh enable/disable toggle
/// - Connection details card
/// - Status indicators

import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../windows/windows_integration.dart';

class TunnelControlView extends ConsumerStatefulWidget {
  const TunnelControlView({super.key});

  @override
  ConsumerState<TunnelControlView> createState() => _TunnelControlViewState();
}

class _TunnelControlViewState extends ConsumerState<TunnelControlView> {
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
    _refreshTimer = Timer.periodic(const Duration(seconds: 3), (_) {
      ref.read(appNotifierProvider.notifier).refreshTunnelStatus();
    });
  }

  /// Update system tray when tunnel state changes
  void _updateSystemTray(AppState appState) {
    if (!Platform.isWindows) return;

    // Update tray icon tooltip and menu
    try {
      final integration = ref.read(windowsIntegrationProvider);
      integration.updateTrayConnectionState();
    } catch (e) {
      // System tray may not be initialized
    }
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);

    // Update system tray when tunnel state changes
    _updateSystemTray(appState);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          _buildHeader(appState),

          const SizedBox(height: 24),

          // Tunnel Card
          _buildTunnelCard(appState),

          const SizedBox(height: 16),

          // Mesh Card
          _buildMeshCard(appState),

          const SizedBox(height: 24),

          // Connection Details
          if (appState.isTunnelUp || appState.isMeshEnabled)
            _buildConnectionDetailsCard(appState),
        ],
      ),
    );
  }

  Widget _buildHeader(AppState appState) {
    return Row(
      children: [
        const Icon(
          Icons.security,
          color: Color(0xFFE9C46A),
          size: 24,
        ),
        const SizedBox(width: 12),
        const Text(
          'WireGuard Tunnel',
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
            ref.read(appNotifierProvider.notifier).refreshTunnelStatus();
            ref.read(appNotifierProvider.notifier).refreshMeshStatus();
          },
          tooltip: 'Refresh Status',
        ),
      ],
    );
  }

  Widget _buildTunnelCard(AppState appState) {
    return _buildCard(
      child: Row(
        children: [
          // Status indicator
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: (appState.isTunnelUp ? Colors.green : Colors.red)
                  .withOpacity(0.15),
              borderRadius: BorderRadius.circular(28),
            ),
            child: Icon(
              appState.isTunnelUp
                  ? Icons.check_circle
                  : Icons.cancel,
              color: appState.isTunnelUp ? Colors.green : Colors.red,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),

          // Info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'VPN Tunnel',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  appState.isTunnelUp ? 'Active' : 'Inactive',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.6),
                    fontSize: 13,
                  ),
                ),
                if (appState.tunnelIP != null && appState.tunnelIP!.isNotEmpty)
                  Text(
                    appState.tunnelIP!,
                    style: const TextStyle(
                      color: Color(0xFF718096),
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                  ),
              ],
            ),
          ),

          // Uptime
          if (appState.isTunnelUp && appState.connectedSince != null)
            Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  'Uptime',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.4),
                    fontSize: 11,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  _formatUptime(appState.connectedSince!),
                  style: const TextStyle(
                    color: Color(0xFFA0AEC0),
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),

          const SizedBox(width: 16),

          // Action button
          ElevatedButton(
            onPressed: appState.isTunnelUp
                ? () => ref.read(appNotifierProvider.notifier).disconnectTunnel()
                : () => ref.read(appNotifierProvider.notifier).connectTunnel(),
            style: ElevatedButton.styleFrom(
              backgroundColor: appState.isTunnelUp
                  ? Colors.red.shade600
                  : const Color(0xFFE9C46A),
              foregroundColor: appState.isTunnelUp
                  ? Colors.white
                  : Colors.black,
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            child: Text(
              appState.isTunnelUp ? 'Disconnect' : 'Connect',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 14,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMeshCard(AppState appState) {
    return _buildCard(
      child: Row(
        children: [
          // Status indicator
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: (appState.isMeshEnabled
                      ? const Color(0xFF2A9D8F)
                      : Colors.grey)
                  .withOpacity(0.15),
              borderRadius: BorderRadius.circular(28),
            ),
            child: Icon(
              appState.isMeshEnabled
                  ? Icons.people
                  : Icons.people_outline,
              color: appState.isMeshEnabled
                  ? const Color(0xFF2A9D8F)
                  : Colors.grey,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),

          // Info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'P2P Mesh Networking',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  appState.isMeshEnabled ? 'Active' : 'Inactive',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.6),
                    fontSize: 13,
                  ),
                ),
                if (appState.meshStatus != null)
                  Text(
                    '${appState.meshStatus!.onlineCount}/${appState.meshStatus!.peerCount} peers online',
                    style: const TextStyle(
                      color: Color(0xFF718096),
                      fontSize: 11,
                    ),
                  ),
              ],
            ),
          ),

          // Action button
          ElevatedButton(
            onPressed: () => ref.read(appNotifierProvider.notifier).toggleMesh(),
            style: ElevatedButton.styleFrom(
              backgroundColor: appState.isMeshEnabled
                  ? Colors.transparent
                  : const Color(0xFF2A9D8F),
              foregroundColor: appState.isMeshEnabled
                  ? Colors.white
                  : Colors.black,
              side: appState.isMeshEnabled
                  ? const BorderSide(color: Color(0xFF2A9D8F))
                  : null,
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            child: Text(
              appState.isMeshEnabled ? 'Disable' : 'Enable',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 14,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildConnectionDetailsCard(AppState appState) {
    final status = appState.meshStatus;

    return _buildCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(
                Icons.info_outline,
                color: Color(0xFFE9C46A),
                size: 18,
              ),
              const SizedBox(width: 8),
              const Text(
                'Connection Details',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Stats row
          Row(
            children: [
              Expanded(
                child: _buildStatItem(
                  'Tunnel IP',
                  status?.tunnelIp ?? 'N/A',
                  Icons.network,
                  const Color(0xFF2A9D8F),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildStatItem(
                  'Peers',
                  '${status?.peerCount ?? 0}',
                  Icons.people,
                  const Color(0xFFE9C46A),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildStatItem(
                  'Online',
                  '${status?.onlineCount ?? 0}',
                  Icons.wifi,
                  Colors.green,
                ),
              ),
            ],
          ),

          const SizedBox(height: 16),

          // Bandwidth info
          Row(
            children: [
              Expanded(
                child: Row(
                  children: [
                    Icon(
                      Icons.arrow_downward_circle,
                      size: 16,
                      color: Colors.blue.shade400,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _formatBytes(status?.totalRxBytes ?? 0),
                      style: TextStyle(
                        color: Colors.blue.shade400,
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(width: 4),
                    Text(
                      'received',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.5),
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: Row(
                  children: [
                    Icon(
                      Icons.arrow_upward_circle,
                      size: 16,
                      color: Colors.orange.shade400,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _formatBytes(status?.totalTxBytes ?? 0),
                      style: TextStyle(
                        color: Colors.orange.shade400,
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(width: 4),
                    Text(
                      'sent',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.5),
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildStatItem(
    String label,
    String value,
    IconData icon,
    Color color,
  ) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(
              color: Colors.white.withOpacity(0.6),
              fontSize: 11,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 14,
              fontWeight: FontWeight.bold,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCard({required Widget child}) {
    return Container(
      padding: const EdgeInsets.all(20),
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

  String _formatUptime(DateTime since) {
    final interval = DateTime.now().difference(since);
    final hours = interval.inHours;
    final minutes = interval.inMinutes % 60;
    if (hours > 0) {
      return '${hours}h ${minutes}m';
    }
    return '${minutes}m';
  }

  String _formatBytes(int bytes) {
    if (bytes == 0) return '0 B';
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
}
