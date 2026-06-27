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
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

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
        const SectionHeader(title: 'WireGuard Tunnel', icon: Icons.security),
        const Spacer(),
        IconButton(
          icon: const Icon(Icons.refresh, size: 20),
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
    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      padding: const EdgeInsets.all(20),
      child: Row(
        children: [
          // Status indicator
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: (appState.isTunnelUp
                      ? AppTheme.lemonGreen
                      : AppTheme.errorColor)
                  .withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(28),
            ),
            child: Icon(
              appState.isTunnelUp ? Icons.check_circle : Icons.cancel,
              color:
                  appState.isTunnelUp ? AppTheme.lemonGreen : AppTheme.errorColor,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),

          // Info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Text(
                      'VPN Tunnel',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(width: 8),
                    LemonBadge(
                      text: appState.isTunnelUp ? 'UP' : 'DOWN',
                      color: appState.isTunnelUp
                          ? AppTheme.lemonGreen
                          : Colors.grey,
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  appState.isTunnelUp ? 'Active' : 'Inactive',
                  style: TextStyle(
                    color: scheme.onSurfaceVariant,
                    fontSize: 13,
                  ),
                ),
                if (appState.tunnelIP != null && appState.tunnelIP!.isNotEmpty)
                  Text(
                    appState.tunnelIP!,
                    style: TextStyle(
                      color: scheme.onSurfaceVariant,
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
                    color: scheme.onSurfaceVariant,
                    fontSize: 11,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  _formatUptime(appState.connectedSince!),
                  style: const TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),

          const SizedBox(width: 16),

          // Action button
          appState.isTunnelUp
              ? ElevatedButton(
                  onPressed: () =>
                      ref.read(appNotifierProvider.notifier).disconnectTunnel(),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.errorColor,
                    foregroundColor: Colors.white,
                  ),
                  child: const Text('Disconnect'),
                )
              : ElevatedButton(
                  onPressed: () =>
                      ref.read(appNotifierProvider.notifier).connectTunnel(),
                  child: const Text('Connect'),
                ),
        ],
      ),
    );
  }

  Widget _buildMeshCard(AppState appState) {
    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      padding: const EdgeInsets.all(20),
      child: Row(
        children: [
          // Status indicator
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: (appState.isMeshEnabled
                      ? AppTheme.lemonGreen
                      : Colors.grey)
                  .withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(28),
            ),
            child: Icon(
              appState.isMeshEnabled ? Icons.people : Icons.people_outline,
              color:
                  appState.isMeshEnabled ? AppTheme.lemonGreen : Colors.grey,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),

          // Info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Text(
                      'P2P Mesh Networking',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(width: 8),
                    LemonBadge(
                      text: appState.isMeshEnabled ? 'ENABLED' : 'DISABLED',
                      color: appState.isMeshEnabled
                          ? AppTheme.lemonGreen
                          : Colors.grey,
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  appState.isMeshEnabled ? 'Active' : 'Inactive',
                  style: TextStyle(
                    color: scheme.onSurfaceVariant,
                    fontSize: 13,
                  ),
                ),
                if (appState.meshStatus != null)
                  Text(
                    '${appState.meshStatus!.onlineCount}/${appState.meshStatus!.peerCount} peers online',
                    style: TextStyle(
                      color: scheme.onSurfaceVariant,
                      fontSize: 11,
                    ),
                  ),
              ],
            ),
          ),

          // Action button
          appState.isMeshEnabled
              ? OutlinedButton(
                  onPressed: () =>
                      ref.read(appNotifierProvider.notifier).toggleMesh(),
                  child: const Text('Disable'),
                )
              : ElevatedButton(
                  onPressed: () =>
                      ref.read(appNotifierProvider.notifier).toggleMesh(),
                  child: const Text('Enable'),
                ),
        ],
      ),
    );
  }

  Widget _buildConnectionDetailsCard(AppState appState) {
    final status = appState.meshStatus;

    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(
            title: 'Connection Details',
            icon: Icons.info_outline,
          ),
          const SizedBox(height: 16),

          // Stats row
          Row(
            children: [
              Expanded(
                child: StatCard(
                  title: 'Tunnel IP',
                  value: status?.tunnelIp ?? 'N/A',
                  icon: Icons.lan,
                  color: AppTheme.lemonGreen,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: StatCard(
                  title: 'Peers',
                  value: '${status?.peerCount ?? 0}',
                  icon: Icons.people,
                  color: AppTheme.lemonYellowDark,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: StatCard(
                  title: 'Online',
                  value: '${status?.onlineCount ?? 0}',
                  icon: Icons.wifi,
                  color: AppTheme.lemonGreen,
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
                    const Icon(
                      Icons.arrow_circle_down,
                      size: 16,
                      color: AppTheme.infoColor,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _formatBytes(status?.totalRxBytes ?? 0),
                      style: const TextStyle(
                        color: AppTheme.infoColor,
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(width: 4),
                    Text(
                      'received',
                      style: TextStyle(
                        color: scheme.onSurfaceVariant,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: Row(
                  children: [
                    const Icon(
                      Icons.arrow_circle_up,
                      size: 16,
                      color: AppTheme.nodeOrange,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _formatBytes(status?.totalTxBytes ?? 0),
                      style: const TextStyle(
                        color: AppTheme.nodeOrange,
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(width: 4),
                    Text(
                      'sent',
                      style: TextStyle(
                        color: scheme.onSurfaceVariant,
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
