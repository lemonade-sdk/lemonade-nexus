/// @title VPN Menu View
/// @description Menu bar tray dropdown showing VPN status and quick actions.
///
/// Matches macOS VPNMenuView.swift functionality:
/// - VPN status indicator
/// - Tunnel IP display
/// - Connect/Disconnect button
/// - Open Manager button
/// - Quit button
///
/// Note: This view is designed to be used in a system tray context menu.
/// For the main app window, use TunnelControlView instead.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class VPNMenuView extends ConsumerWidget {
  const VPNMenuView({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appState = ref.watch(appNotifierProvider);
    final scheme = Theme.of(context).colorScheme;

    return Container(
      constraints: const BoxConstraints(minWidth: 200),
      padding: const EdgeInsets.symmetric(vertical: 8),
      color: scheme.surface,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          // Status Section
          _buildStatusSection(context, appState),
          Divider(height: 16, color: scheme.outline),
          // Connect/Disconnect Button
          if (appState.isAuthenticated) ...[
            _buildConnectButton(appState, ref),
            Divider(height: 16, color: scheme.outline),
          ],
          // Open Manager Button
          _buildMenuItem(
            context: context,
            icon: Icons.dashboard,
            label: 'Open Manager',
            shortcut: 'O',
            onTap: () {
              // Bring main window to front
              // This is handled by the tray manager
            },
          ),
          Divider(height: 16, color: scheme.outline),
          // Quit Button
          _buildMenuItem(
            context: context,
            icon: Icons.close,
            label: 'Quit Lemonade Nexus',
            shortcut: 'Q',
            onTap: () {
              // Quit application
              // This is handled by the tray manager
            },
          ),
        ],
      ),
    );
  }

  Widget _buildStatusSection(BuildContext context, AppState appState) {
    final scheme = Theme.of(context).colorScheme;

    if (!appState.isAuthenticated) {
      return _buildStatusItem(
        context: context,
        isHealthy: false,
        label: 'Not signed in',
        color: scheme.onSurfaceVariant,
      );
    }

    if (appState.isTunnelUp) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildStatusItem(
            context: context,
            isHealthy: true,
            label: 'VPN: Connected',
            color: AppTheme.lemonGreen,
          ),
          if (appState.tunnelIP != null && appState.tunnelIP!.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(left: 24, top: 4),
              child: Text(
                'IP: ${appState.tunnelIP}',
                style: TextStyle(
                  color: scheme.onSurfaceVariant,
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
        ],
      );
    }

    return _buildStatusItem(
      context: context,
      isHealthy: false,
      label: 'VPN: Disconnected',
      color: scheme.onSurfaceVariant,
    );
  }

  Widget _buildStatusItem({
    required BuildContext context,
    required bool isHealthy,
    required String label,
    required Color color,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(
        children: [
          StatusDot(isHealthy: isHealthy, size: 10),
          const SizedBox(width: 8),
          Text(
            label,
            style: TextStyle(
              color: color,
              fontSize: 12,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildConnectButton(AppState appState, WidgetRef ref) {
    final isConnecting = appState.isTunnelUp == false && appState.tunnelIP == null;
    final isDisconnecting = appState.isTunnelUp == true && appState.tunnelIP == null;
    final isBusy = isConnecting || isDisconnecting;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      child: SizedBox(
        width: double.infinity,
        child: ElevatedButton(
          style: appState.isTunnelUp
              ? ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.errorColor,
                  foregroundColor: Colors.white,
                )
              : null,
          onPressed: isBusy
              ? null
              : () {
                  final notifier = ref.read(appNotifierProvider.notifier);
                  if (appState.isTunnelUp) {
                    notifier.disconnectTunnel();
                  } else {
                    notifier.connectTunnel();
                  }
                },
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (isBusy)
                const SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              else
                Icon(
                  appState.isTunnelUp ? Icons.close : Icons.play_arrow,
                  size: 16,
                ),
              const SizedBox(width: 8),
              Text(
                appState.isTunnelUp ? 'Disconnect VPN' : 'Connect VPN',
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMenuItem({
    required BuildContext context,
    required IconData icon,
    required String label,
    required String shortcut,
    required VoidCallback onTap,
  }) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 4),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(6),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
            child: Row(
              children: [
                Icon(icon, size: 16, color: AppTheme.lemonYellowDark),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    label,
                    style: const TextStyle(
                      fontSize: 12,
                    ),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: scheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    shortcut,
                    style: TextStyle(
                      color: scheme.onSurfaceVariant,
                      fontSize: 10,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
