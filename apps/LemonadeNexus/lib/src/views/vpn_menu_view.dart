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

class VPNMenuView extends ConsumerWidget {
  const VPNMenuView({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appState = ref.watch(appNotifierProvider);

    return Container(
      constraints: const BoxConstraints(minWidth: 200),
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          // Status Section
          _buildStatusSection(appState),
          const Divider(height: 16),
          // Connect/Disconnect Button
          if (appState.isAuthenticated) ...[
            _buildConnectButton(appState),
            const Divider(height: 16),
          ],
          // Open Manager Button
          _buildMenuItem(
            icon: Icons.dashboard,
            label: 'Open Manager',
            shortcut: 'O',
            onTap: () {
              // Bring main window to front
              // This is handled by the tray manager
            },
          ),
          const Divider(height: 16),
          // Quit Button
          _buildMenuItem(
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

  Widget _buildStatusSection(AppState appState) {
    if (!appState.isAuthenticated) {
      return _buildStatusItem(
        icon: Icons.person_off,
        label: 'Not signed in',
        color: const Color(0xFFA0AEC0),
      );
    }

    if (appState.isTunnelUp) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildStatusItem(
            icon: Icons.check_circle,
            label: 'VPN: Connected',
            color: Colors.green,
          ),
          if (appState.tunnelIP != null && appState.tunnelIP!.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(left: 24, top: 4),
              child: Text(
                'IP: ${appState.tunnelIP}',
                style: TextStyle(
                  color: const Color(0xFFA0AEC0),
                  fontSize: 11,
                  fontFamily: 'monospace',
                ),
              ),
            ),
        ],
      );
    }

    return _buildStatusItem(
      icon: Icons.cancel,
      label: 'VPN: Disconnected',
      color: const Color(0xFFA0AEC0),
    );
  }

  Widget _buildStatusItem({
    required IconData icon,
    required String label,
    required Color color,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(
        children: [
          Icon(icon, size: 16, color: color),
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

  Widget _buildConnectButton(AppState appState) {
    final isConnecting = appState.isTunnelUp == false && appState.tunnelIP == null;
    final isDisconnecting = appState.isTunnelUp == true && appState.tunnelIP == null;
    final isBusy = isConnecting || isDisconnecting;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      child: Material(
        color: appState.isTunnelUp ? Colors.red.shade600 : const Color(0xFF2A9D8F),
        borderRadius: BorderRadius.circular(6),
        child: InkWell(
          onTap: isBusy
              ? null
              : () {
                  final notifier = ref.read(appNotifierProvider.notifier);
                  if (appState.isTunnelUp) {
                    notifier.disconnectTunnel();
                  } else {
                    notifier.connectTunnel();
                  }
                },
          borderRadius: BorderRadius.circular(6),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            child: Row(
              children: [
                if (isBusy)
                  SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                    ),
                  )
                else
                  Icon(
                    appState.isTunnelUp ? Icons.close : Icons.play_arrow,
                    size: 16,
                    color: Colors.white,
                  ),
                const SizedBox(width: 8),
                Text(
                  appState.isTunnelUp ? 'Disconnect VPN' : 'Connect VPN',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildMenuItem({
    required IconData icon,
    required String label,
    required String shortcut,
    required VoidCallback onTap,
  }) {
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
                Icon(icon, size: 16, color: const Color(0xFFE9C46A)),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    label,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 12,
                    ),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: const Color(0xFF2D3748),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    shortcut,
                    style: TextStyle(
                      color: const Color(0xFFA0AEC0),
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
