/// @title Main Navigation
/// @description Sidebar + detail shell, styled like the macOS NavigationSplitView.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/app_state.dart';
import '../state/providers.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';
import 'dashboard_view.dart';
import 'tunnel_control_view.dart';
import 'peers_view.dart';
import 'network_monitor_view.dart';
import 'tree_browser_view.dart';
import 'servers_view.dart';
import 'certificates_view.dart';
import 'settings_view.dart';

class MainNavigation extends ConsumerWidget {
  const MainNavigation({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appState = ref.watch(appNotifierProvider);
    final scheme = Theme.of(context).colorScheme;

    return Scaffold(
      body: Row(
        children: [
          Container(
            width: 220,
            decoration: BoxDecoration(
              color: scheme.surface,
              border: Border(right: BorderSide(color: scheme.outline, width: 0.5)),
            ),
            child: _Sidebar(appState: appState),
          ),
          Expanded(child: _content(appState.selectedSidebarItem)),
        ],
      ),
    );
  }

  Widget _content(SidebarItem item) {
    switch (item) {
      case SidebarItem.dashboard:
        return const DashboardView();
      case SidebarItem.tunnel:
        return const TunnelControlView();
      case SidebarItem.peers:
        return const PeersView();
      case SidebarItem.network:
        return const NetworkMonitorView();
      case SidebarItem.endpoints:
        return const TreeBrowserView();
      case SidebarItem.servers:
        return const ServersView();
      case SidebarItem.certificates:
        return const CertificatesView();
      case SidebarItem.relays:
        return const ServersView();
      case SidebarItem.settings:
        return const SettingsView();
    }
  }
}

class _Sidebar extends ConsumerWidget {
  final AppState appState;
  const _Sidebar({required this.appState});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final scheme = Theme.of(context).colorScheme;
    return Column(
      children: [
        const SizedBox(height: 12),
        _header(scheme),
        Divider(height: 16, color: scheme.outline),
        Expanded(
          child: ListView(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            children: SidebarItem.values
                .map((item) => _item(context, ref, item))
                .toList(),
          ),
        ),
        Divider(height: 1, color: scheme.outline),
        _footer(context, ref, scheme),
      ],
    );
  }

  Widget _header(ColorScheme scheme) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: AppTheme.lemonYellow.withValues(alpha: 0.2),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.shield_outlined, color: AppTheme.lemonYellowDark, size: 18),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Lemonade Nexus',
                    style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
                const SizedBox(height: 2),
                Row(
                  children: [
                    StatusDot(isHealthy: appState.isServerHealthy, size: 6),
                    const SizedBox(width: 4),
                    Text(
                      appState.isServerHealthy ? 'Connected' : 'Disconnected',
                      style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _item(BuildContext context, WidgetRef ref, SidebarItem item) {
    final scheme = Theme.of(context).colorScheme;
    final selected = appState.selectedSidebarItem == item;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 1),
      child: Material(
        color: selected ? AppTheme.lemonYellow.withValues(alpha: 0.18) : Colors.transparent,
        borderRadius: BorderRadius.circular(6),
        child: InkWell(
          borderRadius: BorderRadius.circular(6),
          onTap: () =>
              ref.read(appNotifierProvider.notifier).setSelectedSidebarItem(item),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
            child: Row(
              children: [
                Icon(item.icon,
                    size: 18,
                    color: selected ? AppTheme.lemonYellowDark : scheme.onSurfaceVariant),
                const SizedBox(width: 10),
                Text(
                  item.label,
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: selected ? FontWeight.w600 : FontWeight.normal,
                    color: selected ? scheme.onSurface : scheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _footer(BuildContext context, WidgetRef ref, ColorScheme scheme) {
    final username = appState.username;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(
        children: [
          Icon(Icons.account_circle_outlined, size: 18, color: scheme.onSurfaceVariant),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              (username == null || username.isEmpty) ? 'User' : username,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant),
            ),
          ),
          IconButton(
            tooltip: 'Sign Out',
            visualDensity: VisualDensity.compact,
            icon: Icon(Icons.logout, size: 16, color: scheme.onSurfaceVariant),
            onPressed: () => ref.read(appNotifierProvider.notifier).signOut(),
          ),
        ],
      ),
    );
  }
}
