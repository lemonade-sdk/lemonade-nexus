/// @title Main Navigation
/// @description Main navigation shell with sidebar and content area.
///
/// Provides the primary navigation structure for the authenticated app.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../views/dashboard_view.dart';
import '../views/tunnel_control_view.dart';
import '../views/peers_view.dart';
import '../views/network_monitor_view.dart';
import '../views/tree_browser_view.dart';
import '../views/servers_view.dart';
import '../views/certificates_view.dart';
import '../views/settings_view.dart';

class MainNavigation extends ConsumerStatefulWidget {
  const MainNavigation({super.key});

  @override
  ConsumerState<MainNavigation> createState() => _MainNavigationState();
}

class _MainNavigationState extends ConsumerState<MainNavigation> {
  bool _sidebarCollapsed = false;

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final selectedView = appState.selectedSidebarItem;

    return Scaffold(
      body: Row(
        children: [
          // Sidebar
          AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            width: _sidebarCollapsed ? 60 : 240,
            decoration: BoxDecoration(
              color: const Color(0xFF1A1A2E).withOpacity(0.95),
              border: Border(
                right: BorderSide(
                  color: const Color(0xFF2D3748),
                  width: 1,
                ),
              ),
            ),
            child: _buildSidebar(appState),
          ),

          // Main content area
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    const Color(0xFF1A1A2E),
                    const Color(0xFF16213E),
                    const Color(0xFF0F3460),
                  ],
                ),
              ),
              child: SafeArea(
                child: _buildContentView(selectedView),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSidebar(appState) {
    return Column(
      children: [
        // Logo area
        _buildLogo(),

        const SizedBox(height: 16),

        // Navigation items
        Expanded(
          child: ListView(
            padding: const EdgeInsets.symmetric(vertical: 8),
            children: SidebarItem.values.map((item) {
              return _buildSidebarItem(item, appState);
            }).toList(),
          ),
        ),

        // Bottom actions
        _buildBottomActions(),
      ],
    );
  }

  Widget _buildLogo() {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          SizedBox(
            width: 32,
            height: 32,
            child: Stack(
              alignment: Alignment.center,
              children: [
                Container(
                  width: 26,
                  height: 18,
                  decoration: BoxDecoration(
                    color: const Color(0xFFE9C46A),
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                Container(
                  width: 8,
                  height: 8,
                  decoration: const BoxDecoration(
                    color: Color(0xFF2A9D8F),
                    shape: BoxShape.circle,
                  ),
                ),
              ],
            ),
          ),
          if (!_sidebarCollapsed) ...[
            const SizedBox(width: 12),
            const Text(
              'Nexus',
              style: TextStyle(
                color: Color(0xFFE9C46A),
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildSidebarItem(SidebarItem item, appState) {
    final isSelected = appState.selectedSidebarItem == item;

    return ListTile(
      selected: isSelected,
      selectedTileColor: const Color(0xFFE9C46A).withOpacity(0.2),
      leading: Icon(
        item.icon,
        color: isSelected
            ? const Color(0xFFE9C46A)
            : Colors.white.withOpacity(0.6),
        size: 22,
      ),
      title: _sidebarCollapsed
          ? null
          : Text(
              item.label,
              style: TextStyle(
                color: isSelected
                    ? const Color(0xFFE9C46A)
                    : Colors.white.withOpacity(0.8),
                fontSize: 14,
                fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
              ),
            ),
      onTap: () {
        ref.read(appNotifierProvider.notifier).setSelectedSidebarItem(item);
      },
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
      ),
      contentPadding: _sidebarCollapsed
          ? const EdgeInsets.symmetric(horizontal: 16, vertical: 4)
          : const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
    );
  }

  Widget _buildBottomActions() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        border: Border(
          top: BorderSide(
            color: const Color(0xFF2D3748),
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // Connection status indicator
          Consumer(
            builder: (context, ref, child) {
              final appState = ref.watch(appNotifierProvider);
              return Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                decoration: BoxDecoration(
                  color: appState.isConnected
                      ? Colors.green.withOpacity(0.1)
                      : Colors.grey.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                        color: appState.isConnected ? Colors.green : Colors.grey,
                        shape: BoxShape.circle,
                      ),
                    ),
                    if (!_sidebarCollapsed) ...[
                      const SizedBox(width: 8),
                      Text(
                        appState.isConnected ? 'Connected' : 'Disconnected',
                        style: TextStyle(
                          color: appState.isConnected
                              ? Colors.green
                              : Colors.grey,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ],
                ),
              );
            },
          ),

          const SizedBox(height: 8),

          // Collapse/expand button
          IconButton(
            icon: Icon(
              _sidebarCollapsed
                  ? Icons.chevron_right
                  : Icons.chevron_left,
              color: Colors.white.withOpacity(0.6),
            ),
            onPressed: () {
              setState(() {
                _sidebarCollapsed = !_sidebarCollapsed;
              });
            },
            tooltip: _sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar',
          ),

          // Settings
          ListTile(
            selected: false,
            leading: Icon(
              Icons.logout,
              color: Colors.white.withOpacity(0.6),
              size: 22,
            ),
            title: _sidebarCollapsed
                ? null
                : const Text(
                    'Sign Out',
                    style: TextStyle(
                      color: Color(0xFFE9C46A),
                      fontSize: 14,
                    ),
                  ),
            onTap: () {
              _showSignOutConfirmation();
            },
          ),
        ],
      ),
    );
  }

  void _showSignOutConfirmation() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1A1A2E),
        title: const Text(
          'Sign Out',
          style: TextStyle(color: Colors.white),
        ),
        content: const Text(
          'Are you sure you want to sign out?',
          style: TextStyle(color: Color(0xFFA0AEC0)),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text(
              'Cancel',
              style: TextStyle(color: Color(0xFFA0AEC0)),
            ),
          ),
          ElevatedButton(
            onPressed: () {
              ref.read(appNotifierProvider.notifier).signOut();
              Navigator.pop(context);
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
            ),
            child: const Text('Sign Out'),
          ),
        ],
      ),
    );
  }

  Widget _buildContentView(SidebarItem selectedView) {
    switch (selectedView) {
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
        return const ServersView(); // Reuse servers view for relays
      case SidebarItem.settings:
        return const SettingsView();
    }
  }
}
