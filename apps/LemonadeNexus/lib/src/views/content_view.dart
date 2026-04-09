/// @title Content View
/// @description Main container with sidebar navigation.
///
/// Matches macOS ContentView.swift functionality:
/// - Sidebar navigation with all sections
/// - Header with connection status
/// - Footer with user info and sign out
/// - Detail view based on selected item

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import 'dashboard_view.dart';
import 'tunnel_control_view.dart';
import 'peers_view.dart';
import 'network_monitor_view.dart';
import 'tree_browser_view.dart';
import 'servers_view.dart';
import 'certificates_view.dart';
import 'settings_view.dart';

class ContentView extends ConsumerStatefulWidget {
  const ContentView({super.key});

  @override
  ConsumerState<ContentView> createState() => _ContentViewState();
}

class _ContentViewState extends ConsumerState<ContentView> {
  @override
  void initState() {
    super.initState();
    // Refresh data on initial load
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final notifier = ref.read(appNotifierProvider.notifier);
      notifier.refreshAllData();
    });
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);

    return Scaffold(
      body: Row(
        children: [
          // Sidebar
          _buildSidebar(appState),

          // Vertical divider
          const VerticalDivider(
            thickness: 1,
            width: 1,
            color: Color(0xFF2D3748),
          ),

          // Detail view
          Expanded(
            child: _buildDetailView(appState),
          ),
        ],
      ),
    );
  }

  Widget _buildSidebar(AppState appState) {
    return Container(
      width: 260,
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A2E),
      ),
      child: Column(
        children: [
          // Sidebar Header
          _buildSidebarHeader(appState),

          const SizedBox(height: 8),

          // Navigation items
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(vertical: 8),
              children: SidebarItem.values.map((item) {
                return _buildSidebarItem(
                  item,
                  appState.selectedSidebarItem == item,
                  () {
                    ref.read(appNotifierProvider.notifier).setSelectedSidebarItem(item);
                  },
                );
              }).toList(),
            ),
          ),

          // Sidebar Footer
          _buildSidebarFooter(appState),
        ],
      ),
    );
  }

  Widget _buildSidebarHeader(AppState appState) {
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
      child: Column(
        children: [
          Row(
            children: [
              // Logo
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: const Color(0xFFE9C46A).withOpacity(0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(
                  Icons.security,
                  color: Color(0xFFE9C46A),
                  size: 22,
                ),
              ),
              const SizedBox(width: 12),
              // Title and status
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Lemonade Nexus',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 15,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Row(
                      children: [
                        _buildStatusDot(appState.isServerHealthy),
                        const SizedBox(width: 6),
                        Text(
                          appState.isServerHealthy ? 'Connected' : 'Disconnected',
                          style: const TextStyle(
                            color: Color(0xFFA0AEC0),
                            fontSize: 11,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          const Divider(
            color: Color(0xFF2D3748),
            height: 1,
          ),
        ],
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
        boxShadow: [
          BoxShadow(
            color: (isHealthy ? Colors.green : Colors.red).withOpacity(0.5),
            blurRadius: 4,
            spreadRadius: 1,
          ),
        ],
      ),
    );
  }

  Widget _buildSidebarItem(SidebarItem item, bool isSelected, VoidCallback onTap) {
    return ListTile(
      onTap: onTap,
      selected: isSelected,
      leading: Icon(
        item.iconData,
        color: isSelected
            ? const Color(0xFFE9C46A)
            : const Color(0xFFA0AEC0),
        size: 20,
      ),
      title: Text(
        item.label,
        style: TextStyle(
          color: isSelected ? Colors.white : const Color(0xFFA0AEC0),
          fontSize: 13,
          fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
        ),
      ),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
      ),
      selectedTileColor: const Color(0xFFE9C46A).withOpacity(0.15),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      dense: true,
    );
  }

  Widget _buildSidebarFooter(AppState appState) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: const BoxDecoration(
        border: Border(
          top: BorderSide(
            color: Color(0xFF2D3748),
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              color: const Color(0xFFE9C46A).withOpacity(0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(
              Icons.person,
              color: Color(0xFFE9C46A),
              size: 18,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  appState.username ?? 'User',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  appState.isAuthenticated ? 'Online' : 'Offline',
                  style: const TextStyle(
                    color: Color(0xFF718096),
                    fontSize: 10,
                  ),
                ),
              ],
            ),
          ),
          IconButton(
            icon: const Icon(
              Icons.logout,
              color: Color(0xFF718096),
              size: 18,
            ),
            onPressed: () => _showSignOutDialog(appState),
            tooltip: 'Sign Out',
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ],
      ),
    );
  }

  void _showSignOutDialog(AppState appState) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1A1A2E),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: Color(0xFF2D3748)),
        ),
        title: const Text(
          'Sign Out',
          style: TextStyle(color: Colors.white),
        ),
        content: const Text(
          'Are you sure you want to sign out? You will need to re-enter your credentials.',
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
              Navigator.pop(context);
              ref.read(appNotifierProvider.notifier).signOut();
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red.shade600,
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            child: const Text('Sign Out'),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailView(AppState appState) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Color(0xFF16213E),
            Color(0xFF0F3460),
          ],
        ),
      ),
      child: SafeArea(
        child: _getDetailViewForItem(appState.selectedSidebarItem),
      ),
    );
  }

  Widget _getDetailViewForItem(SidebarItem item) {
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
        return const TreeBrowserView(); // Show relay nodes from tree
      case SidebarItem.settings:
        return const SettingsView();
    }
  }
}

extension SidebarItemData on SidebarItem {
  IconData get iconData {
    switch (this) {
      case SidebarItem.dashboard:
        return Icons.dashboard_outlined;
      case SidebarItem.tunnel:
        return Icons.security_outlined;
      case SidebarItem.peers:
        return Icons.people_outlined;
      case SidebarItem.network:
        return Icons.network_check_outlined;
      case SidebarItem.endpoints:
        return Icons.account_tree_outlined;
      case SidebarItem.servers:
        return Icons.dns_outlined;
      case SidebarItem.certificates:
        return Icons.cert_outlined;
      case SidebarItem.relays:
        return Icons.wifi_tethering_outlined;
      case SidebarItem.settings:
        return Icons.settings_outlined;
    }
  }
}
