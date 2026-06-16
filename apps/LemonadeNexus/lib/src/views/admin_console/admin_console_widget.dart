/// Admin console widget — 5-tab management panel for a selected Lemonade server.
///
/// When a server is selected in the left sidebar, this widget fills the right panel.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'admin_dashboard_tab.dart';
import 'admin_models_tab.dart';
import 'admin_backends_tab.dart';
import 'admin_system_info_tab.dart';
import 'admin_logs_tab.dart';
import 'server_admin_provider.dart';

/// The admin console for a specific server. Shows tabs:
/// Dashboard · Models · Backends · System · Logs
class AdminConsoleWidget extends ConsumerWidget {
  final String serverName;

  const AdminConsoleWidget({super.key, required this.serverName});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final client = ref.watch(serverAdminProvider);

    if (client == null) {
      return Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.dns_outlined, size: 48, color: Colors.white.withOpacity(0.3)),
                const SizedBox(height: 16),
                Text(
                  'Select a server to access admin features.',
                  style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 14),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      );
    }

    return DefaultTabController(
      length: 5,
      child: Scaffold(
        body: Column(
          children: [
            // App bar with server name and tabs
            Container(
              decoration: BoxDecoration(
                color: const Color(0xFF1A1A2E).withOpacity(0.95),
                border: Border(bottom: BorderSide(color: const Color(0xFF2D3748))),
              ),
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    child: Row(
                      children: [
                        const Icon(Icons.admin_panel_settings, color: Color(0xFFE9C46A), size: 20),
                        const SizedBox(width: 8),
                        Text(
                          'Admin · $serverName',
                          style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                  ),
                  TabBar(
                    isScrollable: true,
                    labelColor: const Color(0xFFE9C46A),
                    unselectedLabelColor: Colors.white.withOpacity(0.6),
                    indicatorColor: const Color(0xFFE9C46A),
                    tabs: const [
                      Tab(text: 'Dashboard', icon: Icon(Icons.dashboard, size: 18)),
                      Tab(text: 'Models', icon: Icon(Icons.model_training, size: 18)),
                      Tab(text: 'Backends', icon: Icon(Icons.developer_board, size: 18)),
                      Tab(text: 'System', icon: Icon(Icons.computer, size: 18)),
                      Tab(text: 'Logs', icon: Icon(Icons.receipt_long, size: 18)),
                    ],
                  ),
                ],
              ),
            ),
            // Tab content
            Expanded(
              child: TabBarView(
                children: const [
                  AdminDashboardTab(),
                  AdminModelsTab(),
                  AdminBackendsTab(),
                  AdminSystemInfoTab(),
                  AdminLogsTab(),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
