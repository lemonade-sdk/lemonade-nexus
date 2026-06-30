/// @title Servers View
/// @description Server list and selection interface with admin console.
///
/// Left panel: list of Lemonade servers with health status
/// Right panel: Admin Console for the selected server (Dashboard, Models, Backends, System, Logs)

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';
import '../views/admin_console/server_admin_provider.dart';
import '../views/admin_console/admin_console_widget.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class ServersView extends ConsumerStatefulWidget {
  const ServersView({super.key});

  @override
  ConsumerState<ServersView> createState() => _ServersViewState();
}

class _ServersViewState extends ConsumerState<ServersView> {
  AdminServer? _selectedAdminServer;
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    _loadServers();
  }

  Future<void> _loadServers() async {
    setState(() => _isLoading = true);
    await ref.read(appNotifierProvider.notifier).refreshServers();

    // Sync SDK servers into admin server list
    final appState = ref.read(appNotifierProvider);
    final sdkServers = appState.servers;
    final adminNotifer = ref.read(adminServersProvider.notifier);

    // Convert SDK ServerInfo to AdminServer entries
    final adminServers = sdkServers.map((s) {
      return AdminServer(
        id: s.id,
        name: '${s.host}:${s.port}',
        baseUrl: 'http://${s.host}:${s.port}',
        available: s.available,
      );
    }).toList();

    adminNotifer.syncFromSdkServers(sdkServers.map((s) => {
      'id': s.id,
      'host': s.host,
      'port': s.port,
      'name': '${s.host}:${s.port}',
      'region': s.region,
      'available': s.available,
      'latencyMs': s.latencyMs,
    }).toList());

    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final appState = ref.watch(appNotifierProvider);
    final servers = appState.servers;
    final adminServers = ref.watch(adminServersProvider);
    final healthyCount = servers.where((s) => s.available).length;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Server list panel
        Expanded(
          flex: 1,
          child: Container(
            decoration: BoxDecoration(
              border: Border(right: BorderSide(color: scheme.outline, width: 1)),
            ),
            child: Column(
              children: [
                // Header
                Padding(
                  padding: const EdgeInsets.all(24),
                  child: Row(
                    children: [
                      const SectionHeader(title: 'Mesh Servers', icon: Icons.dns),
                      const Spacer(),
                      _buildHealthBadge(healthyCount, servers.length),
                      const SizedBox(width: 8),
                      IconButton(
                        tooltip: 'Refresh',
                        icon: const Icon(Icons.refresh, size: 18),
                        onPressed: _loadServers,
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(),
                      ),
                    ],
                  ),
                ),
                // List
                Expanded(
                  child: _isLoading
                      ? const Center(child: CircularProgressIndicator())
                      : servers.isEmpty
                          ? _buildEmptyState()
                          : ListView.builder(
                              padding: const EdgeInsets.all(24),
                              itemCount: servers.length,
                              itemBuilder: (context, index) => _buildServerCard(servers[index]),
                            ),
                ),
              ],
            ),
          ),
        ),
        // Right panel: Admin Console for selected server
        Expanded(
          flex: 2,
          child: _selectedAdminServer != null
              ? AdminConsoleWidget(serverName: _selectedAdminServer!.name)
              : _buildNoSelectionState(),
        ),
      ],
    );
  }

  Widget _buildHealthBadge(int healthy, int total) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: scheme.surface,
        borderRadius: BorderRadius.circular(100),
      ),
      child: Row(
        children: [
          StatusDot(isHealthy: healthy > 0, size: 8),
          const SizedBox(width: 6),
          Text('$healthy/$total healthy',
              style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return const EmptyState(
      icon: Icons.dns_outlined,
      title: 'No Servers',
      message: 'No mesh servers are currently visible. Check your connection.',
    );
  }

  Widget _buildServerCard(ServerInfo server) {
    final scheme = Theme.of(context).colorScheme;
    final isSelected = _selectedAdminServer?.id == server.id;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () {
          setState(() {
            _selectedAdminServer = AdminServer(
              id: server.id,
              name: '${server.host}:${server.port}',
              baseUrl: 'http://${server.host}:${server.port}',
              available: server.available,
            );
          });
        },
        child: AppCard(
          padding: const EdgeInsets.all(12),
          child: DecoratedBox(
            decoration: BoxDecoration(
              color: isSelected
                  ? AppTheme.lemonYellowDark.withValues(alpha: 0.15)
                  : Colors.transparent,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Padding(
              padding: const EdgeInsets.all(4),
              child: Row(
                children: [
                  StatusDot(isHealthy: server.available, size: 10),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                '${server.host}:${server.port}',
                                style: const TextStyle(
                                    fontSize: 13, fontWeight: FontWeight.w600),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            LemonBadge(
                              text: server.available ? 'HEALTHY' : 'UNHEALTHY',
                              color: server.available
                                  ? AppTheme.lemonGreen
                                  : AppTheme.errorColor,
                            ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        Row(
                          children: [
                            if (server.latencyMs != null)
                              Text('${server.latencyMs}ms',
                                  style: TextStyle(
                                      color: _getLatencyColor(server.latencyMs!),
                                      fontSize: 11,
                                      fontFamily: 'monospace')),
                            if (server.latencyMs != null) const SizedBox(width: 8),
                            Text(server.region,
                                style: TextStyle(
                                    color: scheme.onSurfaceVariant, fontSize: 11)),
                          ],
                        ),
                      ],
                    ),
                  ),
                  Icon(Icons.chevron_right,
                      color: scheme.onSurfaceVariant, size: 16),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildNoSelectionState() {
    return const EmptyState(
      icon: Icons.admin_panel_settings_outlined,
      title: 'Select a Server',
      message: 'Choose a server from the list to access its Admin Console.',
    );
  }

  Color _getLatencyColor(double ms) {
    if (ms < 50) return AppTheme.lemonGreen;
    if (ms < 150) return AppTheme.nodeOrange;
    return AppTheme.errorColor;
  }
}
