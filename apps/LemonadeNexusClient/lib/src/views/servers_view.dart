/// @title Servers View
/// @description Server list and selection interface with admin console.
///
/// Left panel: list of Lemonade servers with health status
/// Right panel: the selected server's details (endpoint, port, last seen,
/// health, identity key, and live stats for the server this app is connected
/// to), above the Admin Console (Dashboard, Models, Backends, System, Logs)
library;

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
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
  ServerInfo? _selectedServer;
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    // Defer the first fetch until after the view paints — the native call is
    // synchronous and would otherwise block (freeze) the navigation transition.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _loadServers();
    });
  }

  Future<void> _loadServers() async {
    setState(() => _isLoading = true);
    await ref.read(appNotifierProvider.notifier).refreshServers();

    // Sync SDK servers into admin server list
    final appState = ref.read(appNotifierProvider);
    final sdkServers = appState.servers;
    final adminNotifer = ref.read(adminServersProvider.notifier);

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
                      const Flexible(
                        child: SectionHeader(
                            title: 'Mesh Servers',
                            icon: Icons.dns,
                            flexibleTitle: true),
                      ),
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
        // Right panel: details and Admin Console for the selected server
        Expanded(
          flex: 2,
          child: _selectedAdminServer != null
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    if (_selectedServer != null)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(24, 24, 24, 0),
                        child: _buildServerDetails(_selectedServer!, servers),
                      ),
                    Expanded(
                        child: AdminConsoleWidget(serverName: _selectedAdminServer!.name)),
                  ],
                )
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
          ref.read(appNotifierProvider.notifier).refreshStats();
          setState(() {
            _selectedServer = server;
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

  /// The queried server lists itself first, with no last-seen time; live
  /// stats come from that server only.
  bool _isConnectedServer(ServerInfo server, List<ServerInfo> servers) =>
      servers.isNotEmpty && servers.first.id == server.id && server.lastSeen == 0;

  Widget _buildServerDetails(ServerInfo server, List<ServerInfo> servers) {
    final scheme = Theme.of(context).colorScheme;
    final connected = _isConnectedServer(server, servers);
    final stats = ref.watch(appNotifierProvider).stats;
    return AppCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              StatusDot(isHealthy: server.available, size: 10),
              const SizedBox(width: 8),
              Expanded(
                child: Text('${server.host}:${server.port}',
                    style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
              ),
              if (connected) ...[
                const LemonBadge(text: 'CONNECTED', color: AppTheme.lemonYellowDark),
                const SizedBox(width: 6),
              ],
              LemonBadge(
                text: server.available ? 'HEALTHY' : 'UNHEALTHY',
                color: server.available ? AppTheme.lemonGreen : AppTheme.errorColor,
              ),
            ],
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 24,
            runSpacing: 8,
            children: [
              _detail('Endpoint', server.endpoint.isEmpty ? server.host : server.endpoint),
              _detail('HTTP port', '${server.port}'),
              _detail('Last seen', connected ? 'now' : _lastSeen(server.lastSeen)),
              if (server.region.isNotEmpty) _detail('Region', server.region),
              if (server.latencyMs != null) _detail('Latency', '${server.latencyMs}ms'),
              if (connected && stats != null) ...[
                _detail('Mesh peers', '${stats.peerCount}'),
                _detail('Private API', stats.privateApiEnabled ? 'on' : 'off'),
                _detail('Service', stats.service),
              ],
            ],
          ),
          if (!connected) ...[
            const SizedBox(height: 8),
            Text('Live stats are shown for the server this app is connected to.',
                style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant)),
          ],
          if (server.pubkey.isNotEmpty) ...[
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: SelectableText(server.pubkey,
                      style: TextStyle(
                          fontSize: 11,
                          fontFamily: 'monospace',
                          color: scheme.onSurfaceVariant)),
                ),
                IconButton(
                  tooltip: 'Copy public key',
                  icon: const Icon(Icons.copy, size: 16),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: server.pubkey));
                    ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Public key copied')));
                  },
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _detail(String label, String value) {
    final scheme = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(label, style: TextStyle(fontSize: 10, color: scheme.onSurfaceVariant)),
        const SizedBox(height: 2),
        Text(value, style: const TextStyle(fontSize: 13, fontFamily: 'monospace')),
      ],
    );
  }

  String _lastSeen(int epochSec) {
    if (epochSec <= 0) return 'unknown';
    final ago = DateTime.now()
        .difference(DateTime.fromMillisecondsSinceEpoch(epochSec * 1000));
    if (ago.inSeconds < 60) return '${ago.inSeconds}s ago';
    if (ago.inMinutes < 60) return '${ago.inMinutes}m ago';
    if (ago.inHours < 24) return '${ago.inHours}h ago';
    return '${ago.inDays}d ago';
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
