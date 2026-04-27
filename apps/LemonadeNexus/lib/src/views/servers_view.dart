/// @title Servers View
/// @description Server list and selection interface.
///
/// Matches macOS ServersView.swift functionality:
/// - Server list with health status
/// - Server count badge
/// - Server detail view

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';

class ServersView extends ConsumerStatefulWidget {
  const ServersView({super.key});

  @override
  ConsumerState<ServersView> createState() => _ServersViewState();
}

class _ServersViewState extends ConsumerState<ServersView> {
  ServerInfo? _selectedServer;
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    _loadServers();
  }

  Future<void> _loadServers() async {
    setState(() => _isLoading = true);
    await ref.read(appNotifierProvider.notifier).refreshServers();
    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
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
            decoration: const BoxDecoration(
              color: Color(0xFF1A1A2E),
              border: Border(right: BorderSide(color: Color(0xFF2D3748), width: 1)),
            ),
            child: Column(
              children: [
                // Header
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      const Icon(Icons.dns, color: Color(0xFFE9C46A), size: 20),
                      const SizedBox(width: 8),
                      const Text('Mesh Servers', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                      const Spacer(),
                      _buildHealthBadge(healthyCount, servers.length),
                      const SizedBox(width: 8),
                      IconButton(
                        icon: const Icon(Icons.refresh, size: 18),
                        color: const Color(0xFFA0AEC0),
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
                              padding: const EdgeInsets.all(8),
                              itemCount: servers.length,
                              itemBuilder: (context, index) => _buildServerCard(servers[index]),
                            ),
                ),
              ],
            ),
          ),
        ),
        // Detail panel
        if (_selectedServer != null)
          Expanded(
            flex: 1,
            child: _buildDetailPanel(_selectedServer!),
          )
        else
          Expanded(
            flex: 1,
            child: _buildNoSelectionState(),
          ),
      ],
    );
  }

  Widget _buildHealthBadge(int healthy, int total) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: const Color(0xFF2D3748),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          _buildStatusDot(healthy > 0),
          const SizedBox(width: 6),
          Text('$healthy/$total healthy', style: const TextStyle(color: Color(0xFFA0AEC0), fontSize: 11)),
        ],
      ),
    );
  }

  Widget _buildStatusDot(bool isHealthy) {
    return Container(
      width: 8, height: 8,
      decoration: BoxDecoration(color: isHealthy ? Colors.green : Colors.red, shape: BoxShape.circle),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.dns_outlined, size: 48, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('No Servers', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text('No mesh servers are currently visible. Check your connection.', textAlign: TextAlign.center, style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 13)),
          ),
        ],
      ),
    );
  }

  Widget _buildServerCard(ServerInfo server) {
    final isSelected = _selectedServer?.id == server.id;
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2, horizontal: 4),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isSelected ? const Color(0xFFE9C46A).withOpacity(0.15) : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: const Color(0xFF2D3748)),
      ),
      child: InkWell(
        onTap: () => setState(() => _selectedServer = server),
        child: Row(
          children: [
            _buildStatusDot(server.available),
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
                          style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      _buildBadge(text: server.available ? 'HEALTHY' : 'UNHEALTHY', color: server.available ? Colors.green : Colors.red),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      if (server.latencyMs != null)
                        Text('${server.latencyMs}ms', style: TextStyle(color: _getLatencyColor(server.latencyMs!), fontSize: 11, fontFamily: 'monospace')),
                      if (server.latencyMs != null) const SizedBox(width: 8),
                      Text(server.region, style: const TextStyle(color: Color(0xFF718096), fontSize: 11)),
                    ],
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: Color(0xFF718096), size: 16),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailPanel(ServerInfo server) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              Container(
                width: 56, height: 56,
                decoration: BoxDecoration(
                  color: (server.available ? Colors.green : Colors.red).withOpacity(0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(Icons.dns, color: server.available ? Colors.green : Colors.red, size: 28),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('${server.host}:${server.port}', style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    _buildBadge(text: server.available ? 'HEALTHY' : 'UNHEALTHY', color: server.available ? Colors.green : Colors.red),
                  ],
                ),
              ),
            ],
          ),
          const Divider(color: Color(0xFF2D3748), height: 24),
          // Details
          _buildDetailRow('Endpoint', '${server.host}:${server.port}'),
          _buildDetailRow('Port', '${server.port}'),
          _buildDetailRow('Region', server.region),
          _buildDetailRow('Health', server.available ? 'Healthy' : 'Unhealthy'),
          if (server.latencyMs != null) _buildDetailRow('Latency', '${server.latencyMs}ms'),
        ],
      ),
    );
  }

  Widget _buildNoSelectionState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.dns_outlined, size: 64, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('Select a Server', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Text('Choose a server from the list to view details.', style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 14), textAlign: TextAlign.center),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 100, child: Text(label, style: const TextStyle(color: Color(0xFF718096), fontSize: 13))),
          Expanded(child: Text(value, style: const TextStyle(color: Colors.white, fontSize: 13, fontFamily: 'monospace'))),
        ],
      ),
    );
  }

  Widget _buildBadge({required String text, required Color color}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
      decoration: BoxDecoration(color: color.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
      child: Text(text, style: TextStyle(color: color, fontSize: 9, fontWeight: FontWeight.bold)),
    );
  }

  Color _getLatencyColor(double ms) {
    if (ms < 50) return Colors.green;
    if (ms < 150) return Colors.orange;
    return Colors.red;
  }
}
