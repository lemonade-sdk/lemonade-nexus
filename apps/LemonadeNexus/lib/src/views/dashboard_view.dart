/// @title Dashboard View
/// @description Connection status and mesh stats, styled like the macOS app.
library;

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/providers.dart';
import '../state/app_state.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class DashboardView extends ConsumerStatefulWidget {
  const DashboardView({super.key});

  @override
  ConsumerState<DashboardView> createState() => _DashboardViewState();
}

class _DashboardViewState extends ConsumerState<DashboardView> {
  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    _refreshTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      ref.read(appNotifierProvider.notifier).refreshMeshStatus();
    });
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const SectionHeader(title: 'Dashboard', icon: Icons.dashboard_outlined),
              const Spacer(),
              IconButton(
                tooltip: 'Refresh',
                icon: const Icon(Icons.refresh, size: 20),
                onPressed: () =>
                    ref.read(appNotifierProvider.notifier).refreshAllData(),
              ),
            ],
          ),
          const SizedBox(height: 20),
          _statsRow(appState),
          const SizedBox(height: 16),
          _meshRow(appState),
          const SizedBox(height: 16),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(child: _serverHealthCard(appState)),
              const SizedBox(width: 16),
              Expanded(child: _connectionCard(appState)),
            ],
          ),
          const SizedBox(height: 16),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(child: _networkCard(appState)),
              const SizedBox(width: 16),
              Expanded(child: _trustCard(appState)),
            ],
          ),
          const SizedBox(height: 24),
          const SectionHeader(title: 'Recent Activity', icon: Icons.list_alt),
          const SizedBox(height: 12),
          _activityCard(appState),
        ],
      ),
    );
  }

  Widget _statsRow(AppState appState) {
    return Row(
      children: [
        Expanded(
          child: StatCard(
            icon: Icons.people_outline,
            title: 'Peer Count',
            value: '${appState.stats?.peerCount ?? 0}',
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: StatCard(
            icon: Icons.dns_outlined,
            title: 'Servers',
            value: '${appState.servers.length}',
            color: AppTheme.lemonGreen,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: StatCard(
            icon: Icons.wifi_tethering,
            title: 'Relays',
            value: '${appState.relays.length}',
            color: AppTheme.nodeOrange,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: StatCard(
            icon: Icons.access_time,
            title: 'Uptime',
            value: _uptime(appState.connectedSince),
            color: AppTheme.lemonGreen,
          ),
        ),
      ],
    );
  }

  Widget _meshRow(AppState appState) {
    final mesh = appState.meshStatus;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(child: _p2pMeshCard(appState)),
        const SizedBox(width: 16),
        Expanded(
          child: _card('Mesh Peers', Icons.hub_outlined, [
            _kv('Online', _mono('${mesh?.onlineCount ?? 0} / ${mesh?.peerCount ?? 0}')),
            _kv('Direct', _mono('${appState.meshPeers.where((p) => (p.endpoint ?? '').isNotEmpty).length}')),
            _kv('Relayed', _mono('${appState.meshPeers.where((p) => (p.endpoint ?? '').isEmpty && (p.relayEndpoint ?? '').isNotEmpty).length}')),
          ]),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _card('Bandwidth', Icons.swap_horiz, [
            _kv('Received', _mono(_bytes(mesh?.totalRxBytes ?? 0))),
            _kv('Sent', _mono(_bytes(mesh?.totalTxBytes ?? 0))),
            _kv('Total', _mono(_bytes((mesh?.totalRxBytes ?? 0) + (mesh?.totalTxBytes ?? 0)))),
          ]),
        ),
      ],
    );
  }

  /// P2P mesh networking card with an enable/disable control. Replaces the old
  /// VPN "Tunnel" card — endpoint connectivity is via the userspace mesh
  /// routing layer, not a VPN tunnel.
  Widget _p2pMeshCard(AppState appState) {
    final mesh = appState.meshStatus;
    final enabled = appState.isMeshEnabled;
    final loading = appState.isLoading;
    return _card('P2P Mesh', Icons.hub, [
      _kv('Status', LemonBadge(
        text: enabled ? 'ENABLED' : 'DISABLED',
        color: enabled ? AppTheme.lemonGreen : Colors.grey,
      )),
      _kv('Online', _mono('${mesh?.onlineCount ?? 0} / ${mesh?.peerCount ?? 0}')),
      if ((mesh?.tunnelIp ?? '').isNotEmpty) _kv('Mesh IP', _mono(mesh!.tunnelIp!)),
      const SizedBox(height: 12),
      SizedBox(
        width: double.infinity,
        child: enabled
            ? OutlinedButton.icon(
                onPressed: loading
                    ? null
                    : () => ref.read(appNotifierProvider.notifier).toggleMesh(),
                icon: const Icon(Icons.stop_circle_outlined, size: 16),
                label: const Text('Disable Mesh'),
              )
            : ElevatedButton.icon(
                onPressed: loading
                    ? null
                    : () => ref.read(appNotifierProvider.notifier).toggleMesh(),
                icon: loading
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.play_circle_outline, size: 16),
                label: const Text('Enable Mesh'),
              ),
      ),
    ], trailing: StatusDot(isHealthy: enabled, size: 8));
  }

  Widget _serverHealthCard(AppState appState) {
    final h = appState.healthStatus;
    return _card('Server Health', Icons.favorite_outline, [
      if (h != null) ...[
        _kv('Status', LemonBadge(
          text: h.status.toUpperCase(),
          color: appState.isServerHealthy ? AppTheme.lemonGreen : AppTheme.errorColor,
        )),
        _kv('Service', _mono(h.service.isEmpty ? '—' : h.service)),
        if ((h.dnsBaseDomain ?? '').isNotEmpty)
          _kv('DNS Domain', _mono(h.dnsBaseDomain!, size: 11)),
      ] else
        _kv('', const Text('Unable to reach server',
            style: TextStyle(fontSize: 13, color: AppTheme.nodeOrange))),
      _kv('URL', _mono('${appState.serverHost}:${appState.serverPort}', size: 11)),
    ], trailing: StatusDot(isHealthy: appState.isServerHealthy, size: 8));
  }

  Widget _connectionCard(AppState appState) {
    return _card('Connection', Icons.cable_outlined, [
      if (appState.tunnelIP != null) _kv('Tunnel IP', _mono(appState.tunnelIP!)),
      if (appState.userId != null) _kv('User ID', _mono(appState.userId!, size: 11)),
      if (appState.publicKeyBase64 != null)
        _kv('Public Key', _mono('${appState.publicKeyBase64!.substring(0, appState.publicKeyBase64!.length.clamp(0, 20))}…', size: 11)),
      if (appState.connectedSince != null)
        _kv('Since', Text(_rel(appState.connectedSince!),
            style: const TextStyle(fontSize: 12))),
    ], trailing: LemonBadge(
      text: appState.isAuthenticated ? 'ACTIVE' : 'INACTIVE',
      color: appState.isAuthenticated ? AppTheme.lemonGreen : Colors.grey,
    ));
  }

  Widget _networkCard(AppState appState) {
    final s = appState.stats;
    return _card('Network', Icons.lan_outlined, [
      if (s != null) ...[
        _kv('Service', _mono(s.service)),
        _kv('Peers', _mono('${s.peerCount}')),
        _kv('Private API', LemonBadge(
          text: s.privateApiEnabled ? 'ENABLED' : 'DISABLED',
          color: s.privateApiEnabled ? AppTheme.lemonGreen : Colors.grey,
        )),
      ] else
        _kv('', const Text('No stats available', style: TextStyle(fontSize: 13))),
      _kv('Servers', Text(
        '${appState.servers.where((s) => s.available).length}/${appState.servers.length} healthy',
        style: const TextStyle(fontSize: 12))),
    ]);
  }

  Widget _trustCard(AppState appState) {
    final t = appState.trustStatus;
    return _card('Trust Status', Icons.verified_user_outlined, [
      if (t != null) ...[
        _kv('Our Tier', LemonBadge(
          text: 'TIER ${t.trustTier}',
          color: t.trustTier == '1' ? AppTheme.lemonGreen : AppTheme.nodeOrange,
        )),
        _kv('Trusted Peers', _mono('${t.peerCount}')),
      ] else
        // /api/trust/status is a private-API route reached via the mesh layer.
        _kv('', Text(
          appState.isMeshEnabled
              ? 'Trust data unavailable'
              : 'Enable mesh to view trust status',
          style: const TextStyle(fontSize: 13, color: AppTheme.nodeOrange),
        )),
    ], trailing: StatusDot(isHealthy: appState.trustStatus != null, size: 8));
  }

  Widget _activityCard(AppState appState) {
    final scheme = Theme.of(context).colorScheme;
    if (appState.activityLog.isEmpty) {
      return AppCard(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Center(
            child: Text('No recent activity',
                style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant)),
          ),
        ),
      );
    }
    final entries = appState.activityLog.take(10).toList();
    return AppCard(
      padding: EdgeInsets.zero,
      child: Column(
        children: [
          for (var i = 0; i < entries.length; i++)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              decoration: BoxDecoration(
                border: i == entries.length - 1
                    ? null
                    : Border(bottom: BorderSide(color: scheme.outline, width: 0.5)),
              ),
              child: Row(
                children: [
                  Container(
                    width: 8,
                    height: 8,
                    decoration: BoxDecoration(
                      color: _activityColor(entries[i].level),
                      shape: BoxShape.circle,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(entries[i].message,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 12)),
                  ),
                  Text(_rel(entries[i].timestamp),
                      style: TextStyle(fontSize: 10, color: scheme.onSurfaceVariant)),
                ],
              ),
            ),
        ],
      ),
    );
  }

  // ---- helpers --------------------------------------------------------------

  Widget _card(String title, IconData icon, List<Widget> rows, {Widget? trailing}) {
    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: AppTheme.lemonYellowDark),
              const SizedBox(width: 8),
              Text(title, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
              const Spacer(),
              if (trailing != null) trailing,
            ],
          ),
          Divider(height: 16, color: scheme.outline),
          ...rows,
        ],
      ),
    );
  }

  Widget _kv(String label, Widget value) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 84,
            child: Text(label,
                style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
          ),
          Expanded(child: value),
        ],
      ),
    );
  }

  Widget _mono(String text, {double size = 13}) {
    final scheme = Theme.of(context).colorScheme;
    return Text(text,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(
            fontSize: size, fontFamily: 'monospace', color: scheme.onSurface));
  }

  Color _activityColor(ActivityLevel level) {
    switch (level) {
      case ActivityLevel.info:
        return AppTheme.infoColor;
      case ActivityLevel.success:
        return AppTheme.lemonGreen;
      case ActivityLevel.warning:
        return AppTheme.nodeOrange;
      case ActivityLevel.error:
        return AppTheme.errorColor;
    }
  }

  String _uptime(DateTime? since) {
    if (since == null) return '--';
    final d = DateTime.now().difference(since);
    final h = d.inHours, m = d.inMinutes % 60;
    return h > 0 ? '${h}h ${m}m' : '${m}m';
  }

  String _rel(DateTime time) {
    final d = DateTime.now().difference(time);
    if (d.inSeconds < 60) return '${d.inSeconds}s ago';
    if (d.inMinutes < 60) return '${d.inMinutes}m ago';
    if (d.inHours < 24) return '${d.inHours}h ago';
    return '${d.inDays}d ago';
  }

  String _bytes(int bytes) {
    final kb = bytes / 1024, mb = kb / 1024, gb = mb / 1024;
    if (gb >= 1) return '${gb.toStringAsFixed(1)} GB';
    if (mb >= 1) return '${mb.toStringAsFixed(1)} MB';
    if (kb >= 1) return '${kb.toStringAsFixed(0)} KB';
    return '$bytes B';
  }
}
