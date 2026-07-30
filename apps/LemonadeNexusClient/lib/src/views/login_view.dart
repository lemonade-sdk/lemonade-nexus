/// @title Login View
/// @description Passwordless Cluster picker. A Cluster is an account; a
/// membership is a device Ed25519 key held in the keyring, so there is nothing
/// to type to get back in. Three actions: Connect (tap a Cluster card),
/// Register (a new Cluster) and Join (an invitation code from another device).
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/providers.dart';
import '../state/app_state.dart';
import '../state/cluster_keyring.dart';
import '../services/dns_discovery.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class LoginView extends ConsumerStatefulWidget {
  const LoginView({super.key});

  @override
  ConsumerState<LoginView> createState() => _LoginViewState();
}

class _LoginViewState extends ConsumerState<LoginView> {
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!mounted) return;
      await _notifier.loadClusters();
      if (!mounted) return;
      final state = ref.read(appNotifierProvider);
      if (!state.settings.autoDiscoveryEnabled ||
          state.discoveredServers.isNotEmpty ||
          state.isDiscovering) {
        return;
      }
      // A known server is shown by _serverSection, so only sweep in background.
      final known = _notifier.rememberedServer();
      _notifier.discoverNearestServer(connectToBest: known == null);
    });
  }

  AppNotifier get _notifier => ref.read(appNotifierProvider.notifier);

  Future<void> _run(Future<bool> Function() action, String failMsg) async {
    setState(() => _error = null);
    final ok = await action();
    if (!ok && mounted) {
      setState(() => _error = ref.read(appNotifierProvider).errorMessage ?? failMsg);
    }
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final scheme = Theme.of(context).colorScheme;

    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 380),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const LemonLogo(size: 96),
                const SizedBox(height: 8),
                const Text('Lemonade Nexus',
                    style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold)),
                const SizedBox(height: 4),
                Text('Secure Mesh VPN',
                    style: TextStyle(fontSize: 14, color: scheme.onSurfaceVariant)),
                const SizedBox(height: 28),
                AppCard(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      _serverSection(appState),
                      const SizedBox(height: 16),
                      for (final cluster in appState.clusters) ...[
                        _clusterCard(cluster, appState),
                        const SizedBox(height: 12),
                      ],
                      _registerCard(appState),
                      if (_error != null) ...[
                        const SizedBox(height: 16),
                        _errorBox(_error!),
                      ],
                      const SizedBox(height: 10),
                      Center(
                        child: TextButton(
                          onPressed: appState.isLoading ? null : _showJoinDialog,
                          style: TextButton.styleFrom(
                            foregroundColor: AppTheme.lemonYellow,
                            visualDensity: VisualDensity.compact,
                          ),
                          child: const Text('Have an invitation code?',
                              style: TextStyle(
                                  fontSize: 12, fontStyle: FontStyle.italic)),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 24),
                Text('v1.0.0',
                    style: TextStyle(
                        fontSize: 11,
                        color: scheme.onSurfaceVariant.withValues(alpha: 0.6))),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ---- cluster cards --------------------------------------------------------

  Widget _clusterCard(ClusterEntry cluster, AppState appState) {
    final scheme = Theme.of(context).colorScheme;
    final busy = appState.isLoading;
    return Material(
      color: scheme.surfaceContainerHighest,
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: busy ? null : () => _connect(cluster),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 16),
          child: Row(
            children: [
              const Icon(Icons.person_outline, size: 44, color: AppTheme.lemonYellow),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(cluster.name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            fontSize: 19, fontWeight: FontWeight.w500)),
                    const SizedBox(height: 2),
                    Text(_subtitleFor(cluster),
                        style: TextStyle(
                            fontSize: 12,
                            fontStyle: FontStyle.italic,
                            color: scheme.onSurfaceVariant)),
                  ],
                ),
              ),
              PopupMenuButton<String>(
                tooltip: 'Cluster options',
                icon: Icon(Icons.settings, size: 20, color: scheme.onSurfaceVariant),
                onSelected: (value) {
                  if (value == 'rename') _showRenameDialog(cluster);
                  if (value == 'forget') _confirmForget(cluster);
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'rename', child: Text('Rename')),
                  PopupMenuItem(
                      value: 'forget', child: Text('Forget on this device')),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// "Last used …", or the state of a membership with no account key yet.
  String _subtitleFor(ClusterEntry cluster) {
    if (!cluster.hasGroupKey && !cluster.isOwner) return 'Waiting for account key';
    if (cluster.lastUsed == null) return 'Never connected';
    return 'Last used ${_relativeTime(cluster.lastUsed!)}';
  }

  Widget _registerCard(AppState appState) {
    final scheme = Theme.of(context).colorScheme;
    return Material(
      color: scheme.surfaceContainerHighest.withValues(alpha: 0.5),
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: appState.isLoading ? null : _showRegisterDialog,
        child: Container(
          height: 96,
          alignment: Alignment.center,
          child: appState.isLoading
              ? const SizedBox(
                  width: 22,
                  height: 22,
                  child: CircularProgressIndicator(strokeWidth: 2))
              : Icon(Icons.add_circle_outline,
                  size: 40, color: scheme.onSurfaceVariant),
        ),
      ),
    );
  }

  // ---- actions --------------------------------------------------------------

  Future<void> _connect(ClusterEntry cluster) =>
      _run(() => _notifier.connectToCluster(cluster), 'Could not connect');

  Future<void> _showRegisterDialog() async {
    final name = await _promptText(
      title: 'New Cluster',
      message: 'A Cluster is your account. This device becomes its owner — no '
          'password needed.',
      label: 'Cluster name',
      initial: '',
      action: 'Create',
    );
    if (name == null || name.isEmpty) return;
    await _run(
        () => _notifier.registerCluster(name), 'Could not create the Cluster');
  }

  Future<void> _showJoinDialog() async {
    final result = await showDialog<_JoinRequest>(
      context: context,
      builder: (_) => const _JoinDialog(),
    );
    if (result == null) return;
    await _run(() => _notifier.joinCluster(result.code, name: result.name),
        'Could not join the Cluster');
  }

  Future<void> _showRenameDialog(ClusterEntry cluster) async {
    final name = await _promptText(
      title: 'Rename Cluster',
      message: 'This label is local to this device.',
      label: 'Cluster name',
      initial: cluster.name,
      action: 'Rename',
    );
    if (name == null || name.isEmpty) return;
    await _notifier.renameCluster(cluster.localId, name);
  }

  Future<void> _confirmForget(ClusterEntry cluster) async {
    final scheme = Theme.of(context).colorScheme;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: scheme.outline)),
        title: const Text('Forget Cluster'),
        content: Text(
          'Remove "${cluster.name}" from this device. Its key is deleted here, '
          'so you would need a new invitation code to come back'
          '${cluster.isOwner ? ' — and this device owns the Cluster' : ''}.',
          style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.errorColor),
            child: const Text('Forget'),
          ),
        ],
      ),
    );
    if (confirmed == true) await _notifier.forgetCluster(cluster.localId);
  }

  Future<String?> _promptText({
    required String title,
    required String message,
    required String label,
    required String initial,
    required String action,
  }) {
    final scheme = Theme.of(context).colorScheme;
    final controller = TextEditingController(text: initial);
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: scheme.outline)),
        title: Text(title),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(message,
                style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant)),
            const SizedBox(height: 16),
            TextField(
              controller: controller,
              autofocus: true,
              decoration: InputDecoration(labelText: label),
              onSubmitted: (v) => Navigator.pop(ctx, v.trim()),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, controller.text.trim()),
            child: Text(action),
          ),
        ],
      ),
    );
  }

  // ---- server discovery -----------------------------------------------------

  Widget _serverSection(AppState appState) {
    final scheme = Theme.of(context).colorScheme;

    // Show the last-used server so Clusters are usable before the sweep ends.
    if (appState.discoveredServers.isEmpty) {
      final known = _notifier.rememberedServer();
      if (known != null) {
        return Row(
          children: [
            const StatusDot(isHealthy: true, size: 8),
            const SizedBox(width: 8),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('${known.host}:${known.port}',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontSize: 12)),
                  Text(
                    appState.isDiscovering
                        ? 'Last used — looking for closer servers…'
                        : 'Last used server',
                    style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant),
                  ),
                ],
              ),
            ),
            if (appState.isDiscovering)
              const SizedBox(
                  width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
            else
              IconButton(
                tooltip: 'Find servers',
                visualDensity: VisualDensity.compact,
                icon: Icon(Icons.refresh, size: 16, color: scheme.onSurfaceVariant),
                onPressed: () => _notifier.discoverNearestServer(connectToBest: false),
              ),
          ],
        );
      }
    }

    if (appState.isDiscovering) {
      return Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const SizedBox(
              width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2)),
          const SizedBox(width: 10),
          Flexible(
            child: Text('Discovering servers on lemonade-nexus.io…',
                style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
          ),
        ],
      );
    }

    final servers = appState.discoveredServers;
    if (servers.isNotEmpty) {
      final best = servers.first;
      final currentKey =
          '${appState.settings.serverHost}:${appState.settings.serverPort}';
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const StatusDot(isHealthy: true, size: 8),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Connected to ${best.displayName}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 12)),
                    Text(
                      '${servers.length} server${servers.length == 1 ? '' : 's'} found — ${best.latencyMs.round()}ms latency',
                      style:
                          TextStyle(fontSize: 11, color: scheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
              IconButton(
                tooltip: 'Re-discover',
                visualDensity: VisualDensity.compact,
                icon: Icon(Icons.refresh, size: 16, color: scheme.onSurfaceVariant),
                onPressed: _notifier.discoverNearestServer,
              ),
            ],
          ),
          if (servers.length > 1)
            ...servers.map((s) => _serverPickerRow(s, currentKey)),
        ],
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        if (appState.discoveryMessage != null)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Text(appState.discoveryMessage!,
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
          ),
        OutlinedButton.icon(
          onPressed: _notifier.discoverNearestServer,
          icon: const Icon(Icons.wifi_tethering, size: 16),
          label: const Text('Discover servers'),
        ),
      ],
    );
  }

  Widget _serverPickerRow(DiscoveredServer s, String currentKey) {
    final scheme = Theme.of(context).colorScheme;
    final host = s.connectHost ?? s.hostname ?? s.ip;
    final selected = '$host:${s.port}' == currentKey;
    return InkWell(
      onTap: () =>
          _notifier.connectToServer(host, s.port, useTls: s.scheme == 'https'),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          children: [
            Icon(
              selected ? Icons.radio_button_checked : Icons.radio_button_unchecked,
              size: 13,
              color: selected ? AppTheme.lemonYellowDark : scheme.onSurfaceVariant,
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(s.displayName,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 12)),
            ),
            Text('${s.latencyMs.round()}ms',
                style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant)),
          ],
        ),
      ),
    );
  }

  Widget _errorBox(String message) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppTheme.errorColor.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          const Icon(Icons.error_outline, size: 16, color: AppTheme.errorColor),
          const SizedBox(width: 8),
          Expanded(
            child: Text(message,
                style: const TextStyle(fontSize: 12, color: AppTheme.errorColor)),
          ),
        ],
      ),
    );
  }
}

String _relativeTime(DateTime when) {
  final d = DateTime.now().difference(when);
  if (d.inMinutes < 1) return 'just now';
  if (d.inMinutes < 60) {
    return '${d.inMinutes} minute${d.inMinutes == 1 ? '' : 's'} ago';
  }
  if (d.inHours < 24) {
    return '${d.inHours == 1 ? 'an hour' : '${d.inHours} hours'} ago';
  }
  if (d.inDays < 30) return '${d.inDays} day${d.inDays == 1 ? '' : 's'} ago';
  final months = d.inDays ~/ 30;
  return '$months month${months == 1 ? '' : 's'} ago';
}

class _JoinRequest {
  final String code;
  final String name;
  const _JoinRequest(this.code, this.name);
}

/// Prompts for an invitation code minted by a device already in the Cluster.
class _JoinDialog extends StatefulWidget {
  const _JoinDialog();

  @override
  State<_JoinDialog> createState() => _JoinDialogState();
}

class _JoinDialogState extends State<_JoinDialog> {
  final _codeController = TextEditingController();
  final _nameController = TextEditingController();

  @override
  void dispose() {
    _codeController.dispose();
    _nameController.dispose();
    super.dispose();
  }

  void _submit() {
    final code = _codeController.text.trim();
    if (code.isEmpty) return;
    final name = _nameController.text.trim();
    Navigator.pop(context, _JoinRequest(code, name.isEmpty ? 'Cluster' : name));
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AlertDialog(
      backgroundColor: scheme.surface,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: scheme.outline)),
      title: const Text('Join a Cluster'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Add Device on a device already in the Cluster gives you a code. '
            'This device generates its own key — the code just authorizes it.',
            style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _codeController,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: 'Invitation code',
              hintText: 'lnk_…',
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _nameController,
            decoration: const InputDecoration(
              labelText: 'Name for this Cluster (optional)',
            ),
            onSubmitted: (_) => _submit(),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        ElevatedButton(onPressed: _submit, child: const Text('Join')),
      ],
    );
  }
}
