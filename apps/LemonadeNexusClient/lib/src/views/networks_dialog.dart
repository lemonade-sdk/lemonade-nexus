/// @title Networks dialog
/// @description Join another network with an invitation code, list the
/// groups this account belongs to, and leave a group joined through an
/// invite. Joining never moves this account's own network: the account
/// becomes a member of the invite's group (POST /api/link/accept).
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
import '../state/providers.dart';
import '../../theme/app_theme.dart';

Future<void> showNetworksDialog(BuildContext context) {
  return showDialog<void>(context: context, builder: (_) => const NetworksDialog());
}

class NetworksDialog extends ConsumerStatefulWidget {
  const NetworksDialog({super.key});

  @override
  ConsumerState<NetworksDialog> createState() => _NetworksDialogState();
}

class _NetworksDialogState extends ConsumerState<NetworksDialog> {
  final _codeController = TextEditingController();
  List<Map<String, dynamic>> _memberships = [];
  bool _busy = false;
  String? _error;
  String? _notice;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _refresh());
  }

  @override
  void dispose() {
    _codeController.dispose();
    super.dispose();
  }

  String _reason(Object e) => e is SdkException ? (e.message ?? e.toString()) : e.toString();

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
      _notice = null;
    });
    try {
      await action();
    } catch (e) {
      if (mounted) setState(() => _error = _reason(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _refresh() => _run(() async {
        final list = await ref.read(appNotifierProvider.notifier).listMemberships();
        if (mounted) setState(() => _memberships = list);
      });

  Future<void> _join() async {
    // An 8-digit code or the full token, passed through as typed; the SDK
    // and the server decide. Only the shape is checked here.
    final code = normalizeInvite(_codeController.text);
    final malformed = inviteFormatError(code);
    if (malformed != null) {
      setState(() => _error = malformed);
      return;
    }
    await _run(() async {
      final result = await ref.read(appNotifierProvider.notifier).acceptInvite(code);
      _codeController.clear();
      _notice = result['status'] == 'pending'
          ? 'The server accepted the code. The membership is being committed.'
          : 'You joined ${result['node_id'] ?? 'the network'}.';
      final list = await ref.read(appNotifierProvider.notifier).listMemberships();
      if (mounted) setState(() => _memberships = list);
    });
  }

  Future<void> _leave(String nodeId) => _run(() async {
        await ref.read(appNotifierProvider.notifier).leaveMembership(nodeId);
        final list = await ref.read(appNotifierProvider.notifier).listMemberships();
        if (mounted) setState(() => _memberships = list);
      });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AlertDialog(
      backgroundColor: scheme.surface,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12), side: BorderSide(color: scheme.outline)),
      title: const Row(
        children: [
          Icon(Icons.hub_outlined, color: AppTheme.lemonYellowDark, size: 20),
          SizedBox(width: 8),
          Text('Networks'),
        ],
      ),
      content: SizedBox(
        width: 460,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Join another network with an invitation code. Your own network '
              'stays as it is; this device becomes a member of the invited group.',
              style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _codeController,
                    enabled: !_busy,
                    decoration: const InputDecoration(
                      labelText: 'Invitation code',
                      hintText: inviteInputHint,
                      contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    ),
                    style: const TextStyle(fontSize: 13, fontFamily: 'monospace'),
                    onSubmitted: (_) => _join(),
                  ),
                ),
                const SizedBox(width: 8),
                ElevatedButton(
                  onPressed: _busy ? null : _join,
                  child: const Text('Join'),
                ),
              ],
            ),
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(_error!, style: const TextStyle(fontSize: 12, color: AppTheme.errorColor)),
            ],
            if (_notice != null) ...[
              const SizedBox(height: 8),
              Text(_notice!, style: const TextStyle(fontSize: 12, color: AppTheme.lemonGreen)),
            ],
            const SizedBox(height: 16),
            Text('Your networks',
                style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: scheme.onSurface)),
            const SizedBox(height: 8),
            if (_busy && _memberships.isEmpty)
              const Center(child: Padding(
                padding: EdgeInsets.all(12),
                child: CircularProgressIndicator(),
              ))
            else if (_memberships.isEmpty)
              Text('No networks found.',
                  style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant))
            else
              ..._memberships.map((m) => _row(context, m)),
          ],
        ),
      ),
      actions: [
        TextButton.icon(
          onPressed: _busy ? null : _refresh,
          icon: const Icon(Icons.refresh, size: 16),
          label: const Text('Refresh'),
        ),
        ElevatedButton(onPressed: () => Navigator.pop(context), child: const Text('Done')),
      ],
    );
  }

  Widget _row(BuildContext context, Map<String, dynamic> m) {
    final scheme = Theme.of(context).colorScheme;
    final nodeId = m['node_id']?.toString() ?? '';
    final name = (m['hostname']?.toString().isNotEmpty ?? false) ? m['hostname'].toString() : nodeId;
    final member = m['role'] == 'member';
    final perms = ((m['permissions'] as List?) ?? const []).join(', ');
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(member ? Icons.group_add_outlined : Icons.home_outlined,
              size: 18, color: scheme.onSurfaceVariant),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(name, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                Text(member ? 'Member: $perms' : 'Home network',
                    style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant)),
              ],
            ),
          ),
          if (member)
            TextButton(
              onPressed: _busy ? null : () => _leave(nodeId),
              style: TextButton.styleFrom(foregroundColor: AppTheme.errorColor),
              child: const Text('Leave'),
            ),
        ],
      ),
    );
  }
}
