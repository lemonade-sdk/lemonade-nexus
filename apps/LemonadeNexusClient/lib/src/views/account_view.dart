/// @title Cluster View
/// @description Manage the connected Cluster (account): its devices — invite a
/// new one and share the account key with it — plus identity/session details
/// and the zero-knowledge encrypted-chat round-trip over the private mesh API
/// (/api/chats, /api/account/keys/*). The server stores opaque blobs it cannot
/// read; real client-side E2E crypto is a later step, so this view sends a
/// placeholder ciphertext purely to prove the account-data path works.
library;

import 'dart:convert';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/cluster_keyring.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class AccountView extends ConsumerStatefulWidget {
  const AccountView({super.key});

  @override
  ConsumerState<AccountView> createState() => _AccountViewState();
}

class _AccountViewState extends ConsumerState<AccountView> {
  bool _isLoading = false;
  String? _error;
  List<Map<String, dynamic>> _chats = [];
  int _pendingKeys = 0;
  bool _hasEnvelope = false;
  List<ClusterDevice> _devices = [];
  bool _isBusyDevices = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    // Clear first: an early return used to leave a stale error on screen that
    // no amount of refreshing could shift.
    setState(() => _error = null);
    if (!ref.read(appNotifierProvider).isMeshEnabled) return;
    setState(() => _isLoading = true);
    final notifier = ref.read(appNotifierProvider.notifier);
    try {
      final resp = await notifier.callPrivateApi('GET', '/api/chats');
      if (resp.containsKey('error')) {
        setState(() {
          _error = resp['error'].toString();
          _isLoading = false;
        });
        return;
      }
      final list = (resp['chats'] as List?) ?? const [];
      // Best-effort key-envelope status (ignore individual failures).
      int pending = _pendingKeys;
      bool hasEnv = _hasEnvelope;
      try {
        final p = await notifier.callPrivateApi('GET', '/api/account/keys/pending');
        pending = ((p['pending'] as List?) ?? const []).length;
      } catch (e) {
        debugPrint('[ClusterView] keys/pending failed: $e');
      }
      try {
        // fetchGroupKey, not a raw GET: it persists the key into the keyring.
        hasEnv = await notifier.fetchGroupKey() != null;
      } catch (e) {
        debugPrint('[ClusterView] fetchGroupKey failed: $e');
      }
      List<ClusterDevice> devices = _devices;
      try {
        devices = await notifier.listClusterDevices();
      } catch (e) {
        debugPrint('[ClusterView] listClusterDevices failed: $e');
      }
      if (!mounted) return;
      setState(() {
        _chats =
            list.map((e) => Map<String, dynamic>.from(e as Map)).toList();
        _pendingKeys = pending;
        _hasEnvelope = hasEnv;
        _devices = devices;
        _isLoading = false;
      });
    } catch (e, stack) {
      debugPrint('[ClusterView] load failed: $e\n$stack');
      if (!mounted) return;
      setState(() {
        _error = 'Could not load Cluster data: $e';
        _isLoading = false;
      });
    }
  }

  String _randomNonceB64() {
    final rng = Random.secure();
    return base64Encode(List<int>.generate(16, (_) => rng.nextInt(256)));
  }

  void _toast(String message, {bool error = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(message),
      backgroundColor: error ? AppTheme.errorColor : AppTheme.lemonGreen,
    ));
  }

  Future<void> _createChat() async {
    final scheme = Theme.of(context).colorScheme;
    final controller = TextEditingController(
        text: 'placeholder-ciphertext-${DateTime.now().millisecondsSinceEpoch}');
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: scheme.outline)),
        title: const Text('New Chat'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'The server stores this blob opaquely — it never reads the '
              'contents. Real end-to-end encryption is a later client step; '
              'this verifies the storage round-trip.',
              style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              maxLines: 3,
              decoration: const InputDecoration(
                labelText: 'Ciphertext (placeholder)',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          ElevatedButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Create')),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      final resp = await ref.read(appNotifierProvider.notifier).callPrivateApi(
        'POST',
        '/api/chats',
        body: {
          'key_id': 'placeholder',
          'nonce': _randomNonceB64(),
          'ciphertext': controller.text,
        },
      );
      if (resp.containsKey('error')) {
        _toast('Create failed: ${resp['error']}', error: true);
      } else {
        _toast('Chat ${(resp['chat_id'] ?? '').toString().substring(0, 8)}… created');
      }
      await _load();
    } catch (e) {
      _toast('Create failed: $e', error: true);
    }
  }

  Future<void> _viewChat(String chatId) async {
    try {
      final resp = await ref
          .read(appNotifierProvider.notifier)
          .callPrivateApi('GET', '/api/chats/$chatId');
      if (!mounted) return;
      final scheme = Theme.of(context).colorScheme;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          backgroundColor: scheme.surface,
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
              side: BorderSide(color: scheme.outline)),
          title: const Text('Chat blob (as stored)'),
          content: SingleChildScrollView(
            child: SelectableText(
              const JsonEncoder.withIndent('  ').convert(resp),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Close')),
          ],
        ),
      );
    } catch (e) {
      _toast('Load failed: $e', error: true);
    }
  }

  Future<void> _deleteChat(String chatId) async {
    final scheme = Theme.of(context).colorScheme;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: scheme.outline)),
        title: const Text('Delete chat?'),
        content: Text('This permanently deletes chat $chatId.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.errorColor,
                foregroundColor: Colors.white),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await ref
          .read(appNotifierProvider.notifier)
          .callPrivateApi('POST', '/api/chats/$chatId/delete');
      _toast('Chat deleted');
      await _load();
    } catch (e) {
      _toast('Delete failed: $e', error: true);
    }
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
              SectionHeader(
                  title: appState.activeCluster?.name ?? 'Cluster',
                  icon: Icons.account_circle_outlined),
              const Spacer(),
              if (appState.isMeshEnabled) ...[
                IconButton(
                  tooltip: 'New chat',
                  onPressed: _createChat,
                  icon: const Icon(Icons.add_circle_outline),
                ),
                IconButton(
                  tooltip: 'Refresh',
                  onPressed: _load,
                  icon: const Icon(Icons.refresh),
                ),
              ],
            ],
          ),
          const SizedBox(height: 16),
          _identityCard(context, appState),
          const SizedBox(height: 16),
          if (!appState.isMeshEnabled)
            _meshOffCard(context)
          else ...[
            _statsRow(),
            const SizedBox(height: 16),
            _devicesSection(context),
            const SizedBox(height: 16),
            _chatsSection(context),
          ],
        ],
      ),
    );
  }

  Widget _identityCard(BuildContext context, dynamic appState) {
    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text('Identity & Session',
                  style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
              const Spacer(),
              StatusDot(isHealthy: appState.isMeshEnabled),
              const SizedBox(width: 6),
              LemonBadge(
                text: appState.isMeshEnabled ? 'Mesh up' : 'Mesh off',
                color: appState.isMeshEnabled
                    ? AppTheme.lemonGreen
                    : AppTheme.errorColor,
              ),
            ],
          ),
          const SizedBox(height: 12),
          _row(context, 'User', appState.username),
          _row(context, 'User ID', appState.userId, copy: true),
          _row(context, 'Public key', appState.publicKeyBase64, copy: true),
          _row(context, 'Tunnel IP', appState.tunnelIP),
        ],
      ),
    );
  }

  Widget _statsRow() {
    return Row(
      children: [
        Expanded(
          child: StatCard(
            title: 'Chats',
            value: '${_chats.length}',
            icon: Icons.chat_bubble_outline,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: StatCard(
            title: 'My group key',
            value: _hasEnvelope ? 'Yes' : 'No',
            icon: Icons.vpn_key_outlined,
            color: _hasEnvelope ? AppTheme.lemonGreen : AppTheme.errorColor,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: StatCard(
            title: 'Devices needing key',
            value: '$_pendingKeys',
            icon: Icons.devices_other,
          ),
        ),
      ],
    );
  }

  // ---- devices --------------------------------------------------------------

  Widget _devicesSection(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    // Sharing seals OUR copy to another device, so only offer it when we hold
    // the key, and never for our own row.
    final weHoldKey = ref.read(appNotifierProvider).activeCluster?.hasGroupKey ?? false;
    final anyPending = _devices.any((d) => d.needsKey && !d.isThisDevice);
    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text('Devices',
                  style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
              const SizedBox(width: 8),
              Text('${_devices.length}',
                  style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
              const Spacer(),
              if (anyPending && weHoldKey)
                TextButton.icon(
                  onPressed: _isBusyDevices ? null : _shareKeyWithAll,
                  icon: const Icon(Icons.key, size: 16),
                  label: const Text('Share key with all'),
                ),
              TextButton.icon(
                onPressed: _isBusyDevices ? null : _addDevice,
                icon: const Icon(Icons.add_to_queue, size: 16),
                label: const Text('Add device'),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            'Each device has its own key. An invitation code lets a new device '
            'join; it can only read Cluster data once an existing device shares '
            'the account key with it.',
            style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant),
          ),
          const SizedBox(height: 12),
          if (_devices.isEmpty)
            Text('No devices listed yet.',
                style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant))
          else
            for (final device in _devices) _deviceRow(context, device, weHoldKey),
        ],
      ),
    );
  }

  Widget _deviceRow(BuildContext context, ClusterDevice device, bool weHoldKey) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Icon(device.isThisDevice ? Icons.computer : Icons.devices_other,
              size: 18,
              color: device.isThisDevice
                  ? AppTheme.lemonYellowDark
                  : scheme.onSurfaceVariant),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Flexible(
                      child: Text(device.hostname,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(
                              fontSize: 13, fontWeight: FontWeight.w500)),
                    ),
                    if (device.isThisDevice) ...[
                      const SizedBox(width: 6),
                      const LemonBadge(text: 'THIS DEVICE'),
                    ],
                    if (device.needsKey) ...[
                      const SizedBox(width: 6),
                      const LemonBadge(
                          text: 'NEEDS KEY', color: AppTheme.errorColor),
                    ],
                  ],
                ),
                Text(device.tunnelIp?.isNotEmpty == true ? device.tunnelIp! : device.nodeId,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                        fontSize: 11,
                        fontFamily: 'monospace',
                        color: scheme.onSurfaceVariant)),
              ],
            ),
          ),
          if (device.needsKey && device.isThisDevice)
            IconButton(
              tooltip: 'Check for the account key',
              visualDensity: VisualDensity.compact,
              icon: const Icon(Icons.refresh, size: 16),
              onPressed: _isBusyDevices ? null : _load,
            )
          else if (device.needsKey && weHoldKey)
            IconButton(
              tooltip: 'Share the account key with this device',
              visualDensity: VisualDensity.compact,
              icon: const Icon(Icons.key, size: 16),
              onPressed: _isBusyDevices ? null : _shareKeyWithAll,
            ),
          if (!device.isThisDevice)
            IconButton(
              tooltip: 'Remove device',
              visualDensity: VisualDensity.compact,
              icon: const Icon(Icons.delete_outline,
                  size: 16, color: AppTheme.errorColor),
              onPressed: _isBusyDevices ? null : () => _removeDevice(device),
            ),
        ],
      ),
    );
  }

  /// Mint an invitation code and show it for transfer to the new device.
  Future<void> _addDevice() async {
    setState(() => _isBusyDevices = true);
    try {
      final invite =
          await ref.read(appNotifierProvider.notifier).createDeviceInvite();
      final code = invite['link_token']?.toString() ?? '';
      if (code.isEmpty) {
        _toast(invite['error']?.toString() ?? 'Could not create an invitation',
            error: true);
        return;
      }
      if (!mounted) return;
      await _showInviteDialog(code);
    } catch (e) {
      _toast('Could not create an invitation: $e', error: true);
    } finally {
      if (mounted) setState(() => _isBusyDevices = false);
    }
  }

  Future<void> _showInviteDialog(String code) {
    final scheme = Theme.of(context).colorScheme;
    return showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: scheme.outline)),
        title: const Text('Invitation code'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Enter this on the new device via "Have an invitation code?". It '
              'is single-use and expires in 10 minutes. Come back here to share '
              'the account key once it has joined.',
              style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 16),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: scheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(code,
                  style: const TextStyle(fontSize: 12, fontFamily: 'monospace')),
            ),
          ],
        ),
        actions: [
          TextButton.icon(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: code));
              _toast('Invitation code copied');
            },
            icon: const Icon(Icons.copy, size: 16),
            label: const Text('Copy'),
          ),
          ElevatedButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Done')),
        ],
      ),
    );
  }

  /// Seal the account key to every device still waiting for it.
  Future<void> _shareKeyWithAll() async {
    setState(() => _isBusyDevices = true);
    try {
      final count =
          await ref.read(appNotifierProvider.notifier).provisionPendingDevices();
      _toast(count == 0
          ? 'No device was provisioned — this device may not hold the account key yet'
          : 'Shared the account key with $count device${count == 1 ? '' : 's'}');
      await _load();
    } catch (e) {
      _toast('Could not share the account key: $e', error: true);
    } finally {
      if (mounted) setState(() => _isBusyDevices = false);
    }
  }

  Future<void> _removeDevice(ClusterDevice device) async {
    final scheme = Theme.of(context).colorScheme;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: scheme.outline)),
        title: const Text('Remove device'),
        content: Text(
          'Remove "${device.hostname}" from this Cluster and revoke its key. It '
          'keeps any data it already downloaded — the account key is not '
          'rotated yet.',
          style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.errorColor),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    setState(() => _isBusyDevices = true);
    final ok = await ref
        .read(appNotifierProvider.notifier)
        .removeClusterDevice(device.nodeId);
    _toast(ok ? 'Device removed' : 'Could not remove the device', error: !ok);
    if (mounted) setState(() => _isBusyDevices = false);
    await _load();
  }

  Widget _chatsSection(BuildContext context) {
    if (_isLoading) {
      return const Padding(
        padding: EdgeInsets.all(40),
        child: Center(child: CircularProgressIndicator()),
      );
    }
    if (_error != null) {
      return AppCard(
        child: Row(
          children: [
            const Icon(Icons.error_outline, color: AppTheme.errorColor),
            const SizedBox(width: 12),
            Expanded(child: Text(_error!)),
          ],
        ),
      );
    }
    if (_chats.isEmpty) {
      return const EmptyState(
        icon: Icons.chat_bubble_outline,
        title: 'No Chats',
        message: 'Create a chat to verify the encrypted round-trip.',
      );
    }
    return AppCard(
      padding: EdgeInsets.zero,
      child: Column(
        children: [
          for (var i = 0; i < _chats.length; i++) ...[
            if (i > 0) const Divider(height: 1),
            _chatRow(context, _chats[i]),
          ],
        ],
      ),
    );
  }

  Widget _chatRow(BuildContext context, Map<String, dynamic> chat) {
    final scheme = Theme.of(context).colorScheme;
    final id = (chat['chat_id'] ?? '').toString();
    final updated = chat['updated_at'];
    final size = chat['size'];
    return ListTile(
      leading: const StatusDot(isHealthy: true),
      title: Text(
        id,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: Text(
        'updated $updated · $size bytes',
        style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          IconButton(
            tooltip: 'View blob',
            icon: const Icon(Icons.visibility_outlined, size: 18),
            onPressed: () => _viewChat(id),
          ),
          IconButton(
            tooltip: 'Delete',
            icon: const Icon(Icons.delete_outline,
                size: 18, color: AppTheme.errorColor),
            onPressed: () => _deleteChat(id),
          ),
        ],
      ),
    );
  }

  Widget _meshOffCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.lan_outlined, color: AppTheme.lemonYellowDark),
              SizedBox(width: 10),
              Text('Mesh not connected',
                  style:
                      TextStyle(fontSize: 14, fontWeight: FontWeight.w600)),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Account data (chats and group keys) is served only over the private '
            'mesh API. Enable the mesh to reach it.',
            style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
          ),
          const SizedBox(height: 12),
          ElevatedButton.icon(
            icon: const Icon(Icons.play_arrow),
            label: const Text('Enable Mesh'),
            onPressed: () async {
              await ref.read(appNotifierProvider.notifier).enableMesh();
              await _load();
            },
          ),
        ],
      ),
    );
  }

  Widget _row(BuildContext context, String label, String? value,
      {bool copy = false}) {
    final scheme = Theme.of(context).colorScheme;
    final text = (value == null || value.isEmpty) ? '—' : value;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 110,
            child: Text(label,
                style:
                    TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
          ),
          Expanded(
            child: Text(
              text,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (copy && value != null && value.isNotEmpty)
            InkWell(
              onTap: () {
                Clipboard.setData(ClipboardData(text: value));
                _toast('Copied');
              },
              child: Icon(Icons.copy, size: 14, color: scheme.onSurfaceVariant),
            ),
        ],
      ),
    );
  }
}
