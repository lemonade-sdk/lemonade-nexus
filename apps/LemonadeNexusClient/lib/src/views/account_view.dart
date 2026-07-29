/// @title Account View
/// @description Verify the account system end to end: identity/session details,
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

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    if (!ref.read(appNotifierProvider).isMeshEnabled) return;
    setState(() {
      _isLoading = true;
      _error = null;
    });
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
      } catch (_) {}
      try {
        final e = await notifier.callPrivateApi('GET', '/api/account/keys/envelope');
        hasEnv = !e.containsKey('error');
      } catch (_) {}
      if (!mounted) return;
      setState(() {
        _chats =
            list.map((e) => Map<String, dynamic>.from(e as Map)).toList();
        _pendingKeys = pending;
        _hasEnvelope = hasEnv;
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        // A private-API call throws when the mesh transport can't reach the
        // server (tunnel still connecting or down). Show an actionable message
        // instead of the raw exception.
        _error = 'Could not reach the server over the mesh yet. If the tunnel '
            'just came up, give it a moment and tap Refresh.';
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
              const SectionHeader(
                  title: 'Account', icon: Icons.account_circle_outlined),
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
