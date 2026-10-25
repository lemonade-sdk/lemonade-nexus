/// @title Invite Member dialog
/// @description Mints a single-use invitation code (POST /api/link/token over
/// the private mesh API) so another person or device can join this Cluster's
/// group, or a chosen group when the dialog is opened from a group's context
/// menu. Shows the code with copy, a live expiry countdown and regeneration.
/// When this device cannot mint codes yet it says why instead of failing
/// silently.
library;

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../sdk/ffi_bindings.dart' show LnError;
import '../sdk/lemonade_nexus_sdk.dart';
import '../state/providers.dart';
import '../../theme/app_theme.dart';

/// Show the invite dialog. Without [targetNodeId] the invite targets this
/// account's own top-level group; with it, the invite targets that group
/// ([targetLabel] names it in the title).
Future<void> showInviteMemberDialog(BuildContext context,
    {String? targetNodeId, String? targetLabel}) {
  return showDialog<void>(
    context: context,
    builder: (_) =>
        InviteMemberDialog(targetNodeId: targetNodeId, targetLabel: targetLabel),
  );
}

class InviteMemberDialog extends ConsumerStatefulWidget {
  final String? targetNodeId;
  final String? targetLabel;
  const InviteMemberDialog({super.key, this.targetNodeId, this.targetLabel});

  @override
  ConsumerState<InviteMemberDialog> createState() => _InviteMemberDialogState();
}

class _InviteMemberDialogState extends ConsumerState<InviteMemberDialog> {
  static const _ttlSec = 600;

  String? _code;
  DateTime? _expiresAt;
  String? _error;
  bool _busy = false;
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted && _code != null) setState(() {});
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_blocker() == null) _generate();
    });
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  /// Why this device cannot mint a code right now, or null when it can.
  String? _blocker() {
    final state = ref.read(appNotifierProvider);
    if (!state.isAuthenticated) {
      return 'Sign in to a Cluster before inviting members.';
    }
    if (!state.isMeshEnabled) {
      return 'This device is not on the mesh yet. Invitation codes are issued '
          'over the private mesh API, so the mesh must be up first.';
    }
    return null;
  }

  Future<void> _generate() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final invite = await ref
          .read(appNotifierProvider.notifier)
          .createDeviceInvite(ttlSec: _ttlSec, targetNodeId: widget.targetNodeId);
      final code = invite['link_token']?.toString() ?? '';
      if (code.isEmpty) {
        throw SdkException(LnError.internal,
            message: invite['error']?.toString() ?? 'The server returned no code');
      }
      final expiresSec = (invite['expires_at'] as num?)?.toInt();
      setState(() {
        _code = code;
        _expiresAt = expiresSec != null
            ? DateTime.fromMillisecondsSinceEpoch(expiresSec * 1000)
            : DateTime.now().add(const Duration(seconds: _ttlSec));
      });
    } on SdkException catch (e) {
      setState(() => _error = e.message ?? e.toString());
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Duration get _remaining {
    final expiresAt = _expiresAt;
    if (expiresAt == null) return Duration.zero;
    final left = expiresAt.difference(DateTime.now());
    return left.isNegative ? Duration.zero : left;
  }

  String _formatRemaining(Duration d) {
    final m = d.inMinutes;
    final s = d.inSeconds % 60;
    return '$m:${s.toString().padLeft(2, '0')}';
  }

  void _copy() {
    final code = _code;
    if (code == null) return;
    Clipboard.setData(ClipboardData(text: code));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
      content: Text('Invitation code copied'),
      backgroundColor: AppTheme.lemonGreen,
    ));
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final blocker = _blocker();
    final expired = _code != null && _remaining == Duration.zero;

    return AlertDialog(
      backgroundColor: scheme.surface,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: scheme.outline)),
      title: Row(
        children: [
          const Icon(Icons.person_add_alt_1, color: AppTheme.lemonYellowDark, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              widget.targetNodeId == null
                  ? 'Invite member'
                  : 'Invite user to ${widget.targetLabel ?? widget.targetNodeId}',
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
      content: SizedBox(
        width: 440,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (blocker != null)
              _notice(context, Icons.info_outline, blocker, scheme.onSurfaceVariant)
            else ...[
              Text(
                'Share this code with the person you are inviting. On a new '
                'device they choose "Have an invitation code?" on the sign-in '
                'screen and enter it. A person who already has a network '
                'enters it in "Join another network" and keeps their own '
                'network. The code works once.',
                style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: 16),
              if (_busy && _code == null)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 24),
                  child: Center(child: CircularProgressIndicator()),
                )
              else if (_code != null)
                _codeBox(context, expired),
              if (_error != null) ...[
                const SizedBox(height: 12),
                _notice(context, Icons.error_outline,
                    'Could not create an invitation: $_error', AppTheme.errorColor),
              ],
              const SizedBox(height: 12),
              Text(
                'Members join your group with their own key. They can read '
                'Cluster data only after you share the account key with them '
                'from the Devices list.',
                style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant),
              ),
            ],
          ],
        ),
      ),
      actions: [
        if (blocker == null)
          TextButton.icon(
            onPressed: _busy ? null : _generate,
            icon: const Icon(Icons.refresh, size: 16),
            label: Text(_code == null ? 'Try again' : 'New code'),
          ),
        if (blocker == null && _code != null && !expired)
          TextButton.icon(
            onPressed: _copy,
            icon: const Icon(Icons.copy, size: 16),
            label: const Text('Copy'),
          ),
        ElevatedButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Done'),
        ),
      ],
    );
  }

  Widget _codeBox(BuildContext context, bool expired) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
            color: expired ? AppTheme.errorColor : AppTheme.lemonYellowDark,
            width: 1.2),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SelectableText(
            _code!,
            style: TextStyle(
              fontSize: 14,
              fontFamily: 'monospace',
              letterSpacing: 0.5,
              color: expired ? scheme.onSurfaceVariant : scheme.onSurface,
              decoration: expired ? TextDecoration.lineThrough : null,
            ),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Icon(Icons.timer_outlined,
                  size: 14,
                  color: expired ? AppTheme.errorColor : scheme.onSurfaceVariant),
              const SizedBox(width: 6),
              Text(
                expired
                    ? 'Expired. Create a new code.'
                    : 'Expires in ${_formatRemaining(_remaining)}',
                style: TextStyle(
                    fontSize: 12,
                    color: expired ? AppTheme.errorColor : scheme.onSurfaceVariant),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _notice(BuildContext context, IconData icon, String text, Color color) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 18, color: color),
        const SizedBox(width: 8),
        Expanded(child: Text(text, style: TextStyle(fontSize: 13, color: color))),
      ],
    );
  }
}
