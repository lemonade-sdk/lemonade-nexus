/// @title Invite Member dialog
/// @description Mints a single-use invite (POST /api/link/token over the
/// private mesh API) so another person or device can join this Cluster's
/// group, or a chosen group when the dialog is opened from a group's context
/// menu. Shows the 8-digit invitation code large and grouped, with copy of
/// the plain digits, the full invite token under a secondary copy action, a
/// live expiry countdown and regeneration. A server that predates invite
/// codes returns only the token, which is then shown in the code's place.
/// When this device cannot mint invites yet it says why instead of failing
/// silently.
library;

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
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

  Invite? _invite;
  DateTime? _expiresAt;
  String? _error;
  bool _busy = false;
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted && _invite != null) setState(() {});
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
      final json = await ref
          .read(appNotifierProvider.notifier)
          .createDeviceInvite(ttlSec: _ttlSec, targetNodeId: widget.targetNodeId);
      final invite = Invite.fromJson(json);
      if (invite.linkToken.isEmpty) {
        throw SdkException(LnError.internal,
            message: json['error']?.toString() ?? 'The server returned no code');
      }
      // The code's expiry bounds the countdown: the code is what is shown.
      final expiresSec = invite.hasCode
          ? (invite.codeExpiresAt ?? invite.expiresAt)
          : invite.expiresAt;
      setState(() {
        _invite = invite;
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

  void _copy(String text, String what) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text('$what copied'),
      backgroundColor: AppTheme.lemonGreen,
    ));
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final blocker = _blocker();
    final invite = _invite;
    final expired = invite != null && _remaining == Duration.zero;

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
                'device they choose "Join with an invite code" on the sign-in '
                'screen and enter it. A person who already has a network '
                'enters it in "Join another network" and keeps their own '
                'network. The code works once.',
                style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: 16),
              if (_busy && invite == null)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 24),
                  child: Center(child: CircularProgressIndicator()),
                )
              else if (invite != null)
                InviteCodeBox(
                  invite: invite,
                  expired: expired,
                  remaining: _formatRemaining(_remaining),
                  onCopyCode: () => _copy(invite.primary, 'Invitation code'),
                  onCopyToken: () => _copy(invite.linkToken, 'Invite token'),
                ),
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
            label: Text(invite == null ? 'Try again' : 'New code'),
          ),
        if (blocker == null && invite != null && !expired)
          TextButton.icon(
            onPressed: () => _copy(invite.primary, 'Invitation code'),
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

/// The minted invite: the 8-digit code large and grouped ("1234 5678") with
/// copy of the plain digits, the full token under a secondary copy action,
/// and the countdown. Without a code (an older server) the token takes the
/// code's place.
class InviteCodeBox extends StatelessWidget {
  final Invite invite;
  final bool expired;

  /// The countdown text, "m:ss".
  final String remaining;
  final VoidCallback onCopyCode;
  final VoidCallback onCopyToken;

  const InviteCodeBox({
    super.key,
    required this.invite,
    required this.expired,
    required this.remaining,
    required this.onCopyCode,
    required this.onCopyToken,
  });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final muted = expired ? scheme.onSurfaceVariant : scheme.onSurface;
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
          Row(
            children: [
              Expanded(
                child: SelectableText(
                  invite.hasCode ? formatInviteCode(invite.code!) : invite.linkToken,
                  key: const Key('invite-code'),
                  style: TextStyle(
                    fontSize: invite.hasCode ? 32 : 14,
                    fontWeight: invite.hasCode ? FontWeight.w600 : FontWeight.normal,
                    fontFamily: 'monospace',
                    letterSpacing: invite.hasCode ? 4 : 0.5,
                    color: muted,
                    decoration: expired ? TextDecoration.lineThrough : null,
                  ),
                ),
              ),
              if (!expired)
                IconButton(
                  key: const Key('copy-invite-code'),
                  tooltip: 'Copy invitation code',
                  onPressed: onCopyCode,
                  icon: const Icon(Icons.copy, size: 18),
                ),
            ],
          ),
          if (invite.hasCode) ...[
            const SizedBox(height: 4),
            Text(
              'Type this code on the joining device. It works once and for '
              'up to ten minutes.',
              style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant),
            ),
          ],
          const SizedBox(height: 10),
          Row(
            children: [
              Icon(Icons.timer_outlined,
                  size: 14,
                  color: expired ? AppTheme.errorColor : scheme.onSurfaceVariant),
              const SizedBox(width: 6),
              Text(
                expired ? 'Expired. Create a new code.' : 'Expires in $remaining',
                style: TextStyle(
                    fontSize: 12,
                    color: expired ? AppTheme.errorColor : scheme.onSurfaceVariant),
              ),
              const Spacer(),
              if (invite.hasCode && !expired)
                TextButton.icon(
                  key: const Key('copy-invite-token'),
                  onPressed: onCopyToken,
                  icon: const Icon(Icons.link, size: 14),
                  label: const Text('Copy full invite token',
                      style: TextStyle(fontSize: 12)),
                ),
            ],
          ),
        ],
      ),
    );
  }
}
