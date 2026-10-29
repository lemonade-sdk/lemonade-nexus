/// @title Invites
/// @description The invite a device mints (ln_invite_create) and the two
/// forms it comes in: an 8-digit invite code and the full link token. Both
/// name one single-use invite; the SDK passes either through unchanged and
/// the server treats exactly 8 digits as a code.
library;

/// Number of digits in an invite code.
const int inviteCodeDigits = 8;

/// What a join or accept field accepts, for labels and validation messages.
const String inviteInputHint = '8-digit code or invite token';

final RegExp _codePattern = RegExp(r'^[0-9]{8}$');
final RegExp _tokenPattern = RegExp(r'^lnk_[0-9a-fA-F]{64}$');

/// True when [invite] is an invite code: exactly 8 decimal digits.
bool isInviteCode(String invite) => _codePattern.hasMatch(invite);

/// Why [invite] is neither an invite code nor a link token, or null when it
/// is one of the two. Mirrors the native SDK's check (invite_format_error),
/// so the UI can refuse a mistyped invite before the SDK is called.
String? inviteFormatError(String invite) {
  final text = invite.trim();
  if (text.isEmpty) return 'Enter an $inviteInputHint';
  if (isInviteCode(text) || _tokenPattern.hasMatch(text)) return null;
  final digits = text.replaceAll(RegExp(r'\s'), '');
  if (RegExp(r'^[0-9]+$').hasMatch(digits)) {
    return 'An invite code has $inviteCodeDigits digits';
  }
  return 'Enter an $inviteInputHint (lnk_ and 64 hex digits)';
}

/// The value to hand to the SDK: [invite] without surrounding whitespace and,
/// for a code typed with spaces ("1234 5678"), without the spaces.
String normalizeInvite(String invite) {
  final text = invite.trim();
  final compact = text.replaceAll(RegExp(r'\s'), '');
  return isInviteCode(compact) ? compact : text;
}

/// [code] grouped for reading, "1234 5678". Anything that is not an invite
/// code is returned unchanged.
String formatInviteCode(String code) {
  if (!isInviteCode(code)) return code;
  return '${code.substring(0, 4)} ${code.substring(4)}';
}

/// One minted invite, as ln_invite_create returns it.
class Invite {
  /// The full token, "lnk_" and 64 hex digits; valid until [expiresAt].
  final String linkToken;

  /// The 8-digit invite code that names the same invite; valid until
  /// [codeExpiresAt]. Null when the server predates invite codes.
  final String? code;
  final String groupNodeId;
  final String targetNodeId;
  final List<String> permissions;

  /// Unix seconds.
  final int? expiresAt;

  /// Unix seconds; at most ten minutes after minting. Null without [code].
  final int? codeExpiresAt;

  const Invite({
    required this.linkToken,
    this.code,
    required this.groupNodeId,
    required this.targetNodeId,
    this.permissions = const [],
    this.expiresAt,
    this.codeExpiresAt,
  });

  bool get hasCode => code != null && isInviteCode(code!);

  /// The form to show first: the code when the server issued one, else the
  /// token.
  String get primary => hasCode ? code! : linkToken;

  factory Invite.fromJson(Map<String, dynamic> json) {
    final code = json['code']?.toString();
    final group = json['group_node_id']?.toString() ?? '';
    return Invite(
      linkToken: json['link_token']?.toString() ?? '',
      code: code != null && isInviteCode(code) ? code : null,
      groupNodeId: group,
      targetNodeId: json['target_node_id']?.toString() ?? group,
      permissions: ((json['permissions'] as List?) ?? const [])
          .map((p) => p.toString())
          .toList(),
      expiresAt: (json['expires_at'] as num?)?.toInt(),
      codeExpiresAt: (json['code_expires_at'] as num?)?.toInt(),
    );
  }
}
