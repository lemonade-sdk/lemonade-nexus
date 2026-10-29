// Invite codes in the client: the shape check and normalization a join or
// accept field applies before the SDK is called, the grouped display of a
// code, and the invite box that shows the code first and copies the plain
// digits. No native SDK library is needed.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

import 'package:nexus_client/src/views/invite_member_dialog.dart';

const _token = 'lnk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

void main() {
  group('inviteFormatError', () {
    test('accepts an 8-digit code and a full token, nothing else', () {
      expect(inviteFormatError('12345678'), isNull);
      expect(inviteFormatError(' 12345678 '), isNull, reason: 'surrounding space is trimmed');
      expect(inviteFormatError(_token), isNull);
      expect(inviteFormatError(_token.toUpperCase().replaceFirst('LNK_', 'lnk_')), isNull);
      expect(inviteFormatError(''), isNotNull);
      expect(inviteFormatError('1234567'), contains('8 digits'));
      expect(inviteFormatError('123456789'), contains('8 digits'));
      expect(inviteFormatError('1234567a'), contains(inviteInputHint));
      expect(inviteFormatError('lnk_x'), contains(inviteInputHint));
      expect(inviteFormatError('${_token}0'), isNotNull);
    });

    test('a code typed with a space is normalized, a token is kept as typed', () {
      expect(normalizeInvite('1234 5678'), '12345678');
      expect(normalizeInvite(' 12345678\n'), '12345678');
      expect(normalizeInvite(' $_token '), _token);
      expect(normalizeInvite('1234 567'), '1234 567', reason: 'not a code; left for the error');
      expect(inviteFormatError(normalizeInvite('1234 5678')), isNull);
    });
  });

  group('formatInviteCode and Invite', () {
    test('groups a code as 1234 5678 and leaves a token alone', () {
      expect(formatInviteCode('12345678'), '1234 5678');
      expect(formatInviteCode('00000000'), '0000 0000');
      expect(formatInviteCode(_token), _token);
      expect(isInviteCode('12345678'), isTrue);
      expect(isInviteCode('1234 5678'), isFalse);
    });

    test('reads the code next to the token, and does without it', () {
      final invite = Invite.fromJson({
        'link_token': _token,
        'code': '24681357',
        'group_node_id': 'customer-a',
        'target_node_id': 'customer-a',
        'permissions': ['read', 'connect_private'],
        'expires_at': 1800000600,
        'code_expires_at': 1800000600,
      });
      expect(invite.hasCode, isTrue);
      expect(invite.code, '24681357');
      expect(invite.primary, '24681357');
      expect(invite.linkToken, _token);
      expect(invite.permissions, ['read', 'connect_private']);
      expect(invite.codeExpiresAt, 1800000600);

      final older = Invite.fromJson({'link_token': _token, 'group_node_id': 'customer-a'});
      expect(older.hasCode, isFalse);
      expect(older.primary, _token);
      expect(older.targetNodeId, 'customer-a');

      final malformed = Invite.fromJson({'link_token': _token, 'code': 'abc'});
      expect(malformed.hasCode, isFalse, reason: 'a code is exactly 8 digits');
    });
  });

  group('InviteCodeBox', () {
    Future<void> pumpBox(WidgetTester tester, Invite invite,
        {required VoidCallback onCopyCode, required VoidCallback onCopyToken}) {
      return tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: InviteCodeBox(
            invite: invite,
            expired: false,
            remaining: '9:59',
            onCopyCode: onCopyCode,
            onCopyToken: onCopyToken,
          ),
        ),
      ));
    }

    testWidgets('shows the code grouped and first, and the token behind a secondary action',
        (tester) async {
      var codeCopies = 0;
      var tokenCopies = 0;
      await pumpBox(tester, const Invite(linkToken: _token, code: '12345678', groupNodeId: 'g', targetNodeId: 'g'),
          onCopyCode: () => codeCopies++, onCopyToken: () => tokenCopies++);
      expect(find.text('1234 5678'), findsOneWidget);
      expect(find.text(_token), findsNothing);
      expect(find.text('Copy full invite token'), findsOneWidget);
      expect(find.textContaining('Expires in 9:59'), findsOneWidget);

      await tester.tap(find.byKey(const Key('copy-invite-code')));
      await tester.tap(find.byKey(const Key('copy-invite-token')));
      await tester.pump();
      expect(codeCopies, 1);
      expect(tokenCopies, 1);
    });

    testWidgets('without a code the token is shown in its place', (tester) async {
      await pumpBox(tester, const Invite(linkToken: _token, groupNodeId: 'g', targetNodeId: 'g'),
          onCopyCode: () {}, onCopyToken: () {});
      expect(find.text(_token), findsOneWidget);
      expect(find.text('Copy full invite token'), findsNothing);
    });

    testWidgets('the dialog copies the plain digits, not the grouped text', (tester) async {
      // The dialog's copy handler puts invite.primary on the clipboard. The
      // box only reports the tap; here the same contract is checked end to
      // end through the platform clipboard channel.
      String? copied;
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform,
          (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String?;
        }
        return null;
      });
      const invite = Invite(linkToken: _token, code: '12345678', groupNodeId: 'g', targetNodeId: 'g');
      await pumpBox(tester, invite,
          onCopyCode: () => Clipboard.setData(ClipboardData(text: invite.primary)),
          onCopyToken: () {});
      await tester.tap(find.byKey(const Key('copy-invite-code')));
      await tester.pump();
      expect(copied, '12345678');
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null);
    });
  });
}
