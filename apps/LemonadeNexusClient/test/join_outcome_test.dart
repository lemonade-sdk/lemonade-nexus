// Join outcome: what the app reports after a join with an invite code, for a
// device that joined the invite's group and for one that already had its own
// network. No native SDK library is needed.

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
import 'package:nexus_client/src/state/join_outcome.dart';

JoinOutcome _describe(JoinMembership? membership, {bool hasGroupKey = true}) =>
    describeJoinOutcome(
      invitedName: 'Office',
      homeName: 'Home',
      membership: membership,
      hasGroupKey: hasGroupKey,
    );

void main() {
  test('a plain join is a success in the invited network', () {
    final outcome = _describe(null);
    expect(outcome.isError, isFalse);
    expect(outcome.stayedInOwnNetwork, isFalse);
    expect(outcome.message, contains('Office'));
    expect(outcome.message, isNot(contains('Home')));
  });

  test('a plain join without the account key is still a success', () {
    final outcome = _describe(null, hasGroupKey: false);
    expect(outcome.isError, isFalse);
    expect(outcome.stayedInOwnNetwork, isFalse);
  });

  for (final status in ['member', 'pending']) {
    test('a "$status" membership keeps the device in its own network', () {
      final outcome = _describe(JoinMembership(status: status, groupId: 'g-office'));
      expect(outcome.isError, isFalse);
      expect(outcome.stayedInOwnNetwork, isTrue);
      expect(outcome.message, contains('"Home"'));
      expect(outcome.message, contains('"Office"'));
    });
  }

  test('a refused membership is an error that carries the server reason', () {
    final outcome = _describe(const JoinMembership(
        status: 'refused', groupId: 'g-office', error: 'invite expired'));
    expect(outcome.isError, isTrue);
    expect(outcome.stayedInOwnNetwork, isTrue);
    expect(outcome.message, contains('invite expired'));
  });

  test('a refusal without a reason still reports the status', () {
    final outcome =
        _describe(const JoinMembership(status: 'refused', groupId: 'g-office'));
    expect(outcome.isError, isTrue);
    expect(outcome.message, contains('refused'));
  });

  test('an unknown membership status is not reported as a success', () {
    final outcome =
        _describe(const JoinMembership(status: 'mystery', groupId: 'g-office'));
    expect(outcome.isError, isTrue);
    expect(outcome.message, contains('mystery'));
  });
}
