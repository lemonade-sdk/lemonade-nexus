/// @title Join outcome
/// @description Decides what the app reports after a join with an invite
/// code. A device that already had its own node stays in its own network; the
/// server then makes its identity a member of the invite's group, or refuses
/// that membership. Pure logic, so tests check it without the native SDK.
library;

import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

/// What a join with an invite code did, as the app reports it.
class JoinOutcome {
  /// True when the invite did not take effect. The device can still be
  /// connected to its own network.
  final bool isError;

  /// True when the device joined the invite's group as a member and stays in
  /// its own network, so no new Cluster entry is created for the invite.
  final bool stayedInOwnNetwork;

  /// The text for the activity log and for an error display.
  final String message;

  const JoinOutcome({
    required this.isError,
    required this.stayedInOwnNetwork,
    required this.message,
  });
}

/// Describes a join with an invite code.
///
/// [invitedName] names the invite's group. [homeName] names the network this
/// device is placed in; it is used only when [membership] is set.
/// [membership] is [NetworkJoinResponse.membership]: null when the device
/// joined the invite's group itself. [hasGroupKey] tells whether this device
/// already holds that group's account key.
JoinOutcome describeJoinOutcome({
  required String invitedName,
  required String homeName,
  required JoinMembership? membership,
  required bool hasGroupKey,
}) {
  if (membership == null) {
    return JoinOutcome(
      isError: false,
      stayedInOwnNetwork: false,
      message: hasGroupKey
          ? 'Joined Cluster "$invitedName"'
          : 'Joined "$invitedName" — waiting for the account key',
    );
  }
  final stays = 'This device already has its own network "$homeName" and '
      'stays in it.';
  switch (membership.status) {
    case 'member':
      return JoinOutcome(
        isError: false,
        stayedInOwnNetwork: true,
        message: '$stays The invite made it a member of "$invitedName".',
      );
    case 'pending':
      return JoinOutcome(
        isError: false,
        stayedInOwnNetwork: true,
        message: '$stays The invite makes it a member of "$invitedName" when '
            'the servers commit the change.',
      );
    default:
      final reason = membership.error?.trim();
      return JoinOutcome(
        isError: true,
        stayedInOwnNetwork: true,
        message: 'The invite to "$invitedName" was refused: '
            '${reason == null || reason.isEmpty ? 'the server gave no reason (status "${membership.status}")' : reason}. '
            '$stays',
      );
  }
}
