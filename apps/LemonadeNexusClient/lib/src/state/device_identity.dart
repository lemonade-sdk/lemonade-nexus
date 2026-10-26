/// @title Device Identity
/// @description Decisions about the device identity that need no I/O: which
/// legacy copy moves into the SDK's per-user identity store, and how a store
/// state or failure is explained to the user. The SDK store keeps one
/// identity for the signed-in OS user behind the OS keystore; the app never
/// falls back to a plaintext copy.
library;

import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
import 'cluster_keyring.dart' show canonicalPrincipal;

/// Where a legacy identity copy lives.
enum LegacyIdentitySource {
  /// A `seed` on a Cluster entry in the secure-storage keyring.
  keyring,

  /// An `identity.json` file in the app support directory.
  identityFile,
}

/// One identity copy from before the per-user store, identified by its public
/// key only. The secret stays where it is until the plan is carried out.
class LegacyIdentity {
  final LegacyIdentitySource source;

  /// The keyring entry (localId) that holds the seed; null for the file.
  final String? localId;

  /// What to call it in the activity log: the Cluster name or the file path.
  final String name;

  /// `ed25519:<base64>` as the SDK prints it.
  final String publicKey;

  const LegacyIdentity({
    required this.source,
    required this.name,
    required this.publicKey,
    this.localId,
  });
}

/// What to do with the legacy copies. The store identity, once present, is
/// never replaced.
class IdentityMigrationPlan {
  /// The legacy identity to import. Null when the store already holds one or
  /// when there is no legacy copy. The caller deletes this copy after the
  /// import is verified against the store's public key.
  final LegacyIdentity? import;

  /// Further copies of the same identity (the store's, or [import]'s). They
  /// are deleted once the store holds that identity.
  final List<LegacyIdentity> remove;

  /// Legacy identities that differ from the store's. They are kept, reported,
  /// and never used: a membership registered with such a key cannot connect
  /// with the stored identity.
  final List<LegacyIdentity> conflicts;

  const IdentityMigrationPlan({
    this.import,
    this.remove = const [],
    this.conflicts = const [],
  });

  bool get isEmpty => import == null && remove.isEmpty && conflicts.isEmpty;
}

/// Decide the migration. [legacy] is in order of preference (most recently
/// used first); the first entry is imported when the store is empty.
/// [storePublicKey] is the store's identity, or null when none is stored.
IdentityMigrationPlan planIdentityMigration({
  required String? storePublicKey,
  required List<LegacyIdentity> legacy,
}) {
  if (legacy.isEmpty) return const IdentityMigrationPlan();
  LegacyIdentity? import;
  var keep = storePublicKey ?? '';
  if (keep.isEmpty) {
    import = legacy.first;
    keep = import.publicKey;
  }
  final canonical = canonicalPrincipal(keep);
  final remove = <LegacyIdentity>[];
  final conflicts = <LegacyIdentity>[];
  for (final copy in legacy) {
    if (identical(copy, import)) continue;
    (canonicalPrincipal(copy.publicKey) == canonical ? remove : conflicts).add(copy);
  }
  return IdentityMigrationPlan(import: import, remove: remove, conflicts: conflicts);
}

/// True when the two keys name the same Ed25519 public key, whatever the
/// base64 spelling or "ed25519:" prefix.
bool sameIdentityKey(String a, String b) => canonicalPrincipal(a) == canonicalPrincipal(b);

/// The keystore name for the settings view.
String identityBackendLabel(String backend) {
  switch (backend) {
    case 'keychain':
      return 'macOS Keychain';
    case 'dpapi':
      return 'Windows DPAPI';
    case 'libsecret':
      return 'Secret Service (libsecret)';
    case 'none':
      return 'No keystore';
    default:
      return backend;
  }
}

/// One line about the store for the settings view.
String describeIdentityStore(IdentityStoreStatus status) {
  if (!status.keystoreAvailable) {
    return 'No usable OS keystore in this process; no identity can be stored.';
  }
  if (!status.present) return 'No identity stored yet.';
  if (status.unlocked) return 'Stored and unlocked.';
  return 'Stored, but the keystore did not release it (locked or access denied).';
}

/// Why a store operation failed, in the user's terms. The app fails closed:
/// no plaintext fallback, so the text says what to fix.
String explainIdentityStoreFailure(LnError error, {IdentityStoreStatus? status}) {
  final dir = status?.dir ?? '';
  switch (error) {
    case LnError.unsupported:
      return 'No OS keystore is usable in this process, or the stored identity '
          'was wrapped by another keystore. The device identity cannot be '
          'stored without one.';
    case LnError.auth:
      return 'The OS keystore is locked or refused access to the device '
          'identity. Unlock it and try again.';
    case LnError.rejected:
      return 'The stored identity failed verification or its keystore item is '
          'gone. Remove the stored identity and create it again.';
    case LnError.notFound:
      return 'No device identity is stored.';
    case LnError.internal:
      return 'The identity directory${dir.isEmpty ? '' : ' $dir'} could not be '
          'read or written. On macOS a sandboxed app needs access to that folder.';
    default:
      return 'The identity store failed: ${error.name}.';
  }
}

/// Thrown by a join, register, or connect when the store cannot give the
/// device identity. [reason] is the text from [explainIdentityStoreFailure].
class DeviceIdentityUnavailable implements Exception {
  final String reason;
  const DeviceIdentityUnavailable(this.reason);

  @override
  String toString() => 'No device identity: $reason';
}

/// The device identity as the UI sees it.
class DeviceIdentityState {
  /// The last store status read; null before the first read.
  final IdentityStoreStatus? status;

  /// Why the identity is not usable; null when it is loaded in the SDK.
  final String? error;

  const DeviceIdentityState({this.status, this.error});

  static const unknown = DeviceIdentityState();

  /// True when the stored identity is loaded and can sign.
  bool get ready => error == null && status != null && status!.unlocked;
}
