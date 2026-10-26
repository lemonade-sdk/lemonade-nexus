// The device-identity decisions: which legacy copy moves into the per-user
// identity store, and how the store state is reported. Pure functions; none
// of these tests needs the native SDK library.

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
import 'package:nexus_client/src/state/device_identity.dart';

const _keyA = 'ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const _keyB = 'ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=';

LegacyIdentity _entry(String localId, String key) => LegacyIdentity(
    source: LegacyIdentitySource.keyring,
    localId: localId,
    name: 'Cluster "$localId"',
    publicKey: key);

const _file = LegacyIdentity(
    source: LegacyIdentitySource.identityFile,
    name: '/support/identity.json',
    publicKey: _keyA);

void main() {
  group('planIdentityMigration', () {
    test('nothing to do without legacy copies', () {
      expect(planIdentityMigration(storePublicKey: null, legacy: const []).isEmpty, isTrue);
      expect(planIdentityMigration(storePublicKey: _keyA, legacy: const []).isEmpty, isTrue);
    });

    test('an empty store imports the most recently used copy', () {
      final recent = _entry('recent', _keyA);
      final plan = planIdentityMigration(
          storePublicKey: null, legacy: [recent, _entry('older', _keyB), _file]);
      expect(plan.import, same(recent));
      expect(plan.remove, [_file], reason: 'same key as the imported one');
      expect(plan.conflicts.map((c) => c.localId), ['older']);
    });

    test('an empty store treats an empty public key as none', () {
      final plan = planIdentityMigration(storePublicKey: '', legacy: [_file]);
      expect(plan.import, same(_file));
      expect(plan.remove, isEmpty);
      expect(plan.conflicts, isEmpty);
    });

    test('a store that holds an identity is never replaced', () {
      final plan = planIdentityMigration(
          storePublicKey: _keyB, legacy: [_entry('a', _keyA), _entry('b', _keyB)]);
      expect(plan.import, isNull);
      expect(plan.remove.map((c) => c.localId), ['b']);
      expect(plan.conflicts.map((c) => c.localId), ['a']);
    });

    test('key spelling does not matter', () {
      // Standard base64 with padding against the url-safe unpadded spelling.
      const standard = 'ed25519:+/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
      const urlSafe = '-_8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      expect(sameIdentityKey(standard, urlSafe), isTrue);
      final plan = planIdentityMigration(
          storePublicKey: standard, legacy: [_entry('a', urlSafe)]);
      expect(plan.remove.map((c) => c.localId), ['a']);
      expect(plan.conflicts, isEmpty);
    });
  });

  group('IdentityStoreStatus', () {
    test('parses the SDK status JSON', () {
      final status = IdentityStoreStatus.fromJson({
        'present': true,
        'backend': 'keychain',
        'unlocked': true,
        'public_key': _keyA,
        'dir': '/Users/me/Library/Application Support/LemonadeNexus/identity',
      });
      expect(status.present, isTrue);
      expect(status.backend, 'keychain');
      expect(status.keystoreAvailable, isTrue);
      expect(status.unlocked, isTrue);
      expect(status.publicKey, _keyA);
      expect(IdentityStoreStatus.fromJson(status.toJson()).toJson(), status.toJson());
    });

    test('missing fields fail closed', () {
      final status = IdentityStoreStatus.fromJson(const {});
      expect(status.present, isFalse);
      expect(status.backend, 'none');
      expect(status.keystoreAvailable, isFalse);
      expect(status.unlocked, isFalse);
      expect(status.publicKey, isNull);
      expect(status.dir, isEmpty);
    });

    test('describes each state', () {
      IdentityStoreStatus make({String backend = 'dpapi', bool present = false, bool unlocked = false}) =>
          IdentityStoreStatus(present: present, backend: backend, unlocked: unlocked, dir: 'd');
      expect(describeIdentityStore(make(backend: 'none')), contains('No usable OS keystore'));
      expect(describeIdentityStore(make()), 'No identity stored yet.');
      expect(describeIdentityStore(make(present: true, unlocked: true)), 'Stored and unlocked.');
      expect(describeIdentityStore(make(present: true)), contains('did not release'));
      expect(identityBackendLabel('keychain'), 'macOS Keychain');
      expect(identityBackendLabel('dpapi'), 'Windows DPAPI');
      expect(identityBackendLabel('libsecret'), contains('Secret Service'));
      expect(identityBackendLabel('none'), 'No keystore');
    });
  });

  group('explainIdentityStoreFailure', () {
    const status = IdentityStoreStatus(
        present: false, backend: 'keychain', unlocked: false, dir: '/home/me/identity');

    test('names the cause and never a fallback', () {
      expect(explainIdentityStoreFailure(LnError.unsupported), contains('No OS keystore'));
      expect(explainIdentityStoreFailure(LnError.auth), contains('locked'));
      expect(explainIdentityStoreFailure(LnError.rejected), contains('failed verification'));
      expect(explainIdentityStoreFailure(LnError.notFound), contains('No device identity'));
      expect(explainIdentityStoreFailure(LnError.internal, status: status),
          contains('/home/me/identity'));
      expect(explainIdentityStoreFailure(LnError.connect), contains('connect'));
      for (final error in LnError.values) {
        expect(explainIdentityStoreFailure(error).toLowerCase(), isNot(contains('plaintext')));
      }
    });
  });

  group('DeviceIdentityState', () {
    test('is ready only when loaded and unlocked', () {
      const unlocked = IdentityStoreStatus(present: true, backend: 'keychain', unlocked: true, dir: 'd');
      const locked = IdentityStoreStatus(present: true, backend: 'keychain', unlocked: false, dir: 'd');
      expect(DeviceIdentityState.unknown.ready, isFalse);
      expect(const DeviceIdentityState(status: unlocked).ready, isTrue);
      expect(const DeviceIdentityState(status: locked).ready, isFalse);
      expect(const DeviceIdentityState(status: unlocked, error: 'x').ready, isFalse);
      expect(const DeviceIdentityUnavailable('why').toString(), 'No device identity: why');
    });
  });
}
