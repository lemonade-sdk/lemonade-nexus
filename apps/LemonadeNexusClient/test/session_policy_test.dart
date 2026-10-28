// Unit tests for the pure session decisions in session_policy.dart and the
// persisted Tier 1 epoch floor. None of them needs the native SDK library.

import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:nexus_client/src/platform/settings_store.dart';
import 'package:nexus_client/src/sdk/sdk.dart';
import 'package:nexus_client/src/state/app_state.dart';
import 'package:nexus_client/src/state/session_policy.dart';

void main() {
  group('isAuthenticationRefusal', () {
    test('signs out only on an authentication refusal (HTTP 401/403)', () {
      expect(
          isAuthenticationRefusal(
              SdkException(LnError.auth, message: 'session refused')),
          isTrue);
      expect(
          isAuthenticationRefusal(
              SdkException(LnError.auth, message: 'passkey rejected')),
          isTrue);
    });

    test('keeps the account on connection failures and 5xx answers', () {
      expect(
          isAuthenticationRefusal(
              SdkException(LnError.connect, message: 'server unreachable')),
          isFalse);
      expect(
          isAuthenticationRefusal(
              SdkException(LnError.connect, message: 'HTTP 503')),
          isFalse);
      expect(
          isAuthenticationRefusal(
              SdkException(LnError.internal, message: 'GET /api/x failed')),
          isFalse);
      expect(
          isAuthenticationRefusal(SdkException(LnError.notFound)), isFalse);
      expect(
          isAuthenticationRefusal(SdkException(LnError.rejected)), isFalse);
    });

    test('keeps the account on the SDK Tier 1 errors', () {
      expect(
          isAuthenticationRefusal(SdkException(LnError.connect,
              message: 'no verified Tier 1 server is reachable')),
          isFalse);
      expect(
          isAuthenticationRefusal(SdkException(LnError.internal,
              message: "the session's server is no longer a verified Tier 1 "
                  'server: join again')),
          isFalse);
    });

    test('keeps the account on timeouts, socket and local errors', () {
      expect(isAuthenticationRefusal(TimeoutException('health')), isFalse);
      expect(
          isAuthenticationRefusal(const SocketException('connection refused')),
          isFalse);
      expect(isAuthenticationRefusal(StateError('re-join failed')), isFalse);
      expect(
          isAuthenticationRefusal(JsonParseException('{', 'unexpected end')),
          isFalse);
      expect(isAuthenticationRefusal('session refused'), isFalse);
    });
  });

  group('nextTier1MinEpoch', () {
    test('grows to the reported epoch', () {
      expect(nextTier1MinEpoch(0, 1), 1);
      expect(nextTier1MinEpoch(3, 7), 7);
      expect(nextTier1MinEpoch(3, 7.0), 7);
      expect(nextTier1MinEpoch(3, '8'), 8);
    });

    test('never shrinks', () {
      expect(nextTier1MinEpoch(7, 5), 7);
      expect(nextTier1MinEpoch(7, 7), 7);
      expect(nextTier1MinEpoch(7, 0), 7);
      expect(nextTier1MinEpoch(7, -1), 7);
    });

    test('keeps the stored floor on a missing or malformed value', () {
      expect(nextTier1MinEpoch(4, null), 4);
      expect(nextTier1MinEpoch(4, 'later'), 4);
      expect(nextTier1MinEpoch(4, <String, dynamic>{}), 4);
    });
  });

  group('SettingsStore', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    test('persists the Tier 1 epoch floor next to the network key', () async {
      final store = SettingsStore();
      await store.save(const Settings(genesisKey: 'R0VORVNJUw==', tier1MinEpoch: 9));
      final loaded = await store.load();
      expect(loaded.genesisKey, 'R0VORVNJUw==');
      expect(loaded.tier1MinEpoch, 9);
    });

    test('starts at epoch 0 when nothing is stored', () async {
      expect((await SettingsStore().load()).tier1MinEpoch, 0);
    });
  });

  group('machineDeviceName', () {
    test('uses the host name without the mDNS suffix', () {
      expect(machineDeviceName('Studio-Mac.local'), 'Studio-Mac');
      expect(machineDeviceName('studio-mac.LOCAL'), 'studio-mac');
      expect(machineDeviceName('build-box'), 'build-box');
      expect(machineDeviceName(' build-box. \n'), 'build-box');
    });

    test('keeps a host name that only looks like the suffix', () {
      expect(machineDeviceName('.local'), '.local');
      expect(machineDeviceName('local'), 'local');
    });

    test('cuts the name to 128 characters', () {
      final long = 'h' * 200;
      expect(machineDeviceName(long).length, maxDeviceNameLength);
      expect(machineDeviceName('${'h' * 128}.local').length, 128);
    });

    test('falls back when the machine has no usable name', () {
      expect(machineDeviceName(''), fallbackDeviceName);
      expect(machineDeviceName('   '), fallbackDeviceName);
      expect(machineDeviceName('...'), fallbackDeviceName);
    });
  });

  group('deviceNameToApply', () {
    const nodeId = '0123456789abcdef0123';

    test('replaces the server default with the machine name', () {
      expect(
          deviceNameToApply(
              currentHostname: 'endpoint-01234567',
              nodeId: nodeId,
              machineName: 'Studio-Mac'),
          'Studio-Mac');
      expect(serverDefaultDeviceName(nodeId), 'endpoint-01234567');
      expect(serverDefaultDeviceName('abc'), 'endpoint-abc');
    });

    test('names an endpoint that has no name', () {
      expect(
          deviceNameToApply(
              currentHostname: null, nodeId: nodeId, machineName: 'Studio-Mac'),
          'Studio-Mac');
      expect(
          deviceNameToApply(
              currentHostname: ' ', nodeId: nodeId, machineName: 'Studio-Mac'),
          'Studio-Mac');
    });

    test('keeps a name that was already set', () {
      expect(
          deviceNameToApply(
              currentHostname: 'Living room PC',
              nodeId: nodeId,
              machineName: 'Studio-Mac'),
          isNull);
      expect(
          deviceNameToApply(
              currentHostname: 'endpoint-ffffffff',
              nodeId: nodeId,
              machineName: 'Studio-Mac'),
          isNull,
          reason: 'another node\'s default is a deliberate name here');
    });

    test('does nothing when the machine name is already set', () {
      expect(
          deviceNameToApply(
              currentHostname: 'Studio-Mac',
              nodeId: nodeId,
              machineName: 'Studio-Mac'),
          isNull);
    });
  });
}
