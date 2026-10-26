// Verifies the Dart FFI bindings load and call into the real native SDK shared
// library. Loads by absolute path from the repo build output; skipped if the
// library has not been built in this environment.

import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/ffi_bindings.dart';

String _libLeaf() {
  if (Platform.isWindows) return 'lemonade_nexus_sdk.dll';
  if (Platform.isMacOS) return 'liblemonade_nexus_sdk.dylib';
  return 'liblemonade_nexus_sdk.so';
}

// flutter test runs with cwd = package root (apps/LemonadeNexusClient).
File _libFile() => File('${Directory.current.path}/../../build/projects/'
    'LemonadeNexusSDK/${_libLeaf()}');

void main() {
  test('loads native SDK, creates and destroys a client', () {
    final lib = _libFile();
    if (!lib.existsSync()) {
      markTestSkipped('SDK library not built at ${lib.path}');
      return;
    }
    final sdk = LemonadeNexusFfi(libraryPath: lib.absolute.path);
    final client = sdk.create('127.0.0.1', 9100);
    expect(client, isNot(ffi.nullptr));
    sdk.destroy(client);
  });

  test('pins the network key and reports no Tier 1 server before a refresh', () {
    final lib = _libFile();
    if (!lib.existsSync()) {
      markTestSkipped('SDK library not built at ${lib.path}');
      return;
    }
    final sdk = LemonadeNexusFfi(libraryPath: lib.absolute.path);
    expect(sdk.missingSymbols(), isEmpty);
    final client = sdk.createTls('127.0.0.1', 1);
    expect(client, isNot(ffi.nullptr));
    try {
      expect(sdk.setGenesisKey(client, 'not-a-key'), LnError.rejected);
      // 32 zero bytes: a well-formed key.
      expect(sdk.setGenesisKey(client, 'A' * 43 + '='), LnError.success);
      final (error, json) = sdk.tier1Membership(client);
      expect(error, LnError.success);
      expect(json, contains('"servers":[]'));
      // Discovery never replaces a pinned key.
      final (discoverError, discoverJson) = sdk.discoverGenesisKey(client, null);
      expect(discoverError, LnError.rejected);
      expect(discoverJson, contains('already pinned'));
    } finally {
      sdk.destroy(client);
    }
  });

  test('mesh port calls resolve and report a stopped port', () {
    final lib = _libFile();
    if (!lib.existsSync()) {
      markTestSkipped('SDK library not built at ${lib.path}');
      return;
    }
    final sdk = LemonadeNexusFfi(libraryPath: lib.absolute.path);
    final client = sdk.create('127.0.0.1', 9100);
    try {
      final status = jsonDecode(sdk.meshPortStatus(client)!) as Map<String, dynamic>;
      expect(status['running'], isFalse);
      expect(sdk.meshPortSetSelection(client, 'auto', null), LnError.rejected);
      expect(sdk.meshPortStart(client, 0, 'http://192.0.2.1:80'), LnError.rejected);
      expect(sdk.meshPortStop(client), LnError.success);
    } finally {
      sdk.destroy(client);
    }
  });
}
