// Verifies the Dart FFI bindings load and call into the real native SDK shared
// library. Loads by absolute path from the repo build output; skipped if the
// library has not been built in this environment.

import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus/src/sdk/ffi_bindings.dart';

String _libLeaf() {
  if (Platform.isWindows) return 'lemonade_nexus_sdk.dll';
  if (Platform.isMacOS) return 'liblemonade_nexus_sdk.dylib';
  return 'liblemonade_nexus_sdk.so';
}

// flutter test runs with cwd = package root (apps/LemonadeNexus).
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
}
