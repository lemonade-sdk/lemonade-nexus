// Verifies the Dart FFI bindings load and call into the real native SDK shared
// library. Loads by absolute path from the repo build output; skipped if the
// library has not been built in this environment.

import 'dart:convert';
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

  test('packet pump: create and open a socket-proxy egress', () {
    final lib = _libFile();
    if (!lib.existsSync()) {
      markTestSkipped('SDK library not built at ${lib.path}');
      return;
    }
    final sdk = LemonadeNexusFfi(libraryPath: lib.absolute.path);
    final kp = jsonDecode(sdk.wgGenerateKeypair()!) as Map<String, dynamic>;
    final server = jsonDecode(sdk.wgGenerateKeypair()!) as Map<String, dynamic>;
    final config = jsonEncode({
      'private_key': kp['private_key'],
      'public_key': kp['public_key'],
      'server_public_key': server['public_key'],
      'server_endpoint': '',
      'tunnel_ip': '10.64.0.5/32',
      'allowed_ips': ['10.64.0.0/10'],
      'listen_port': 0,
    });

    final pump = sdk.pumpCreate(config);
    expect(pump, isNot(ffi.nullptr));
    // An egress listener binds a real loopback port regardless of handshake.
    final port = sdk.pumpTcpEgress(pump, '10.64.0.1', 9999);
    expect(port, greaterThan(0));
    sdk.pumpDestroy(pump);
  });
}
