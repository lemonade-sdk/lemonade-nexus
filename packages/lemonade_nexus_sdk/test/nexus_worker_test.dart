// Runs NexusWorker against the real native SDK. Loads the desktop build by
// absolute path; skipped when the library has not been built here.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

String _libLeaf() {
  if (Platform.isWindows) return 'lemonade_nexus_sdk.dll';
  if (Platform.isMacOS) return 'liblemonade_nexus_sdk.dylib';
  return 'liblemonade_nexus_sdk.so';
}

// flutter test runs with cwd = package root (packages/lemonade_nexus_sdk).
File _libFile() => File('${Directory.current.path}/../../build/projects/'
    'LemonadeNexusSDK/${_libLeaf()}');

void main() {
  late NexusWorker worker;
  final lib = _libFile();

  setUp(() async {
    if (!lib.existsSync()) return;
    worker = await NexusWorker.spawn(libraryPath: lib.absolute.path);
  });

  tearDown(() async {
    if (!lib.existsSync()) return;
    await worker.close();
  });

  test('runs SDK calls on the worker and returns their results', () async {
    if (!lib.existsSync()) {
      markTestSkipped('SDK library not built at ${lib.path}');
      return;
    }
    final identity = await worker.run(_generateIdentity);
    expect(identity.pubkey, isNotEmpty);
    // The identity stays on the worker's SDK between calls: setIdentity
    // throws a StateError when none is loaded.
    await worker.run(_connectWithIdentity);
  });

  test('keeps submission order', () async {
    if (!lib.existsSync()) {
      markTestSkipped('SDK library not built at ${lib.path}');
      return;
    }
    final order = <int>[];
    await Future.wait([
      for (var i = 0; i < 5; i++) worker.run(_sleepThenReturn(i)).then(order.add),
    ]);
    expect(order, [0, 1, 2, 3, 4]);
  });

  test('passes SDK errors back to the caller', () async {
    if (!lib.existsSync()) {
      markTestSkipped('SDK library not built at ${lib.path}');
      return;
    }
    // Nothing listens on the discard port, so the health check fails.
    await expectLater(
      worker.run(_healthOfDiscardPort),
      throwsA(isA<SdkException>()
          .having((e) => e.error, 'error', LnError.connect)),
    );
  });
}

// Tasks are top-level functions: a closure written inside main() would carry
// main's variables (the worker itself) and could not be sent to the isolate.
Future<IdentityInfo> _generateIdentity(LemonadeNexusSdk sdk) =>
    sdk.generateIdentity();

Future<void> _connectWithIdentity(LemonadeNexusSdk sdk) async {
  await sdk.connect('127.0.0.1', 9);
  await sdk.setIdentity();
}

Future<HealthResponse> _healthOfDiscardPort(LemonadeNexusSdk sdk) async {
  await sdk.connect('127.0.0.1', 9);
  return sdk.health();
}

Future<int> Function(LemonadeNexusSdk) _sleepThenReturn(int i) => (sdk) async {
      await Future<void>.delayed(Duration(milliseconds: 20 - i * 4));
      return i;
    };
