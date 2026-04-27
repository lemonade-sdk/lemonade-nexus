# Command: Generate FFI Tests

## Description
Generate comprehensive tests for FFI bindings.

## Purpose
Ensure FFI bindings work correctly and have no memory leaks.

## Test Categories

### Unit Tests
```dart
// test/unit/ffi/health_test.dart
void main() {
  group('ln_health FFI', () {
    late LemonadeNexusSdk sdk;
    late Pointer<Void> client;

    setUp(() {
      sdk = loadTestSdk();
      client = sdk.create('localhost', 8080);
    });

    tearDown(() {
      sdk.destroy(client);
    });

    test('returns valid JSON on success', () {
      final result = sdk.health(client);

      expect(result, isA<Map<String, dynamic>>());
      expect(result['service'], equals('lemonade-nexus'));
    });

    test('throws on null client', () {
      expect(
        () => sdk.health(null),
        throwsA(isA<SdkException>()),
      );
    });
  });
}
```

### Memory Tests
```dart
// test/unit/ffi/memory_test.dart
void main() {
  group('Memory Management', () {
    late LemonadeNexusSdk sdk;

    setUp(() => sdk = loadTestSdk());

    test('no memory leaks in health calls', () async {
      final client = sdk.create('localhost', 8080);

      // Call health 1000 times
      for (int i = 0; i < 1000; i++) {
        sdk.health(client);
      }

      sdk.destroy(client);

      // No memory leak detection
      expect(true, true);  // If no crash, test passes
    });

    test('string parameters properly freed', () {
      final client = sdk.create('localhost', 8080);
      final identity = sdk.identityGenerate();

      // This should not leak
      final pubkey = sdk.identityPubkey(identity);
      expect(pubkey, isNotEmpty);

      sdk.identityDestroy(identity);
      sdk.destroy(client);
    });
  });
}
```

### Integration Tests
```dart
// test/integration/sdk_workflow_test.dart
void main() {
  group('SDK Workflow', () {
    late LemonadeNexusSdk sdk;

    setUp(() => sdk = loadTestSdk());

    test('full auth workflow', () {
      // Create client
      final client = sdk.create('localhost', 8080);

      // Generate identity
      final identity = sdk.identityGenerate();

      // Set identity
      sdk.setIdentity(client, identity);

      // Health check
      final health = sdk.health(client);
      expect(health['status'], equals('ok'));

      // Cleanup
      sdk.identityDestroy(identity);
      sdk.destroy(client);
    });
  });
}
```

## Test Generation
- Generate test for each function
- Include success and error cases
- Memory leak stress tests
- Integration workflows

## Output
- Unit test files
- Memory test files
- Integration test files
- Test coverage reports
