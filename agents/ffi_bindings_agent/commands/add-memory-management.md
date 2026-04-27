# Command: Add Memory Management

## Description
Add proper memory management patterns to FFI bindings.

## Purpose
Prevent memory leaks and ensure proper resource cleanup.

## Memory Patterns

### Pattern 1: out_json Parameter
```dart
Map<String, dynamic> health(Pointer<Void> client) {
  final jsonPtr = calloc<Pointer<CChar>>();  // Allocate pointer
  try {
    final result = _health(client, jsonPtr);
    if (result != 0) throw SdkException('Error: $result');

    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _lnFree(jsonPtr.value);  // Free SDK-allocated memory

    return jsonDecode(jsonString) as Map<String, dynamic>;
  } finally {
    calloc.free(jsonPtr);  // Free Dart-allocated pointer
  }
}
```

### Pattern 2: String Parameter
```dart
int setIdentity(Pointer<Void> client, Pointer<Void> identity, String path) {
  final pathPtr = path.toNativeUtf8();  // Allocate
  try {
    return _setIdentity(client, identity, pathPtr);
  } finally {
    calloc.free(pathPtr);  // Free
  }
}
```

### Pattern 3: Return String
```dart
String getPublicKey(Pointer<Void> identity) {
  final pubKeyPtr = _ln_identity_pubkey(identity);
  if (pubKeyPtr == nullptr) {
    throw SdkException('Failed to get public key');
  }
  try {
    return pubKeyPtr.cast<Utf8>().toDartString();
  } finally {
    _lnFree(pubKeyPtr);  // SDK-allocated
  }
}
```

### Pattern 4: Multiple Allocations
```dart
Future<Map<String, dynamic>> submitDelta(Pointer<Void> client, String deltaJson) {
  final deltaPtr = deltaJson.toNativeUtf8();
  final jsonPtr = calloc<Pointer<CChar>>();

  try {
    final result = _ln_tree_submit_delta(client, deltaPtr, jsonPtr);
    if (result != 0) throw SdkException('Error: $result');

    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _lnFree(jsonPtr.value);

    return jsonDecode(jsonString) as Map<String, dynamic>;
  } finally {
    calloc.free(deltaPtr);
    calloc.free(jsonPtr);
  }
}
```

## Checklist
- [ ] All calloc allocations freed
- [ ] All SDK allocations freed with ln_free
- [ ] try/finally blocks in place
- [ ] No early returns without cleanup
- [ ] No memory leaks in testing

## Output
- Memory-safe FFI methods
- No memory leaks
- Clean resource management
