# Command: Generate All FFI Bindings

## Description
Generate complete FFI bindings for all ~60 C SDK functions.

## Purpose
Create the foundational FFI layer that all other components depend on.

## Steps

### 1. Parse C SDK Header
- Read `lemonade_nexus.h`
- Extract all function declarations
- Categorize by functionality
- Identify memory patterns

### 2. Generate Native Typedefs
```dart
typedef LnCreateNative = Pointer<Void> Function(Pointer<Utf8> host, Uint16 port);
typedef LnDestroyNative = Void Function(Pointer<Void> client);
typedef LnHealthNative = Int32 Function(Pointer<Void> client, Pointer<Pointer<CChar>> outJson);
// ... for all ~60 functions
```

### 3. Generate Dart Typedefs
```dart
typedef LnCreate = Pointer<Void> Function(Pointer<Utf8> host, int port);
typedef LnDestroy = void Function(Pointer<Void> client);
typedef LnHealth = int Function(Pointer<Void> client, Pointer<Pointer<CChar>> outJson);
```

### 4. Create SDK Class
```dart
class LemonadeNexusSdk {
  final ffi.DynamicLibrary _lib;
  late final LnFree _lnFree;

  // All function bindings as late final fields

  LemonadeNexusSdk(this._lib) {
    _lnFree = _lib.lookup<ffi.NativeFunction<LnFreeNative>>('ln_free').asFunction();
    // ... lookup all functions
  }
}
```

### 5. Add Wrapper Methods
```dart
Map<String, dynamic> health(Pointer<Void> client) {
  final jsonPtr = calloc<Pointer<CChar>>();
  try {
    final result = _health(client, jsonPtr);
    if (result != 0) throw SdkException('Error: $result');
    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _lnFree(jsonPtr.value);
    return jsonDecode(jsonString) as Map<String, dynamic>;
  } finally {
    calloc.free(jsonPtr);
  }
}
```

## Output Files
- `lib/src/sdk/ffi_bindings.dart`
- `lib/src/sdk/sdk_wrapper.dart`
- `lib/src/sdk/types.dart`

## Success Criteria
- All 60+ functions wrapped
- Compiles without errors
- Memory management correct
- Tests pass
