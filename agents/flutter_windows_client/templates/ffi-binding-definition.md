# Template: FFI Binding Definition

## Description
Standard template for creating Dart FFI bindings for C SDK functions.

## Usage
Use this template when wrapping any C SDK function.

## Template Structure

```dart
// Native function typedef
typedef {NativeFunctionName} = {ReturnType} Function({NativeParameters});

// Dart function typedef
typedef {DartFunctionName} = {DartReturnType} Function({DartParameters});

// In the SDK class:
late final {DartFunctionName} _{functionName};

// In constructor:
_{functionName} = _lib
    .lookup<ffi.NativeFunction<{NativeFunctionName}>>('{c_function_name}')
    .asFunction<{DartFunctionName}}>();

// Public wrapper method:
{DartReturnType} {methodName}({parameters}) {
  // Implementation with proper memory management
}
```

## Complete Example

```dart
// lib/src/sdk/ffi_bindings.dart
import 'dart:ffi';
import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';

/// FFI binding for ln_health function
typedef LnHealthNative = Int32 Function(
  Pointer<Void> client,
  Pointer<Pointer<CChar>> outJson,
);

typedef LnHealth = int Function(
  Pointer<Void> client,
  Pointer<Pointer<CChar>> outJson,
);

/// FFI binding for ln_free function
typedef LnFreeNative = Void Function(Pointer<CChar>);
typedef LnFree = void Function(Pointer<CChar>);

// In LemonadeNexusSdk class:
class LemonadeNexusSdk {
  final ffi.DynamicLibrary _lib;

  late final LnHealth _health;
  late final LnFree _free;

  LemonadeNexusSdk(this._lib) {
    _health = _lib
        .lookup<ffi.NativeFunction<LnHealthNative>>('ln_health')
        .asFunction<LnHealth>();

    _free = _lib
        .lookup<ffi.NativeFunction<LnFreeNative>>('ln_free')
        .asFunction<LnFree>();
  }

  /// Health check - GET /api/health
  ///
  /// Returns JSON response with health status.
  /// Throws [LemonadeNexusException] on failure.
  Map<String, dynamic> health(Pointer<Void> client) {
    final jsonPtr = calloc<Pointer<CChar>>();
    try {
      final result = _health(client, jsonPtr);
      if (result != 0) {
        throw LemonadeNexusException('Health check failed: $result');
      }
      final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
      _free(jsonPtr.value);
      return jsonDecode(jsonString) as Map<String, dynamic>;
    } finally {
      calloc.free(jsonPtr);
    }
  }
}
```

## Memory Management Pattern

```dart
// For functions returning strings via out_json:
{ReturnType} {methodName}(Pointer<Void> client) {
  final jsonPtr = calloc<Pointer<CChar>>();
  try {
    final result = _nativeFunction(client, jsonPtr);
    if (result != 0) {
      throw LemonadeNexusException('Error: $result');
    }
    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _free(jsonPtr.value);  // Call ln_free, not calloc.free!
    return jsonDecode(jsonString);
  } finally {
    calloc.free(jsonPtr);  // Free the pointer itself
  }
}

// For functions taking string parameters:
{ReturnType} {methodName}(Pointer<Void> client, String param) {
  final paramPtr = param.toNativeUtf8();
  try {
    return _nativeFunction(client, paramPtr);
  } finally {
    calloc.free(paramPtr);
  }
}
```

## Error Handling Pattern

```dart
enum LnError {
  nullArg(-1),
  connect(-2),
  auth(-3),
  notFound(-4),
  rejected(-5),
  noIdentity(-6),
  internal(-99);

  final int code;
  const LnError(this.code);

  factory LnError.fromCode(int code) {
    return LnError.values.firstWhere(
      (e) => e.code == code,
      orElse: () => LnError.internal,
    );
  }
}

class LemonadeNexusException implements Exception {
  final String message;
  final LnError? error;

  LemonadeNexusException(this.message, {this.error});

  @override
  String toString() => 'LemonadeNexusException: $message';
}
```

## Related Templates
- SDK Wrapper Class Template
- Model Class Template
- Service Class Template

## Notes
- Always use try/finally for memory management
- Call ln_free for SDK-allocated strings
- Call calloc.free for dart:ffi allocated pointers
- Document error codes
- Include usage examples
