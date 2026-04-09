# Command: Add Error Handling

## Description
Add comprehensive error handling to FFI bindings.

## Purpose
Provide descriptive error messages and proper exception types.

## Error Code Mapping

```dart
enum LnErrorCode {
  ok(0),
  nullArg(-1),
  connect(-2),
  auth(-3),
  notFound(-4),
  rejected(-5),
  noIdentity(-6),
  internal(-99);

  final int code;
  const LnErrorCode(this.code);

  factory LnErrorCode.fromInt(int code) {
    return LnErrorCode.values.firstWhere(
      (e) => e.code == code,
      orElse: () => LnErrorCode.internal,
    );
  }

  String get message {
    switch (this) {
      case LnErrorCode.ok: return 'Success';
      case LnErrorCode.nullArg: return 'Null argument';
      case LnErrorCode.connect: return 'Connection failed';
      case LnErrorCode.auth: return 'Authentication failed';
      case LnErrorCode.notFound: return 'Resource not found';
      case LnErrorCode.rejected: return 'Request rejected';
      case LnErrorCode.noIdentity: return 'No identity attached';
      case LnErrorCode.internal: return 'Internal error';
    }
  }
}
```

## Exception Classes

```dart
/// Base exception for all SDK errors.
abstract class LemonadeException implements Exception {
  final String message;
  final Exception? cause;

  LemonadeException(this.message, {this.cause});

  @override
  String toString() => runtimeType.toString() + ': $message';
}

/// SDK-level error (from C error codes).
class SdkException extends LemonadeException {
  final LnErrorCode errorCode;

  SdkException(String message, {this.errorCode = LnErrorCode.internal, Exception? cause})
      : super(message, cause: cause);

  factory SdkException.fromCode(int code) {
    final errorCode = LnErrorCode.fromInt(code);
    return SdkException(errorCode.message, errorCode: errorCode);
  }
}

/// Category-specific exceptions.
class AuthException extends LemonadeException {
  AuthException(String message, {Exception? cause}) : super(message, cause: cause);
}

class TunnelException extends LemonadeException {
  TunnelException(String message, {Exception? cause}) : super(message, cause: cause);
}

class MeshException extends LemonadeException {
  MeshException(String message, {Exception? cause}) : super(message, cause: cause);
}

class IdentityException extends LemonadeException {
  IdentityException(String message, {Exception? cause}) : super(message, cause: cause);
}
```

## Error Handling Pattern

```dart
Map<String, dynamic> health(Pointer<Void> client) {
  final jsonPtr = calloc<Pointer<CChar>>();
  try {
    final result = _health(client, jsonPtr);
    if (result != 0) {
      throw SdkException.fromCode(result);
    }
    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _lnFree(jsonPtr.value);
    return jsonDecode(jsonString) as Map<String, dynamic>;
  } on SdkException {
    rethrow;  // Re-throw SDK exceptions as-is
  } catch (e) {
    throw SdkException('Health check failed: $e', cause: e as Exception?);
  } finally {
    calloc.free(jsonPtr);
  }
}
```

## Output
- Error code enum
- Exception hierarchy
- Error handling wrappers
- Descriptive messages
