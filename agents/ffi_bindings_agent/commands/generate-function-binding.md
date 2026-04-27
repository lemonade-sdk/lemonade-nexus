# Command: Generate Single Function Binding

## Description
Generate FFI binding for a single C SDK function.

## Purpose
Focused binding generation for individual functions.

## Input
- Function name (e.g., `ln_health`)
- C signature from header
- Memory patterns (out_json, string params)

## Process

### 1. Extract Function Signature
```c
ln_error_t ln_health(ln_client_t* client, char** out_json);
```

### 2. Create Native Typedef
```dart
typedef LnHealthNative = Int32 Function(Pointer<Void> client, Pointer<Pointer<CChar>> outJson);
```

### 3. Create Dart Typedef
```dart
typedef LnHealth = int Function(Pointer<Void> client, Pointer<Pointer<CChar>> outJson);
```

### 4. Add Field to SDK Class
```dart
late final LnHealth _health;
```

### 5. Add Lookup in Constructor
```dart
_health = _lib.lookup<ffi.NativeFunction<LnHealthNative>>('ln_health').asFunction();
```

### 6. Create Wrapper Method
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

## Memory Pattern Recognition

| Pattern | Handling |
|---------|----------|
| `char** out_json` | calloc jsonPtr, ln_free result, calloc.free pointer |
| `const char* param` | toNativeUtf8, calloc.free |
| `char* return` | ln_free after toDartString |
| Opaque handle* | Pointer<Void> |

## Output
- Single function binding
- Wrapper method
- Test case
