# Command: Create SDK Wrapper Class

## Description
Create idiomatic Dart wrapper classes on top of raw FFI bindings.

## Purpose
Provide clean, type-safe Dart API that hides FFI complexity.

## Wrapper Class Structure

```dart
/// Wrapper for identity management operations.
class IdentityService {
  final LemonadeNexusSdk _sdk;
  final Pointer<Void> _client;

  IdentityService(this._sdk, this._client);

  /// Generate a new Ed25519 identity.
  Identity generate() {
    final ptr = _sdk.ln_identity_generate();
    return Identity._(ptr, _sdk);
  }

  /// Load identity from file.
  Identity load(String path) {
    final pathPtr = path.toNativeUtf8();
    try {
      final ptr = _sdk.ln_identity_load(pathPtr);
      return Identity._(ptr, _sdk);
    } finally {
      calloc.free(pathPtr);
    }
  }

  /// Get public key string.
  String getPublicKey(Identity identity) {
    final pubKeyPtr = _sdk.ln_identity_pubkey(identity._ptr);
    try {
      return pubKeyPtr.cast<Utf8>().toDartString();
    } finally {
      _sdk.ln_free(pubKeyPtr);
    }
  }
}
```

## Service Categories

| Service | Functions |
|---------|-----------|
| `ClientService` | Create, destroy, health |
| `IdentityService` | Generate, load, save, pubkey |
| `AuthService` | Password, passkey, token, Ed25519 |
| `TunnelService` | Up, down, status, config |
| `MeshService` | Enable, disable, status, peers |
| `TreeService` | Get, create, update, delete |
| `GroupService` | Add, remove, get members |
| `CertService` | Status, request, decrypt |

## Output
- Service class per category
- Type-safe methods
- Proper memory management
- Exception handling
