# Template: Service Class

## Description
Standard template for creating service classes that wrap FFI SDK calls.

## Usage
Use this template when creating business logic services.

## Template Structure

```dart
// lib/src/services/{name}_service.dart
import '../sdk/sdk_wrapper.dart';
import '../models/{name}_model.dart';

/// {@template {name}Service}
/// Service for {description}.
///
/// Wraps FFI SDK calls with business logic and error handling.
/// {@endtemplate}
class {Name}Service {
  final LemonadeNexusSdk _sdk;
  final Pointer<Void> _client;

  {Name}Service(this._sdk, this._client);

  /// {methodDescription}
  ///
  /// Parameters:
  /// - {param}: {paramDescription}
  ///
  /// Returns: {returnDescription}
  ///
  /// Throws: [{ExceptionType}] on failure
  Future<{ReturnType}> {methodName}({parameters}) async {
    try {
      // FFI call
      final result = await _sdk.{ffiMethod}(_client, {params});
      return {ReturnType}.fromJson(result);
    } catch (e) {
      throw {Name}ServiceException('Failed to {methodName}: $e');
    }
  }
}

/// Exception class for {name} service errors
class {Name}ServiceException implements Exception {
  final String message;
  final Exception? originalException;

  {Name}ServiceException(this.message, {this.originalException});

  @override
  String toString() => '{Name}ServiceException: $message';
}
```

## Complete Example

```dart
// lib/src/services/auth_service.dart
import 'dart:convert';
import '../sdk/sdk_wrapper.dart';
import '../models/user_model.dart';

/// {@template AuthService}
/// Service for authentication operations.
///
/// Wraps C SDK authentication FFI calls with business logic.
/// {@endtemplate}
class AuthService {
  final LemonadeNexusSdk _sdk;
  final Pointer<Void> _client;
  User? _currentUser;
  String? _sessionToken;

  AuthService(this._sdk, this._client);

  /// Get current authenticated user
  User? get currentUser => _currentUser;

  /// Get session token
  String? get sessionToken => _sessionToken;

  /// Check if authenticated
  bool get isAuthenticated => _currentUser != null && _sessionToken != null;

  /// Authenticate with username/password
  ///
  /// Parameters:
  /// - username: User's username
  /// - password: User's password
  ///
  /// Returns: [User] object on success
  ///
  /// Throws: [AuthException] on failure
  Future<User> login(String username, String password) async {
    try {
      // Derive seed from credentials
      final seed = _sdk.identity.deriveSeed(username, password);
      final identity = _sdk.identity.createFromSeed(seed);

      // Attach identity to client
      final setResult = _sdk.client.setIdentity(_client, identity);
      if (setResult != 0) {
        throw AuthException('Failed to set identity: $setResult');
      }

      // Authenticate with challenge-response
      final authResult = await _sdk.auth.ed25519(_client);
      if (authResult['authenticated'] != true) {
        throw AuthException(authResult['error'] ?? 'Authentication failed');
      }

      // Extract user data and token
      _currentUser = User.fromJson(authResult['user']);
      _sessionToken = authResult['session_token'];

      // Set session token for future calls
      _sdk.client.setSessionToken(_client, _sessionToken!);

      return _currentUser!;
    } on LemonadeNexusException catch (e) {
      throw AuthException('SDK error: ${e.message}');
    } catch (e) {
      throw AuthException('Login failed: $e');
    }
  }

  /// Login with passkey
  ///
  /// Parameters:
  /// - passkeyJson: Passkey assertion JSON
  ///
  /// Returns: [User] object on success
  Future<User> loginWithPasskey(Map<String, dynamic> passkeyJson) async {
    try {
      final jsonString = jsonEncode(passkeyJson);
      final result = await _sdk.auth.passkey(_client, jsonString);

      if (result['authenticated'] != true) {
        throw AuthException(result['error'] ?? 'Passkey auth failed');
      }

      _currentUser = User.fromJson(result['user']);
      _sessionToken = result['session_token'];
      _sdk.client.setSessionToken(_client, _sessionToken!);

      return _currentUser!;
    } catch (e) {
      throw AuthException('Passkey login failed: $e');
    }
  }

  /// Logout current user
  ///
  /// Clears session and user data
  void logout() {
    _currentUser = null;
    _sessionToken = null;
  }

  /// Register new user with passkey
  ///
  /// Parameters:
  /// - userId: User ID
  /// - credentialId: Passkey credential ID
  /// - publicKeyX: Public key X coordinate
  /// - publicKeyY: Public key Y coordinate
  ///
  /// Returns: Registration result
  Future<Map<String, dynamic>> registerPasskey({
    required String userId,
    required String credentialId,
    required String publicKeyX,
    required String publicKeyY,
  }) async {
    try {
      final result = await _sdk.auth.registerPasskey(
        _client,
        userId,
        credentialId,
        publicKeyX,
        publicKeyY,
      );
      return result;
    } catch (e) {
      throw AuthException('Registration failed: $e');
    }
  }
}

/// Exception class for authentication errors
class AuthException implements Exception {
  final String message;
  final Exception? originalException;

  AuthException(this.message, {this.originalException});

  @override
  String toString() => 'AuthException: $message';
}
```

## Tunnel Service Example

```dart
// lib/src/services/tunnel_service.dart
import 'dart:convert';
import '../sdk/sdk_wrapper.dart';
import '../models/tunnel_model.dart';

/// {@template TunnelService}
/// Service for WireGuard tunnel management.
/// {@endtemplate}
class TunnelService {
  final LemonadeNexusSdk _sdk;
  final Pointer<Void> _client;
  TunnelConfig? _config;

  TunnelService(this._sdk, this._client);

  /// Get current tunnel status
  Future<TunnelStatus> getStatus() async {
    final result = await _sdk.tunnel.getStatus(_client);
    return TunnelStatus.fromJson(result);
  }

  /// Bring tunnel up with configuration
  Future<void> connect(TunnelConfig config) async {
    try {
      final configJson = jsonEncode(config.toJson());
      final result = await _sdk.tunnel.up(_client, configJson);

      if (result['success'] != true) {
        throw TunnelException(result['error'] ?? 'Failed to connect');
      }

      _config = config;
    } catch (e) {
      throw TunnelException('Connect failed: $e');
    }
  }

  /// Tear tunnel down
  Future<void> disconnect() async {
    try {
      final result = await _sdk.tunnel.down(_client);
      if (result['success'] != true) {
        throw TunnelException(result['error'] ?? 'Failed to disconnect');
      }
      _config = null;
    } catch (e) {
      throw TunnelException('Disconnect failed: $e');
    }
  }

  /// Get WireGuard config string
  Future<String> getConfigString() async {
    return _sdk.tunnel.getWgConfig(_client);
  }
}

class TunnelException implements Exception {
  final String message;
  TunnelException(this.message);
  @override
  String toString() => 'TunnelException: $message';
}
```

## Related Templates
- FFI Binding Template
- Model Class Template
- Provider/StateNotifier Template

## Notes
- Wrap FFI calls with business logic
- Include comprehensive error handling
- Document all methods
- Use typed exceptions
- Follow single responsibility principle
