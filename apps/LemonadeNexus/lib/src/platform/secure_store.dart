/// Secure credential storage (Keychain on macOS, DPAPI-backed locker on Windows)
/// for the session token and the authenticated user's identity metadata. The
/// Ed25519 private key itself stays in the SDK's identity file (see AppPaths).

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class StoredSession {
  final String token;
  final String username;
  final String? userId;
  const StoredSession({required this.token, required this.username, this.userId});
}

class SecureStore {
  static const _storage = FlutterSecureStorage();
  static const _kToken = 'session_token';
  static const _kUsername = 'username';
  static const _kUserId = 'user_id';

  Future<void> saveSession(StoredSession session) async {
    await _storage.write(key: _kToken, value: session.token);
    await _storage.write(key: _kUsername, value: session.username);
    if (session.userId != null) {
      await _storage.write(key: _kUserId, value: session.userId);
    }
  }

  Future<StoredSession?> loadSession() async {
    final token = await _storage.read(key: _kToken);
    final username = await _storage.read(key: _kUsername);
    if (token == null || username == null) return null;
    return StoredSession(
      token: token,
      username: username,
      userId: await _storage.read(key: _kUserId),
    );
  }

  Future<void> clear() async {
    await _storage.delete(key: _kToken);
    await _storage.delete(key: _kUsername);
    await _storage.delete(key: _kUserId);
  }
}
