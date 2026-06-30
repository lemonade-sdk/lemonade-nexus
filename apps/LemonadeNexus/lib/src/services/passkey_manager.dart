/// Dart side of the native passkey (WebAuthn / Secure Enclave) manager.
/// Talks to the macOS runner over the `io.lemonade-nexus/passkey` channel.

import 'dart:io';
import 'package:flutter/services.dart';

class PasskeyCredential {
  final String credentialId;
  final String publicKeyX; // hex
  final String publicKeyY; // hex
  const PasskeyCredential(this.credentialId, this.publicKeyX, this.publicKeyY);
}

class PasskeyAssertion {
  final String credentialId;
  final String authenticatorData; // base64url
  final String clientDataJson; // base64url
  final String signature; // base64url DER
  const PasskeyAssertion({
    required this.credentialId,
    required this.authenticatorData,
    required this.clientDataJson,
    required this.signature,
  });

  /// The `assertion` object the server's passkey auth endpoint expects.
  Map<String, dynamic> toAssertionJson() => {
        'credential_id': credentialId,
        'authenticator_data': authenticatorData,
        'client_data_json': clientDataJson,
        'signature': signature,
      };
}

class PasskeyManager {
  static const _channel = MethodChannel('io.lemonade-nexus/passkey');

  /// Passkeys are currently backed by the macOS Secure Enclave only.
  bool get isSupported => Platform.isMacOS;

  Future<bool> hasCredential() async {
    if (!isSupported) return false;
    return (await _channel.invokeMethod<bool>('hasCredential')) ?? false;
  }

  Future<String?> storedUserId() async {
    if (!isSupported) return null;
    return _channel.invokeMethod<String>('storedUserId');
  }

  Future<PasskeyCredential> generateCredential(String userId) async {
    final r = await _channel
        .invokeMapMethod<String, dynamic>('generateCredential', {'userId': userId});
    if (r == null) throw Exception('Passkey generation returned no credential');
    return PasskeyCredential(
        r['credentialId'] as String, r['publicKeyX'] as String, r['publicKeyY'] as String);
  }

  Future<PasskeyAssertion> signAssertion(String rpId) async {
    final r = await _channel
        .invokeMapMethod<String, dynamic>('signAssertion', {'rpId': rpId});
    if (r == null) throw Exception('Passkey assertion returned no data');
    return PasskeyAssertion(
      credentialId: r['credentialId'] as String,
      authenticatorData: r['authenticatorData'] as String,
      clientDataJson: r['clientDataJson'] as String,
      signature: r['signature'] as String,
    );
  }

  Future<void> deleteCredential() async {
    if (!isSupported) return;
    await _channel.invokeMethod('deleteCredential');
  }
}
