/// @title Trust Store
/// @description Root certificates for the native SDK on iOS and Android.
///
/// The SDK verifies every TLS server with OpenSSL, which finds root
/// certificates through its default paths (`/etc/ssl`). Desktops have them;
/// iOS and Android do not, so every handshake failed there and the network
/// looked unreachable. On those platforms the plugin ships Mozilla's root
/// certificates (`assets/cacert.pem`, from https://curl.se/docs/caextract.html)
/// and points OpenSSL at a copy through `SSL_CERT_FILE`. OpenSSL reads the
/// variable whenever a client loads its default paths, so it covers every
/// client the SDK creates afterwards.
library;

import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart' show rootBundle;

const _asset = 'packages/lemonade_nexus_sdk/assets/cacert.pem';

Future<void>? _installed;

/// Installs the root certificates on iOS and Android; does nothing elsewhere.
/// Runs once per process and must finish before the SDK's first connection.
/// Call it on the root isolate (it reads a Flutter asset).
Future<void> ensureMobileTrustStore() =>
    _installed ??= (Platform.isIOS || Platform.isAndroid) ? _install() : Future.value();

Future<void> _install() async {
  final pem = await rootBundle.load(_asset);
  final file = File('${Directory.systemTemp.path}/lemonade_nexus_cacert.pem');
  await file.writeAsBytes(
      pem.buffer.asUint8List(pem.offsetInBytes, pem.lengthInBytes),
      flush: true);
  final libc = Platform.isAndroid
      ? ffi.DynamicLibrary.open('libc.so')
      : ffi.DynamicLibrary.process();
  final setenv = libc.lookupFunction<
      ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<Utf8>, ffi.Int32),
      int Function(ffi.Pointer<Utf8>, ffi.Pointer<Utf8>, int)>('setenv');
  final name = 'SSL_CERT_FILE'.toNativeUtf8();
  final value = file.path.toNativeUtf8();
  try {
    if (setenv(name, value, 1) != 0) {
      throw StateError('setenv(SSL_CERT_FILE) failed');
    }
  } finally {
    malloc.free(name);
    malloc.free(value);
  }
}
