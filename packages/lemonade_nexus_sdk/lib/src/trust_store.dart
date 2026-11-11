/// @title Trust Store
/// @description Root certificates for the native SDK on iOS and Android.
///
/// The SDK verifies every TLS server with OpenSSL, which finds root
/// certificates through its default paths (`/etc/ssl`). Desktops have them;
/// iOS and Android do not, so every handshake failed there and the network
/// looked unreachable. On those platforms the plugin ships Mozilla's root
/// certificates (`assets/cacert.pem`, from https://curl.se/docs/caextract.html)
/// and writes a copy for the SDK. The copy reaches OpenSSL two ways:
///
/// - `SSL_CERT_FILE`, which OpenSSL reads whenever a client loads its default
///   paths. It works on iOS. An Android app process runs with `AT_SECURE`
///   set, so OpenSSL treats it as set-uid and ignores the variable; every
///   handshake failed with "SSL server verification failed".
/// - The path handed to the SDK (`ln_set_ca_bundle_path`, through the
///   `caBundlePath` of `LemonadeNexusSdk`), which works on both platforms.
///   [ensureMobileTrustStore] returns it for that call.
library;

import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart' show rootBundle;

const _asset = 'packages/lemonade_nexus_sdk/assets/cacert.pem';

Future<String?>? _installed;

/// Installs the root certificates on iOS and Android and returns the path of
/// the bundle, for the `caBundlePath` of `LemonadeNexusSdk`; null elsewhere.
/// Runs once per process and must finish before the SDK's first connection.
/// Call it on the root isolate (it reads a Flutter asset).
Future<String?> ensureMobileTrustStore() =>
    _installed ??= (Platform.isIOS || Platform.isAndroid) ? _install() : Future.value();

Future<String?> _install() async {
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
  return file.path;
}
