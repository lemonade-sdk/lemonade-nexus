// resume() with a native library that predates ln_resume: the lookup finds
// no symbol, so the call is a no-op instead of an error. The test process
// itself stands in for such a library: it exports no ln_* symbol.

import 'dart:ffi' as ffi;

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

void main() {
  test('resume is a no-op when the native library lacks ln_resume', () {
    final ffiBindings = LemonadeNexusFfi.fromLibrary(ffi.DynamicLibrary.process());
    expect(ffiBindings.hasResume, isFalse);
    expect(ffiBindings.resume(ffi.nullptr), LnError.success);
  });

  test('suspend is a no-op when the native library lacks ln_suspend', () {
    final ffiBindings = LemonadeNexusFfi.fromLibrary(ffi.DynamicLibrary.process());
    expect(ffiBindings.hasSuspend, isFalse);
    expect(ffiBindings.suspend(ffi.nullptr), LnError.success);
  });

  test('MeshStatus reads tunnel_up and treats a missing field as false', () {
    final status = MeshStatus.fromJson({'is_up': true, 'tunnel_up': true});
    expect(status.tunnelUp, isTrue);
    expect(MeshStatus.fromJson({'is_up': true}).tunnelUp, isFalse);
    expect(MeshStatus.fromJson({'is_up': true, 'tunnel_up': true}).toJson()['tunnel_up'], isTrue);
  });
}
