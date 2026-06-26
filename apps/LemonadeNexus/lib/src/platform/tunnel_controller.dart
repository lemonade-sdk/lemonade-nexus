/// Platform-selected tunnel control.
///
/// Two models exist:
///   - SdkTunnelController: the legacy system tunnel where the SDK owns a TUN
///     device (BoringTun + utun/wintun) via ln_tunnel_*. Used on Windows/Linux.
///   - PumpTunnelController: the userspace socket-proxy model (no TUN, no system
///     VPN, no entitlements) where the SDK joins the BoringTun dataplane to the
///     in-process netstack and exposes mesh connectivity as loopback sockets via
///     the ln_pump_* C API. This is the target model for macOS (and ultimately
///     all platforms); wiring it needs the ln_pump_* Dart FFI bindings.

import 'dart:io';

import '../sdk/sdk.dart';

abstract class TunnelController {
  Future<void> up(WgConfig config);
  Future<void> down();
  Future<TunnelStatus?> status();
}

TunnelController createTunnelController(LemonadeNexusSdk sdk) {
  if (Platform.isMacOS) return PumpTunnelController();
  return SdkTunnelController(sdk);
}

/// System tunnel via the SDK: BoringTun runs in-process and owns a TUN device.
class SdkTunnelController implements TunnelController {
  final LemonadeNexusSdk _sdk;
  SdkTunnelController(this._sdk);

  @override
  Future<void> up(WgConfig config) => _sdk.tunnelUp(config);

  @override
  Future<void> down() => _sdk.tunnelDown();

  @override
  Future<TunnelStatus?> status() async {
    try {
      return await _sdk.getTunnelStatus();
    } catch (_) {
      return null;
    }
  }
}

/// Userspace socket-proxy tunnel (ln_pump_* — netstack + BoringTun, no TUN).
/// The SDK capability exists and is verified; the Dart FFI bindings for
/// ln_pump_create / ln_pump_tcp_egress / ln_pump_tcp_forward / ln_pump_sync_peers
/// / ln_pump_status are the next step before this can drive the tunnel.
class PumpTunnelController implements TunnelController {
  @override
  Future<void> up(WgConfig config) async {
    throw UnimplementedError(
      'macOS socket-proxy tunnel pending ln_pump_* Dart FFI bindings',
    );
  }

  @override
  Future<void> down() async {}

  @override
  Future<TunnelStatus?> status() async => null;
}
