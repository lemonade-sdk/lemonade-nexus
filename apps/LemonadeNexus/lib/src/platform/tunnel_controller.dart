/// Platform-selected WireGuard tunnel control. On desktop where the SDK owns
/// the tunnel (Windows/Linux) it drives ln_tunnel_* directly; on macOS the
/// tunnel runs in a NetworkExtension and is controlled over a platform channel.

import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import '../sdk/sdk.dart';

abstract class TunnelController {
  Future<void> up(WgConfig config);
  Future<void> down();
  Future<TunnelStatus?> status();
}

TunnelController createTunnelController(LemonadeNexusSdk sdk) {
  if (Platform.isMacOS) return MacTunnelController();
  return SdkTunnelController(sdk);
}

/// In-process tunnel via the SDK (BoringTun runs inside the app).
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

/// macOS tunnel driven by a NEPacketTunnelProvider over a platform channel.
/// Status streaming and the native side land in WS6b; until then start/stop
/// surface a clear error and status reads as unknown.
class MacTunnelController implements TunnelController {
  static const _channel = MethodChannel('io.lemonade-nexus/tunnel');

  @override
  Future<void> up(WgConfig config) {
    return _channel.invokeMethod('start', {'config': jsonEncode(config.toJson())});
  }

  @override
  Future<void> down() => _channel.invokeMethod('stop');

  @override
  Future<TunnelStatus?> status() async => null;
}
