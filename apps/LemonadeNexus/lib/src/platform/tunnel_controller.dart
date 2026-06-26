/// Platform-selected tunnel control.
///
/// Two models exist:
///   - SdkTunnelController: the legacy system tunnel where the SDK owns a TUN
///     device (BoringTun + utun/wintun) via ln_tunnel_*. Used on Windows/Linux.
///   - PumpTunnelController: the userspace socket-proxy model (no TUN, no system
///     VPN, no entitlements) where the SDK joins the BoringTun dataplane to the
///     in-process netstack and exposes mesh connectivity as loopback sockets via
///     the ln_pump_* API. Used on macOS.

import 'dart:convert';
import 'dart:ffi' as ffi;
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

/// Userspace socket-proxy tunnel (ln_pump_*): netstack + BoringTun, no TUN.
/// Connectivity is exposed as loopback sockets via [tcpEgress] / [tcpForward];
/// mesh peers are pushed in via [syncPeers].
class PumpTunnelController implements TunnelController {
  final LemonadeNexusFfi _ffi = LemonadeNexusFfi();
  ffi.Pointer<ffi.Void>? _pump;
  String? _tunnelIp;

  bool get isUp => _pump != null;

  @override
  Future<void> up(WgConfig config) async {
    if (_pump != null) return;
    final handle = _ffi.pumpCreate(jsonEncode(config.toJson()));
    if (handle == ffi.nullptr) {
      throw StateError('ln_pump_create failed');
    }
    _pump = handle;
    _tunnelIp = config.tunnelIp;
  }

  @override
  Future<void> down() async {
    final p = _pump;
    if (p != null) {
      _ffi.pumpDestroy(p);
      _pump = null;
      _tunnelIp = null;
    }
  }

  @override
  Future<TunnelStatus?> status() async {
    if (_pump == null) return null;
    return TunnelStatus(isUp: true, tunnelIp: _tunnelIp);
  }

  /// Open an egress proxy to a mesh endpoint; returns the local 127.0.0.1 port
  /// (0 if not up / failed). Connect a normal socket there to reach dst:port.
  int tcpEgress(String dstIp, int dstPort) {
    final p = _pump;
    return p == null ? 0 : _ffi.pumpTcpEgress(p, dstIp, dstPort);
  }

  /// Expose a local service to the mesh at vip:vport.
  LnError tcpForward(String vip, int vport, String target) {
    final p = _pump;
    return p == null ? LnError.internal : _ffi.pumpTcpForward(p, vip, vport, target);
  }

  /// Push the current mesh peer set (ln_mesh_peers JSON) into the pump.
  LnError syncPeers(String peersJson) {
    final p = _pump;
    return p == null ? LnError.internal : _ffi.pumpSyncPeers(p, peersJson);
  }
}
