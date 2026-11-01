/// @title Mesh Port Models
/// @description Typed view of the ln_mesh_port_status JSON.
library;

import 'package:flutter/foundation.dart' show listEquals;

/// One device URL served by the mesh port.
class MeshPortUrl {
  final String nodeId;
  final String deviceName;
  final String url;
  final bool isSelf;

  const MeshPortUrl({
    required this.nodeId,
    required this.deviceName,
    required this.url,
    required this.isSelf,
  });

  factory MeshPortUrl.fromJson(Map<String, dynamic> json) => MeshPortUrl(
        nodeId: json['node_id'] as String? ?? '',
        deviceName: json['device_name'] as String? ?? '',
        url: json['url'] as String? ?? '',
        isSelf: json['self'] as bool? ?? false,
      );

  @override
  bool operator ==(Object other) =>
      other is MeshPortUrl &&
      other.nodeId == nodeId &&
      other.deviceName == deviceName &&
      other.url == url &&
      other.isSelf == isSelf;

  @override
  int get hashCode => Object.hash(nodeId, deviceName, url, isSelf);
}

/// A Tier 3 device that can be selected.
class MeshPortDevice {
  final String nodeId;
  final String deviceName;
  final bool isOnline;

  const MeshPortDevice({
    required this.nodeId,
    required this.deviceName,
    required this.isOnline,
  });

  factory MeshPortDevice.fromJson(Map<String, dynamic> json) => MeshPortDevice(
        nodeId: json['node_id'] as String? ?? '',
        deviceName: json['device_name'] as String? ?? '',
        isOnline: json['is_online'] as bool? ?? false,
      );

  /// The device name, or the node ID when the device has no name.
  String get label => deviceName.isEmpty ? nodeId : deviceName;

  @override
  bool operator ==(Object other) =>
      other is MeshPortDevice &&
      other.nodeId == nodeId &&
      other.deviceName == deviceName &&
      other.isOnline == isOnline;

  @override
  int get hashCode => Object.hash(nodeId, deviceName, isOnline);
}

/// State of the loopback mesh port.
class MeshPortStatus {
  final bool running;
  final int port;
  final String scheme;
  final bool localService;
  final String error;

  /// null, "local", "auto" or a node ID.
  final String? selection;
  final bool peerKeySet;

  /// "off", "waiting", "activating" (the certificate is installed and TLS starts
  /// when the open plain requests finish), "active", "unsupported_certificate" or
  /// "error".
  final String tlsState;
  final String tlsDomain;
  final String tlsError;
  final int tlsExpiresAt;
  final List<MeshPortUrl> urls;
  final List<MeshPortDevice> devices;

  const MeshPortStatus({
    this.running = false,
    this.port = 0,
    this.scheme = 'http',
    this.localService = false,
    this.error = '',
    this.selection,
    this.peerKeySet = false,
    this.tlsState = 'off',
    this.tlsDomain = '',
    this.tlsError = '',
    this.tlsExpiresAt = 0,
    this.urls = const [],
    this.devices = const [],
  });

  static const stopped = MeshPortStatus();

  factory MeshPortStatus.fromJson(Map<String, dynamic> json) {
    final selection = json['selection'] as Map<String, dynamic>? ?? const {};
    final tls = json['tls'] as Map<String, dynamic>? ?? const {};
    List<T> list<T>(String key, T Function(Map<String, dynamic>) parse) =>
        (json[key] as List<dynamic>? ?? const [])
            .whereType<Map<String, dynamic>>()
            .map(parse)
            .toList();
    return MeshPortStatus(
      running: json['running'] as bool? ?? false,
      port: (json['port'] as num?)?.toInt() ?? 0,
      scheme: json['scheme'] as String? ?? 'http',
      localService: json['local_service'] as bool? ?? false,
      error: json['error'] as String? ?? '',
      selection: selection['target'] as String?,
      peerKeySet: selection['peer_key_set'] as bool? ?? false,
      tlsState: tls['state'] as String? ?? 'off',
      tlsDomain: tls['domain'] as String? ?? '',
      tlsError: tls['error'] as String? ?? '',
      tlsExpiresAt: (tls['expires_at'] as num?)?.toInt() ?? 0,
      urls: list('urls', MeshPortUrl.fromJson),
      devices: list('devices', MeshPortDevice.fromJson),
    );
  }

  bool get tlsActive => tlsState == 'active';

  /// Equal when every field is: a poll that read the same state compares
  /// equal, so a caller can skip it.
  @override
  bool operator ==(Object other) =>
      other is MeshPortStatus &&
      other.running == running &&
      other.port == port &&
      other.scheme == scheme &&
      other.localService == localService &&
      other.error == error &&
      other.selection == selection &&
      other.peerKeySet == peerKeySet &&
      other.tlsState == tlsState &&
      other.tlsDomain == tlsDomain &&
      other.tlsError == tlsError &&
      other.tlsExpiresAt == tlsExpiresAt &&
      listEquals(other.urls, urls) &&
      listEquals(other.devices, devices);

  @override
  int get hashCode => Object.hash(running, port, scheme, localService, error, selection,
      peerKeySet, tlsState, tlsDomain, tlsError, tlsExpiresAt, Object.hashAll(urls),
      Object.hashAll(devices));
}
