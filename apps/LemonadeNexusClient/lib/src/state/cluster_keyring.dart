/// @title Cluster Keyring
/// @description Local store of the Clusters (accounts) this install can connect
/// to. A Cluster is a Customer group node; each membership is a device Ed25519
/// identity (kept as its 32-byte seed) plus the Cluster's group key. There are
/// no passwords — secrets live in the OS secure store (Keychain / DPAPI). The
/// login page renders this keyring: one card per Cluster (Connect), plus
/// Register (new Cluster) and Join (invite code).
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// One Cluster (account) this device can connect to.
class ClusterEntry {
  /// Customer group node id. Empty until the first join assigns it — matched by
  /// [localId] in the meantime.
  final String clusterId;

  /// Stable local key for list identity / dedupe before [clusterId] is known.
  final String localId;

  /// Cluster display name (the old "username").
  final String name;

  /// 'owner' (created this Cluster) or 'member' (linked in via an invite).
  final String role;

  /// 32-byte Ed25519 identity seed for this device's membership (secret).
  final String seedB64;

  /// The Cluster group key (secret); null until provisioned to this device.
  final String? groupKeyB64;

  /// This device's user_id under the Cluster (server-assigned).
  final String? userId;

  final String serverHost;
  final int serverPort;
  final bool useTls;
  final DateTime? lastUsed;

  const ClusterEntry({
    required this.localId,
    required this.name,
    required this.role,
    required this.seedB64,
    required this.serverHost,
    required this.serverPort,
    this.clusterId = '',
    this.useTls = false,
    this.groupKeyB64,
    this.userId,
    this.lastUsed,
  });

  bool get isOwner => role == 'owner';
  bool get hasGroupKey => groupKeyB64 != null && groupKeyB64!.isNotEmpty;

  ClusterEntry copyWith({
    String? clusterId,
    String? name,
    String? role,
    String? seedB64,
    String? groupKeyB64,
    String? userId,
    String? serverHost,
    int? serverPort,
    bool? useTls,
    DateTime? lastUsed,
  }) {
    return ClusterEntry(
      localId: localId,
      clusterId: clusterId ?? this.clusterId,
      name: name ?? this.name,
      role: role ?? this.role,
      seedB64: seedB64 ?? this.seedB64,
      groupKeyB64: groupKeyB64 ?? this.groupKeyB64,
      userId: userId ?? this.userId,
      serverHost: serverHost ?? this.serverHost,
      serverPort: serverPort ?? this.serverPort,
      useTls: useTls ?? this.useTls,
      lastUsed: lastUsed ?? this.lastUsed,
    );
  }

  Map<String, dynamic> toJson() => {
        'local_id': localId,
        'cluster_id': clusterId,
        'name': name,
        'role': role,
        'seed': seedB64,
        if (groupKeyB64 != null) 'group_key': groupKeyB64,
        if (userId != null) 'user_id': userId,
        'server_host': serverHost,
        'server_port': serverPort,
        'use_tls': useTls,
        if (lastUsed != null) 'last_used': lastUsed!.toIso8601String(),
      };

  factory ClusterEntry.fromJson(Map<String, dynamic> j) => ClusterEntry(
        localId: j['local_id'] as String,
        clusterId: (j['cluster_id'] as String?) ?? '',
        name: j['name'] as String? ?? 'Cluster',
        role: j['role'] as String? ?? 'member',
        seedB64: j['seed'] as String,
        groupKeyB64: j['group_key'] as String?,
        userId: j['user_id'] as String?,
        serverHost: j['server_host'] as String? ?? '',
        serverPort: j['server_port'] as int? ?? 0,
        useTls: j['use_tls'] as bool? ?? false,
        lastUsed: (j['last_used'] as String?) != null
            ? DateTime.tryParse(j['last_used'] as String)
            : null,
      );
}

/// A device (Endpoint node) in a Cluster, as reported by the server.
class ClusterDevice {
  final String nodeId;
  final String hostname;
  final String? tunnelIp;

  /// True while this device has no group-key envelope — it cannot read Cluster
  /// data until an owner device seals the key to it.
  final bool needsKey;

  /// True for the device we're running on.
  final bool isThisDevice;

  const ClusterDevice({
    required this.nodeId,
    required this.hostname,
    required this.needsKey,
    required this.isThisDevice,
    this.tunnelIp,
  });
}

/// Persists the Clusters this install can reach as a single JSON blob in the OS
/// secure store. All operations are best-effort — a keystore failure must not
/// crash the app; it just behaves as if the keyring were empty.
class ClusterKeyring {
  static const FlutterSecureStorage _storage = FlutterSecureStorage();
  static const String _key = 'cluster_keyring';

  Future<List<ClusterEntry>> load() async {
    try {
      final raw = await _storage.read(key: _key);
      if (raw == null || raw.isEmpty) return [];
      final list = (jsonDecode(raw) as List).cast<Map<String, dynamic>>();
      final entries = list.map(ClusterEntry.fromJson).toList();
      entries.sort((a, b) => (b.lastUsed ?? DateTime(0)).compareTo(a.lastUsed ?? DateTime(0)));
      return entries;
    } catch (e) {
      debugPrint('[ClusterKeyring] load failed (non-fatal): $e');
      return [];
    }
  }

  Future<void> _save(List<ClusterEntry> entries) async {
    try {
      await _storage.write(
          key: _key, value: jsonEncode(entries.map((e) => e.toJson()).toList()));
    } catch (e) {
      debugPrint('[ClusterKeyring] save failed (non-fatal): $e');
    }
  }

  /// Insert or update a Cluster (matched by [localId]); returns the full list.
  Future<List<ClusterEntry>> upsert(ClusterEntry entry) async {
    final entries = await load();
    final i = entries.indexWhere((e) => e.localId == entry.localId);
    if (i >= 0) {
      entries[i] = entry;
    } else {
      entries.add(entry);
    }
    await _save(entries);
    return load();
  }

  Future<List<ClusterEntry>> remove(String localId) async {
    final entries = await load();
    entries.removeWhere((e) => e.localId == localId);
    await _save(entries);
    return entries;
  }

  Future<void> clear() async {
    try {
      await _storage.delete(key: _key);
    } catch (e) {
      debugPrint('[ClusterKeyring] clear failed (non-fatal): $e');
    }
  }
}
