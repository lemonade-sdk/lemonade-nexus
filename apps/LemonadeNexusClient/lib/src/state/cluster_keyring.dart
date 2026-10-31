/// @title Cluster Keyring
/// @description Local store of the Clusters (accounts) this install can connect
/// to. A Cluster is a Customer group node; each membership is held by this
/// device's Ed25519 identity plus the Cluster's group key. There are no
/// passwords. The device identity is one per OS user and lives in the SDK's
/// per-user identity store (see `device_identity.dart`); this keyring keeps the
/// group keys and membership metadata in the OS secure store (Keychain /
/// DPAPI). The login page renders this keyring: one card per Cluster
/// (Connect), plus Register (new Cluster) and Join (invite code).
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

  /// A 32-byte Ed25519 seed from before the per-user identity store (secret).
  /// Null once the seed has moved into the store. It stays only on an entry
  /// whose key differs from the stored identity; such an entry is reported
  /// and cannot connect.
  final String? legacySeedB64;

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
    required this.serverHost,
    required this.serverPort,
    this.clusterId = '',
    this.useTls = false,
    this.legacySeedB64,
    this.groupKeyB64,
    this.userId,
    this.lastUsed,
  });

  bool get isOwner => role == 'owner';
  bool get hasGroupKey => groupKeyB64 != null && groupKeyB64!.isNotEmpty;
  bool get hasLegacySeed => legacySeedB64 != null && legacySeedB64!.isNotEmpty;

  ClusterEntry copyWith({
    String? clusterId,
    String? name,
    String? role,
    String? groupKeyB64,
    String? userId,
    String? serverHost,
    int? serverPort,
    bool? useTls,
    DateTime? lastUsed,
    // The seed is only ever removed (after its move into the store).
    bool clearLegacySeed = false,
  }) {
    return ClusterEntry(
      localId: localId,
      clusterId: clusterId ?? this.clusterId,
      name: name ?? this.name,
      role: role ?? this.role,
      legacySeedB64: clearLegacySeed ? null : legacySeedB64,
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
        if (legacySeedB64 != null) 'seed': legacySeedB64,
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
        legacySeedB64: j['seed'] as String?,
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

/// A device (Endpoint node) of one of this identity's networks, as reported
/// by the server.
class ClusterDevice {
  final String nodeId;
  final String hostname;
  final String? tunnelIp;

  /// True while this device has no group-key envelope — it cannot read Cluster
  /// data until an owner device seals the key to it.
  final bool needsKey;

  /// True for the device we're running on.
  final bool isThisDevice;

  /// The device's management key ("ed25519:..."), which assignments name.
  final String mgmtPubkey;

  /// True when this device's key holds `admin` on [groupId]: it can change
  /// who holds what in the group and on its devices.
  final bool isAdmin;

  /// A Lemonade inference server; false for a client device.
  final bool isInference;

  /// The device's identity joined [groupId] from its own network with an
  /// invite. The device stays placed in its own network, outside [groupId].
  final bool isMember;

  /// This device may connect to it.
  final bool canConnect;

  /// The group the device was listed for. Empty when unknown.
  final String groupId;

  /// "home" when [groupId] is one of this identity's own networks, "member"
  /// when it is a network this identity joined with an invite, null when the
  /// server did not say.
  final String? groupRole;

  /// Display name of [groupId]. Empty when unknown.
  final String networkName;

  /// True when [groupId] is the network this device is placed in. False for
  /// devices of networks this identity joined and of its other networks.
  final bool inHomeNetwork;

  /// True when the device is placed directly in the active Cluster group. The
  /// key, access, and remove actions apply only to these devices; the server
  /// refuses them for devices placed in other networks.
  final bool placedInCluster;

  const ClusterDevice({
    required this.nodeId,
    required this.hostname,
    required this.needsKey,
    required this.isThisDevice,
    this.tunnelIp,
    this.mgmtPubkey = '',
    this.isAdmin = false,
    this.isInference = false,
    this.isMember = false,
    this.canConnect = false,
    this.groupId = '',
    this.groupRole,
    this.networkName = '',
    this.inHomeNetwork = true,
    this.placedInCluster = true,
  });

  /// True when [groupId] is a network this identity joined with an invite.
  bool get inJoinedNetwork => groupRole == 'member';
}

/// Compare management keys by key bytes: the SDK writes url-safe unpadded
/// base64 while the server writes standard base64, so both spellings occur.
String canonicalPrincipal(String key) {
  var b64 = key.startsWith('ed25519:') ? key.substring(8) : key;
  b64 = b64.replaceAll('-', '+').replaceAll('_', '/').replaceAll('=', '');
  while (b64.length % 4 != 0) {
    b64 += '=';
  }
  return 'ed25519:$b64';
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
