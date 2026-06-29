/// @title Lemonade Nexus SDK Models
/// @description Model classes for C SDK JSON responses.
///
/// These classes provide type-safe representations of JSON data
/// returned by the C SDK FFI bindings.

import 'package:json_annotation/json_annotation.dart';

part 'models.g.dart';

// =========================================================================
// Authentication Models
// =========================================================================

/// Authentication response from ln_auth_* functions.
@JsonSerializable()
class AuthResponse {
  final bool authenticated;
  final String? userId;
  final String? sessionToken;
  final String? error;

  AuthResponse({
    required this.authenticated,
    this.userId,
    this.sessionToken,
    this.error,
  });

  factory AuthResponse.fromJson(Map<String, dynamic> json) =>
      _$AuthResponseFromJson(json);

  Map<String, dynamic> toJson() => _$AuthResponseToJson(this);
}

// =========================================================================
// Tree Models
// =========================================================================

/// Node assignment with permissions.
@JsonSerializable()
class NodeAssignment {
  final String managementPubkey;
  final List<String> permissions;

  NodeAssignment({
    required this.managementPubkey,
    required this.permissions,
  });

  factory NodeAssignment.fromJson(Map<String, dynamic> json) =>
      _$NodeAssignmentFromJson(json);

  Map<String, dynamic> toJson() => _$NodeAssignmentToJson(this);
}

/// Node in the CRDT tree.
@JsonSerializable()
class TreeNode {
  final String id;
  final String parentId;
  final String nodeType;
  final String ownerId;
  final Map<String, dynamic> data;
  final int version;
  final String createdAt;
  final String updatedAt;

  // Additional fields from macOS API
  final String? hostname;
  final String? tunnelIp;
  final String? privateSubnet;
  final String? mgmtPubkey;
  final String? wgPubkey;
  final List<NodeAssignment>? assignments;
  final String? region;
  final String? listenEndpoint;

  TreeNode({
    required this.id,
    required this.parentId,
    required this.nodeType,
    required this.ownerId,
    required this.data,
    required this.version,
    required this.createdAt,
    required this.updatedAt,
    this.hostname,
    this.tunnelIp,
    this.privateSubnet,
    this.mgmtPubkey,
    this.wgPubkey,
    this.assignments,
    this.region,
    this.listenEndpoint,
  });

  factory TreeNode.fromJson(Map<String, dynamic> json) =>
      _$TreeNodeFromJson(json);

  Map<String, dynamic> toJson() => _$TreeNodeToJson(this);

  /// Display hostname - uses data['hostname'] or hostname field
  String get displayName => hostname ?? data['hostname']?.toString() ?? id;

  /// Display tunnel IP - uses data['tunnel_ip'] or tunnelIp field
  String? get displayTunnelIp => tunnelIp ?? data['tunnel_ip']?.toString();

  /// Display region - uses data['region'] or region field
  String? get displayRegion => region ?? data['region']?.toString();
}

/// Response from tree operations.
@JsonSerializable()
class TreeOperationResponse {
  final bool success;
  final TreeNode? node;
  final String? error;
  final List<TreeNode>? children;

  TreeOperationResponse({
    required this.success,
    this.node,
    this.error,
    this.children,
  });

  factory TreeOperationResponse.fromJson(Map<String, dynamic> json) =>
      _$TreeOperationResponseFromJson(json);

  Map<String, dynamic> toJson() => _$TreeOperationResponseToJson(this);
}

// =========================================================================
// IPAM Models
// =========================================================================

/// IP address allocation response.
@JsonSerializable()
class IpAllocation {
  final String nodeId;
  final String blockType;
  final String allocatedIp;
  final String? subnet;
  final String allocatedAt;

  IpAllocation({
    required this.nodeId,
    required this.blockType,
    required this.allocatedIp,
    this.subnet,
    required this.allocatedAt,
  });

  factory IpAllocation.fromJson(Map<String, dynamic> json) =>
      _$IpAllocationFromJson(json);

  Map<String, dynamic> toJson() => _$IpAllocationToJson(this);
}

// =========================================================================
// Relay Models
// =========================================================================

/// Relay server information.
@JsonSerializable()
class RelayInfo {
  final String id;
  final String host;
  final int port;
  final String region;
  final bool available;
  final double? latencyMs;

  RelayInfo({
    required this.id,
    required this.host,
    required this.port,
    required this.region,
    required this.available,
    this.latencyMs,
  });

  /// Parses an entry from the SDK's `ln_relay_list` output.
  ///
  /// Per the SDK source of truth (`CApi.cpp`), the real shape is
  /// `{relay_id, endpoint, region, reputation_score, supports_stun,
  /// supports_relay}` — NOT `{id, host, port, available}` and NOT the macOS
  /// mirror's `{pubkey, load, latency_ms}` (the macOS app diverged here). We map
  /// the real keys; `available` reflects `supports_relay`. No latency is exposed
  /// by this endpoint.
  factory RelayInfo.fromJson(Map<String, dynamic> json) {
    final endpoint = (json['endpoint'] ?? json['host'] ?? '').toString();
    final hostPart = endpoint.contains(':') ? endpoint.split(':').first : endpoint;
    final portPart = endpoint.contains(':')
        ? int.tryParse(endpoint.split(':').last)
        : null;
    return RelayInfo(
      id: (json['relay_id'] ?? json['id'] ?? endpoint).toString(),
      host: (json['host'] ?? hostPart).toString(),
      port: ((json['port']) as num?)?.toInt() ?? portPart ?? 0,
      region: (json['region'] ?? '').toString(),
      available: (json['supports_relay'] as bool?) ??
          (json['available'] as bool?) ??
          true,
      latencyMs: (json['latency_ms'] as num?)?.toDouble(),
    );
  }

  Map<String, dynamic> toJson() => _$RelayInfoToJson(this);
}

/// Relay ticket for establishing a connection.
@JsonSerializable()
class RelayTicket {
  final String ticket;
  final String peerId;
  final String relayId;
  final String expiresAt;

  RelayTicket({
    required this.ticket,
    required this.peerId,
    required this.relayId,
    required this.expiresAt,
  });

  factory RelayTicket.fromJson(Map<String, dynamic> json) =>
      _$RelayTicketFromJson(json);

  Map<String, dynamic> toJson() => _$RelayTicketToJson(this);
}

// =========================================================================
// Certificate Models
// =========================================================================

/// Certificate status information.
@JsonSerializable()
class CertStatus {
  final String domain;
  final bool isIssued;
  final String? expiresAt;
  final String? issuedAt;
  final String? status;

  CertStatus({
    required this.domain,
    required this.isIssued,
    this.expiresAt,
    this.issuedAt,
    this.status,
  });

  /// Mirrors `ln_cert_status` (SDK CApi.cpp): `{domain, has_cert, expires_at,
  /// error?}`. The SDK key is `has_cert`, not `is_issued`, and it does not emit
  /// `issued_at`/`status`.
  factory CertStatus.fromJson(Map<String, dynamic> json) => CertStatus(
        domain: (json['domain'] ?? '').toString(),
        isIssued: (json['has_cert'] ?? json['is_issued'] ?? false) as bool,
        expiresAt: json['expires_at']?.toString(),
        issuedAt: json['issued_at']?.toString(),
        status: json['status']?.toString() ?? json['error']?.toString(),
      );

  Map<String, dynamic> toJson() => _$CertStatusToJson(this);
}

/// Decrypted certificate bundle.
@JsonSerializable()
class CertBundle {
  final String domain;
  final String fullchainPem;
  final String privkeyPem;
  final String expiresAt;

  CertBundle({
    required this.domain,
    required this.fullchainPem,
    required this.privkeyPem,
    required this.expiresAt,
  });

  factory CertBundle.fromJson(Map<String, dynamic> json) =>
      _$CertBundleFromJson(json);

  Map<String, dynamic> toJson() => _$CertBundleToJson(this);
}

// =========================================================================
// Group Models
// =========================================================================

/// Group member information.
@JsonSerializable()
class GroupMember {
  final String nodeId;
  final String pubkey;
  final List<String> permissions;
  final String joinedAt;

  GroupMember({
    required this.nodeId,
    required this.pubkey,
    required this.permissions,
    required this.joinedAt,
  });

  factory GroupMember.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberFromJson(json);

  Map<String, dynamic> toJson() => _$GroupMemberToJson(this);
}

/// Group join response.
@JsonSerializable()
class GroupJoinResponse {
  final bool success;
  final String? endpointNodeId;
  final String? tunnelIp;
  final String? error;

  GroupJoinResponse({
    required this.success,
    this.endpointNodeId,
    this.tunnelIp,
    this.error,
  });

  factory GroupJoinResponse.fromJson(Map<String, dynamic> json) =>
      _$GroupJoinResponseFromJson(json);

  Map<String, dynamic> toJson() => _$GroupJoinResponseToJson(this);
}

// =========================================================================
// Network Models
// =========================================================================

/// Network join response.
@JsonSerializable()
class NetworkJoinResponse {
  final bool success;
  final String? nodeId;
  final String? tunnelIp;
  final String? sessionToken;
  final String? error;

  NetworkJoinResponse({
    required this.success,
    this.nodeId,
    this.tunnelIp,
    this.sessionToken,
    this.error,
  });

  factory NetworkJoinResponse.fromJson(Map<String, dynamic> json) =>
      _$NetworkJoinResponseFromJson(json);

  Map<String, dynamic> toJson() => _$NetworkJoinResponseToJson(this);
}

// =========================================================================
// Latency Models
// =========================================================================

/// Server latency information.
@JsonSerializable()
class ServerLatency {
  final String host;
  final int port;
  final double smoothedRttMs;
  final bool reachable;
  final int consecutiveFailures;

  ServerLatency({
    required this.host,
    required this.port,
    required this.smoothedRttMs,
    required this.reachable,
    required this.consecutiveFailures,
  });

  factory ServerLatency.fromJson(Map<String, dynamic> json) =>
      _$ServerLatencyFromJson(json);

  Map<String, dynamic> toJson() => _$ServerLatencyToJson(this);
}

// =========================================================================
// WireGuard Models
// =========================================================================

/// WireGuard tunnel status.
@JsonSerializable()
class TunnelStatus {
  final bool isUp;
  final String? tunnelIp;
  final String? serverEndpoint;
  final String? lastHandshake;
  final int? rxBytes;
  final int? txBytes;
  final double? latencyMs;

  TunnelStatus({
    required this.isUp,
    this.tunnelIp,
    this.serverEndpoint,
    this.lastHandshake,
    this.rxBytes,
    this.txBytes,
    this.latencyMs,
  });

  factory TunnelStatus.fromJson(Map<String, dynamic> json) =>
      _$TunnelStatusFromJson(json);

  Map<String, dynamic> toJson() => _$TunnelStatusToJson(this);
}

/// WireGuard configuration.
///
/// Mirrors `ln_get_wg_config_json`: `{private_key, public_key, tunnel_ip,
/// server_public_key, server_endpoint, listen_port, keepalive, allowed_ips}`.
/// Note the SDK does NOT emit `dns_server`, so it must be nullable — marking it
/// a required String made config parsing throw and blocked the tunnel.
@JsonSerializable()
class WgConfig {
  final String privateKey;
  final String publicKey;
  final String tunnelIp;
  final String serverPublicKey;
  final String serverEndpoint;
  final String? dnsServer;
  final int listenPort;
  final List<String> allowedIps;
  final int keepalive;

  WgConfig({
    required this.privateKey,
    required this.publicKey,
    required this.tunnelIp,
    required this.serverPublicKey,
    required this.serverEndpoint,
    this.dnsServer,
    required this.listenPort,
    required this.allowedIps,
    required this.keepalive,
  });

  factory WgConfig.fromJson(Map<String, dynamic> json) =>
      _$WgConfigFromJson(json);

  Map<String, dynamic> toJson() => _$WgConfigToJson(this);
}

/// WireGuard keypair.
@JsonSerializable()
class WgKeypair {
  final String privateKey;
  final String publicKey;

  WgKeypair({
    required this.privateKey,
    required this.publicKey,
  });

  factory WgKeypair.fromJson(Map<String, dynamic> json) =>
      _$WgKeypairFromJson(json);

  Map<String, dynamic> toJson() => _$WgKeypairToJson(this);
}

// =========================================================================
// Mesh Models
// =========================================================================

/// Mesh peer information.
@JsonSerializable()
class MeshPeer {
  final String nodeId;
  final String? hostname;
  final String wgPubkey;
  final String? tunnelIp;
  final String? privateSubnet;
  final String? endpoint;
  final String? relayEndpoint;
  final bool isOnline;
  final String? lastHandshake;
  final int? rxBytes;
  final int? txBytes;
  final double? latencyMs;
  final int keepalive;

  MeshPeer({
    required this.nodeId,
    this.hostname,
    required this.wgPubkey,
    this.tunnelIp,
    this.privateSubnet,
    this.endpoint,
    this.relayEndpoint,
    required this.isOnline,
    this.lastHandshake,
    this.rxBytes,
    this.txBytes,
    this.latencyMs,
    required this.keepalive,
  });

  /// Parses a peer from the SDK's mesh output.
  ///
  /// The SDK sends every field as optional (macOS `SDKMeshPeer`), and uses
  /// numeric `latency_ms`/`last_handshake`. The generated parser's strict
  /// `as bool`/`as double?`/`as String?` casts threw on missing/numeric values,
  /// silently emptying mesh status. We parse defensively instead.
  factory MeshPeer.fromJson(Map<String, dynamic> json) => MeshPeer(
        nodeId: (json['node_id'] ?? '').toString(),
        hostname: json['hostname']?.toString(),
        wgPubkey: (json['wg_pubkey'] ?? '').toString(),
        tunnelIp: json['tunnel_ip']?.toString(),
        privateSubnet: json['private_subnet']?.toString(),
        endpoint: json['endpoint']?.toString(),
        relayEndpoint: json['relay_endpoint']?.toString(),
        isOnline: (json['is_online'] as bool?) ?? false,
        lastHandshake: json['last_handshake']?.toString(),
        rxBytes: (json['rx_bytes'] as num?)?.toInt(),
        txBytes: (json['tx_bytes'] as num?)?.toInt(),
        latencyMs: (json['latency_ms'] as num?)?.toDouble(),
        keepalive: (json['keepalive'] as num?)?.toInt() ?? 0,
      );

  Map<String, dynamic> toJson() => _$MeshPeerToJson(this);
}

/// Mesh tunnel status.
@JsonSerializable()
class MeshStatus {
  final bool isUp;
  final String? tunnelIp;
  final int peerCount;
  final int onlineCount;
  final int totalRxBytes;
  final int totalTxBytes;
  final List<MeshPeer> peers;

  MeshStatus({
    required this.isUp,
    this.tunnelIp,
    required this.peerCount,
    required this.onlineCount,
    required this.totalRxBytes,
    required this.totalTxBytes,
    required this.peers,
  });

  /// Parses the SDK's mesh status output (macOS `SDKMeshStatus`).
  ///
  /// `peers` and the counters are optional in the SDK; the generated parser's
  /// strict casts (`peers as List`, `as int`) threw when they were absent.
  factory MeshStatus.fromJson(Map<String, dynamic> json) => MeshStatus(
        isUp: (json['is_up'] as bool?) ?? false,
        tunnelIp: json['tunnel_ip']?.toString(),
        peerCount: (json['peer_count'] as num?)?.toInt() ?? 0,
        onlineCount: (json['online_count'] as num?)?.toInt() ?? 0,
        totalRxBytes: (json['total_rx_bytes'] as num?)?.toInt() ?? 0,
        totalTxBytes: (json['total_tx_bytes'] as num?)?.toInt() ?? 0,
        peers: (json['peers'] as List<dynamic>?)
                ?.whereType<Map<String, dynamic>>()
                .map(MeshPeer.fromJson)
                .toList() ??
            const [],
      );

  Map<String, dynamic> toJson() => _$MeshStatusToJson(this);
}

// =========================================================================
// Stats Models
// =========================================================================

/// Service statistics.
@JsonSerializable()
class ServiceStats {
  final String service;
  final int peerCount;
  final bool privateApiEnabled;

  ServiceStats({
    required this.service,
    required this.peerCount,
    required this.privateApiEnabled,
  });

  factory ServiceStats.fromJson(Map<String, dynamic> json) =>
      _$ServiceStatsFromJson(json);

  Map<String, dynamic> toJson() => _$ServiceStatsToJson(this);
}

/// Server information.
@JsonSerializable()
class ServerInfo {
  final String id;
  final String host;
  final int port;
  final String region;
  final bool available;
  final double? latencyMs;

  ServerInfo({
    required this.id,
    required this.host,
    required this.port,
    required this.region,
    required this.available,
    this.latencyMs,
  });

  /// Parses an entry from the SDK's `ln_servers` output.
  ///
  /// The SDK returns `{endpoint, pubkey, http_port, last_seen, healthy}`
  /// (matching the macOS `ServerEntry` parser) — NOT the
  /// `{id, host, port, region, available, latency_ms}` shape json_serializable
  /// generated. We map the real keys here and fall back to the alternate shape
  /// so either form parses without throwing (a throw here previously emptied
  /// the whole server list).
  factory ServerInfo.fromJson(Map<String, dynamic> json) {
    final endpoint = (json['endpoint'] ?? json['host'] ?? '').toString();
    // `endpoint` may be "host:port"; the HTTP/admin port comes from http_port.
    final hostPart = endpoint.contains(':') ? endpoint.split(':').first : endpoint;
    final httpPort =
        ((json['http_port'] ?? json['port']) as num?)?.toInt() ?? 9100;
    return ServerInfo(
      id: (json['id'] ?? endpoint).toString(),
      host: (json['host'] ?? hostPart).toString(),
      port: httpPort,
      region: (json['region'] ?? '').toString(),
      available: (json['healthy'] ?? json['available'] ?? false) as bool,
      latencyMs: (json['latency_ms'] as num?)?.toDouble(),
    );
  }

  Map<String, dynamic> toJson() => _$ServerInfoToJson(this);
}

// =========================================================================
// Trust Models
// =========================================================================

/// Trust status information.
@JsonSerializable()
class TrustStatus {
  final String trustTier;
  final int peerCount;
  final List<TrustPeerInfo>? peers;

  TrustStatus({
    required this.trustTier,
    required this.peerCount,
    this.peers,
  });

  /// Parses the SDK's `ln_trust_status` output.
  ///
  /// The SDK returns `{our_tier: int, our_platform, require_tee, peer_count,
  /// peers}` (matching the macOS `TrustStatusResponse`) — NOT `trust_tier`. We
  /// map `our_tier` -> [trustTier] (as a string for display) and tolerate the
  /// alternate `trust_tier` shape.
  factory TrustStatus.fromJson(Map<String, dynamic> json) {
    final tier = json['our_tier'] ?? json['trust_tier'];
    return TrustStatus(
      trustTier: tier?.toString() ?? '0',
      peerCount: ((json['peer_count']) as num?)?.toInt() ?? 0,
      peers: (json['peers'] as List<dynamic>?)
          ?.whereType<Map<String, dynamic>>()
          .map(TrustPeerInfo.fromJson)
          .toList(),
    );
  }

  Map<String, dynamic> toJson() => _$TrustStatusToJson(this);
}

/// Individual trust peer information.
@JsonSerializable()
class TrustPeerInfo {
  final String pubkey;
  final String trustLevel;
  final int attestations;
  final String? lastSeen;

  TrustPeerInfo({
    required this.pubkey,
    required this.trustLevel,
    required this.attestations,
    this.lastSeen,
  });

  /// Parses a peer from the SDK's trust status `peers` array.
  ///
  /// The SDK returns `{pubkey, tier: int, platform, last_verified}` (macOS
  /// `TrustPeer`) — NOT `{trust_level, attestations, last_seen}`. We map
  /// `tier` -> [trustLevel] and `last_verified` -> [lastSeen].
  factory TrustPeerInfo.fromJson(Map<String, dynamic> json) {
    final tier = json['tier'] ?? json['trust_level'];
    return TrustPeerInfo(
      pubkey: (json['pubkey'] ?? '').toString(),
      trustLevel: tier?.toString() ?? '0',
      attestations: ((json['attestations']) as num?)?.toInt() ?? 0,
      lastSeen: (json['last_verified'] ?? json['last_seen'])?.toString(),
    );
  }

  Map<String, dynamic> toJson() => _$TrustPeerInfoToJson(this);
}

// =========================================================================
// DDNS Models
// =========================================================================

/// DDNS credential status.
///
/// Mirrors `ln_ddns_status` (SDK CApi.cpp): `{has_credentials, last_ip,
/// binary_hash, binary_approved, error?}`.
@JsonSerializable()
class DdnsStatus {
  final bool hasCredentials;
  final String? lastIp;
  final String? binaryHash;
  final bool? binaryApproved;
  final String? error;

  DdnsStatus({
    this.hasCredentials = false,
    this.lastIp,
    this.binaryHash,
    this.binaryApproved,
    this.error,
  });

  factory DdnsStatus.fromJson(Map<String, dynamic> json) =>
      _$DdnsStatusFromJson(json);

  Map<String, dynamic> toJson() => _$DdnsStatusToJson(this);
}

// =========================================================================
// Enrollment Models
// =========================================================================

/// Enrollment entry.
///
/// Mirrors an item of the `enrollments` array in `ln_enrollment_status` (SDK
/// CApi.cpp): `{request_id, candidate_pubkey, candidate_server_id,
/// sponsor_pubkey, state, state_name, created_at, timeout_at, retries, votes}`.
@JsonSerializable()
class EnrollmentEntry {
  final String requestId;
  final String? candidatePubkey;
  final String? candidateServerId;
  final String? sponsorPubkey;
  final int state;
  final String? stateName;
  final String? createdAt;
  final String? timeoutAt;
  final int retries;

  EnrollmentEntry({
    required this.requestId,
    this.candidatePubkey,
    this.candidateServerId,
    this.sponsorPubkey,
    this.state = 0,
    this.stateName,
    this.createdAt,
    this.timeoutAt,
    this.retries = 0,
  });

  factory EnrollmentEntry.fromJson(Map<String, dynamic> json) =>
      _$EnrollmentEntryFromJson(json);

  Map<String, dynamic> toJson() => _$EnrollmentEntryToJson(this);
}

// =========================================================================
// Governance Models
// =========================================================================

/// Governance proposal.
///
/// Mirrors an entry of `ln_governance_proposals` (SDK CApi.cpp):
/// `{proposal_id, proposer_pubkey, parameter, new_value, old_value, rationale,
/// created_at, expires_at, state, state_name, votes:[...]}`.
@JsonSerializable()
class GovernanceProposal {
  final String proposalId;
  final String? proposerPubkey;
  final int parameter;
  final String newValue;
  final String oldValue;
  final String rationale;
  final String? createdAt;
  final String? expiresAt;
  final int state;
  final String? stateName;

  GovernanceProposal({
    required this.proposalId,
    this.proposerPubkey,
    required this.parameter,
    this.newValue = '',
    this.oldValue = '',
    this.rationale = '',
    this.createdAt,
    this.expiresAt,
    this.state = 0,
    this.stateName,
  });

  factory GovernanceProposal.fromJson(Map<String, dynamic> json) =>
      _$GovernanceProposalFromJson(json);

  Map<String, dynamic> toJson() => _$GovernanceProposalToJson(this);
}

/// Proposal submission response.
@JsonSerializable()
class ProposeResponse {
  final String? proposalId;
  final String status;
  final String? error;

  ProposeResponse({
    this.proposalId,
    required this.status,
    this.error,
  });

  factory ProposeResponse.fromJson(Map<String, dynamic> json) =>
      _$ProposeResponseFromJson(json);

  Map<String, dynamic> toJson() => _$ProposeResponseToJson(this);
}

// =========================================================================
// Attestation Models
// =========================================================================

/// Attestation manifest.
///
/// Mirrors an item of the `manifests` array in `ln_attestation_manifests` (SDK
/// CApi.cpp): `{version, platform, binary_sha256, timestamp}`. The surrounding
/// envelope (`self_hash`, `self_approved`, …) is unwrapped by the SDK wrapper.
@JsonSerializable()
class AttestationManifest {
  final String version;
  final String? platform;
  final String binarySha256;
  final int? timestamp;

  AttestationManifest({
    this.version = '',
    this.platform,
    this.binarySha256 = '',
    this.timestamp,
  });

  factory AttestationManifest.fromJson(Map<String, dynamic> json) =>
      _$AttestationManifestFromJson(json);

  Map<String, dynamic> toJson() => _$AttestationManifestToJson(this);
}

// =========================================================================
// Health Models
// =========================================================================

/// Health check response.
///
/// Mirrors `ln_health` in the SDK (`projects/LemonadeNexusSDK`, CApi.cpp):
/// `{status, service, dns_base_domain, ok, error?}`. The SDK does NOT return
/// version/uptime (those were a fiction that left the dashboard showing
/// "unknown" / "0s") nor `rp_id`.
@JsonSerializable()
class HealthResponse {
  final String status;
  final String service;
  final String? dnsBaseDomain;
  final bool? ok;
  final String? error;

  HealthResponse({
    required this.status,
    this.service = '',
    this.dnsBaseDomain,
    this.ok,
    this.error,
  });

  factory HealthResponse.fromJson(Map<String, dynamic> json) =>
      _$HealthResponseFromJson(json);

  Map<String, dynamic> toJson() => _$HealthResponseToJson(this);
}

// =========================================================================
// Identity Models
// =========================================================================

/// Identity information.
@JsonSerializable()
class IdentityInfo {
  final String pubkey;
  final String? fingerprint;

  IdentityInfo({
    required this.pubkey,
    this.fingerprint,
  });

  factory IdentityInfo.fromJson(Map<String, dynamic> json) =>
      _$IdentityInfoFromJson(json);

  Map<String, dynamic> toJson() => _$IdentityInfoToJson(this);
}
