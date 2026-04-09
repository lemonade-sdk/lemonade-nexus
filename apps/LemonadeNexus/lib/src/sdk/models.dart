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

  factory RelayInfo.fromJson(Map<String, dynamic> json) =>
      _$RelayInfoFromJson(json);

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

  factory CertStatus.fromJson(Map<String, dynamic> json) =>
      _$CertStatusFromJson(json);

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
@JsonSerializable()
class WgConfig {
  final String privateKey;
  final String publicKey;
  final String tunnelIp;
  final String serverPublicKey;
  final String serverEndpoint;
  final String dnsServer;
  final int listenPort;
  final List<String> allowedIps;
  final int keepalive;

  WgConfig({
    required this.privateKey,
    required this.publicKey,
    required this.tunnelIp,
    required this.serverPublicKey,
    required this.serverEndpoint,
    required this.dnsServer,
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

  factory MeshPeer.fromJson(Map<String, dynamic> json) =>
      _$MeshPeerFromJson(json);

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

  factory MeshStatus.fromJson(Map<String, dynamic> json) =>
      _$MeshStatusFromJson(json);

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

  factory ServerInfo.fromJson(Map<String, dynamic> json) =>
      _$ServerInfoFromJson(json);

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

  factory TrustStatus.fromJson(Map<String, dynamic> json) =>
      _$TrustStatusFromJson(json);

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

  factory TrustPeerInfo.fromJson(Map<String, dynamic> json) =>
      _$TrustPeerInfoFromJson(json);

  Map<String, dynamic> toJson() => _$TrustPeerInfoToJson(this);
}

// =========================================================================
// DDNS Models
// =========================================================================

/// DDNS credential status.
@JsonSerializable()
class DdnsStatus {
  final bool isEnabled;
  final String? hostname;
  final String? lastUpdated;
  final String? status;

  DdnsStatus({
    required this.isEnabled,
    this.hostname,
    this.lastUpdated,
    this.status,
  });

  factory DdnsStatus.fromJson(Map<String, dynamic> json) =>
      _$DdnsStatusFromJson(json);

  Map<String, dynamic> toJson() => _$DdnsStatusToJson(this);
}

// =========================================================================
// Enrollment Models
// =========================================================================

/// Enrollment entry.
@JsonSerializable()
class EnrollmentEntry {
  final String id;
  final String status;
  final String createdAt;
  final String? expiresAt;

  EnrollmentEntry({
    required this.id,
    required this.status,
    required this.createdAt,
    this.expiresAt,
  });

  factory EnrollmentEntry.fromJson(Map<String, dynamic> json) =>
      _$EnrollmentEntryFromJson(json);

  Map<String, dynamic> toJson() => _$EnrollmentEntryToJson(this);
}

// =========================================================================
// Governance Models
// =========================================================================

/// Governance proposal.
@JsonSerializable()
class GovernanceProposal {
  final String id;
  final int parameter;
  final String currentValue;
  final String proposedValue;
  final String rationale;
  final String proposerId;
  final int votesFor;
  final int votesAgainst;
  final String status;
  final String createdAt;
  final String? resolvedAt;

  GovernanceProposal({
    required this.id,
    required this.parameter,
    required this.currentValue,
    required this.proposedValue,
    required this.rationale,
    required this.proposerId,
    required this.votesFor,
    required this.votesAgainst,
    required this.status,
    required this.createdAt,
    this.resolvedAt,
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
@JsonSerializable()
class AttestationManifest {
  final String id;
  final String nodeId;
  final String statement;
  final String signature;
  final String createdAt;

  AttestationManifest({
    required this.id,
    required this.nodeId,
    required this.statement,
    required this.signature,
    required this.createdAt,
  });

  factory AttestationManifest.fromJson(Map<String, dynamic> json) =>
      _$AttestationManifestFromJson(json);

  Map<String, dynamic> toJson() => _$AttestationManifestToJson(this);
}

// =========================================================================
// Health Models
// =========================================================================

/// Health check response.
@JsonSerializable()
class HealthResponse {
  final String status;
  final String version;
  final int uptime;

  HealthResponse({
    required this.status,
    required this.version,
    required this.uptime,
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
