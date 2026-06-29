// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'models.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AuthResponse _$AuthResponseFromJson(Map<String, dynamic> json) => AuthResponse(
      authenticated: json['authenticated'] as bool,
      userId: json['user_id'] as String?,
      sessionToken: json['session_token'] as String?,
      error: json['error'] as String?,
    );

Map<String, dynamic> _$AuthResponseToJson(AuthResponse instance) =>
    <String, dynamic>{
      'authenticated': instance.authenticated,
      'user_id': instance.userId,
      'session_token': instance.sessionToken,
      'error': instance.error,
    };

NodeAssignment _$NodeAssignmentFromJson(Map<String, dynamic> json) =>
    NodeAssignment(
      managementPubkey: json['management_pubkey'] as String,
      permissions: (json['permissions'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
    );

Map<String, dynamic> _$NodeAssignmentToJson(NodeAssignment instance) =>
    <String, dynamic>{
      'management_pubkey': instance.managementPubkey,
      'permissions': instance.permissions,
    };

TreeNode _$TreeNodeFromJson(Map<String, dynamic> json) => TreeNode(
      id: json['id'] as String,
      parentId: json['parent_id'] as String,
      nodeType: json['node_type'] as String,
      ownerId: json['owner_id'] as String,
      data: json['data'] as Map<String, dynamic>,
      version: (json['version'] as num).toInt(),
      createdAt: json['created_at'] as String,
      updatedAt: json['updated_at'] as String,
      hostname: json['hostname'] as String?,
      tunnelIp: json['tunnel_ip'] as String?,
      privateSubnet: json['private_subnet'] as String?,
      mgmtPubkey: json['mgmt_pubkey'] as String?,
      wgPubkey: json['wg_pubkey'] as String?,
      assignments: (json['assignments'] as List<dynamic>?)
          ?.map((e) => NodeAssignment.fromJson(e as Map<String, dynamic>))
          .toList(),
      region: json['region'] as String?,
      listenEndpoint: json['listen_endpoint'] as String?,
    );

Map<String, dynamic> _$TreeNodeToJson(TreeNode instance) => <String, dynamic>{
      'id': instance.id,
      'parent_id': instance.parentId,
      'node_type': instance.nodeType,
      'owner_id': instance.ownerId,
      'data': instance.data,
      'version': instance.version,
      'created_at': instance.createdAt,
      'updated_at': instance.updatedAt,
      'hostname': instance.hostname,
      'tunnel_ip': instance.tunnelIp,
      'private_subnet': instance.privateSubnet,
      'mgmt_pubkey': instance.mgmtPubkey,
      'wg_pubkey': instance.wgPubkey,
      'assignments': instance.assignments,
      'region': instance.region,
      'listen_endpoint': instance.listenEndpoint,
    };

TreeOperationResponse _$TreeOperationResponseFromJson(
        Map<String, dynamic> json) =>
    TreeOperationResponse(
      success: json['success'] as bool,
      node: json['node'] == null
          ? null
          : TreeNode.fromJson(json['node'] as Map<String, dynamic>),
      error: json['error'] as String?,
      children: (json['children'] as List<dynamic>?)
          ?.map((e) => TreeNode.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$TreeOperationResponseToJson(
        TreeOperationResponse instance) =>
    <String, dynamic>{
      'success': instance.success,
      'node': instance.node,
      'error': instance.error,
      'children': instance.children,
    };

IpAllocation _$IpAllocationFromJson(Map<String, dynamic> json) => IpAllocation(
      nodeId: json['node_id'] as String,
      blockType: json['block_type'] as String,
      allocatedIp: json['allocated_ip'] as String,
      subnet: json['subnet'] as String?,
      allocatedAt: json['allocated_at'] as String,
    );

Map<String, dynamic> _$IpAllocationToJson(IpAllocation instance) =>
    <String, dynamic>{
      'node_id': instance.nodeId,
      'block_type': instance.blockType,
      'allocated_ip': instance.allocatedIp,
      'subnet': instance.subnet,
      'allocated_at': instance.allocatedAt,
    };

RelayInfo _$RelayInfoFromJson(Map<String, dynamic> json) => RelayInfo(
      id: json['id'] as String,
      host: json['host'] as String,
      port: (json['port'] as num).toInt(),
      region: json['region'] as String,
      available: json['available'] as bool,
      latencyMs: (json['latency_ms'] as num?)?.toDouble(),
    );

Map<String, dynamic> _$RelayInfoToJson(RelayInfo instance) => <String, dynamic>{
      'id': instance.id,
      'host': instance.host,
      'port': instance.port,
      'region': instance.region,
      'available': instance.available,
      'latency_ms': instance.latencyMs,
    };

RelayTicket _$RelayTicketFromJson(Map<String, dynamic> json) => RelayTicket(
      ticket: json['ticket'] as String,
      peerId: json['peer_id'] as String,
      relayId: json['relay_id'] as String,
      expiresAt: json['expires_at'] as String,
    );

Map<String, dynamic> _$RelayTicketToJson(RelayTicket instance) =>
    <String, dynamic>{
      'ticket': instance.ticket,
      'peer_id': instance.peerId,
      'relay_id': instance.relayId,
      'expires_at': instance.expiresAt,
    };

CertStatus _$CertStatusFromJson(Map<String, dynamic> json) => CertStatus(
      domain: json['domain'] as String,
      isIssued: json['is_issued'] as bool,
      expiresAt: json['expires_at'] as String?,
      issuedAt: json['issued_at'] as String?,
      status: json['status'] as String?,
    );

Map<String, dynamic> _$CertStatusToJson(CertStatus instance) =>
    <String, dynamic>{
      'domain': instance.domain,
      'is_issued': instance.isIssued,
      'expires_at': instance.expiresAt,
      'issued_at': instance.issuedAt,
      'status': instance.status,
    };

CertBundle _$CertBundleFromJson(Map<String, dynamic> json) => CertBundle(
      domain: json['domain'] as String,
      fullchainPem: json['fullchain_pem'] as String,
      privkeyPem: json['privkey_pem'] as String,
      expiresAt: json['expires_at'] as String,
    );

Map<String, dynamic> _$CertBundleToJson(CertBundle instance) =>
    <String, dynamic>{
      'domain': instance.domain,
      'fullchain_pem': instance.fullchainPem,
      'privkey_pem': instance.privkeyPem,
      'expires_at': instance.expiresAt,
    };

GroupMember _$GroupMemberFromJson(Map<String, dynamic> json) => GroupMember(
      nodeId: json['node_id'] as String,
      pubkey: json['pubkey'] as String,
      permissions: (json['permissions'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      joinedAt: json['joined_at'] as String,
    );

Map<String, dynamic> _$GroupMemberToJson(GroupMember instance) =>
    <String, dynamic>{
      'node_id': instance.nodeId,
      'pubkey': instance.pubkey,
      'permissions': instance.permissions,
      'joined_at': instance.joinedAt,
    };

GroupJoinResponse _$GroupJoinResponseFromJson(Map<String, dynamic> json) =>
    GroupJoinResponse(
      success: json['success'] as bool,
      endpointNodeId: json['endpoint_node_id'] as String?,
      tunnelIp: json['tunnel_ip'] as String?,
      error: json['error'] as String?,
    );

Map<String, dynamic> _$GroupJoinResponseToJson(GroupJoinResponse instance) =>
    <String, dynamic>{
      'success': instance.success,
      'endpoint_node_id': instance.endpointNodeId,
      'tunnel_ip': instance.tunnelIp,
      'error': instance.error,
    };

NetworkJoinResponse _$NetworkJoinResponseFromJson(Map<String, dynamic> json) =>
    NetworkJoinResponse(
      success: json['success'] as bool,
      nodeId: json['node_id'] as String?,
      tunnelIp: json['tunnel_ip'] as String?,
      sessionToken: json['session_token'] as String?,
      error: json['error'] as String?,
    );

Map<String, dynamic> _$NetworkJoinResponseToJson(
        NetworkJoinResponse instance) =>
    <String, dynamic>{
      'success': instance.success,
      'node_id': instance.nodeId,
      'tunnel_ip': instance.tunnelIp,
      'session_token': instance.sessionToken,
      'error': instance.error,
    };

ServerLatency _$ServerLatencyFromJson(Map<String, dynamic> json) =>
    ServerLatency(
      host: json['host'] as String,
      port: (json['port'] as num).toInt(),
      smoothedRttMs: (json['smoothed_rtt_ms'] as num).toDouble(),
      reachable: json['reachable'] as bool,
      consecutiveFailures: (json['consecutive_failures'] as num).toInt(),
    );

Map<String, dynamic> _$ServerLatencyToJson(ServerLatency instance) =>
    <String, dynamic>{
      'host': instance.host,
      'port': instance.port,
      'smoothed_rtt_ms': instance.smoothedRttMs,
      'reachable': instance.reachable,
      'consecutive_failures': instance.consecutiveFailures,
    };

TunnelStatus _$TunnelStatusFromJson(Map<String, dynamic> json) => TunnelStatus(
      isUp: json['is_up'] as bool,
      tunnelIp: json['tunnel_ip'] as String?,
      serverEndpoint: json['server_endpoint'] as String?,
      lastHandshake: json['last_handshake'] as String?,
      rxBytes: (json['rx_bytes'] as num?)?.toInt(),
      txBytes: (json['tx_bytes'] as num?)?.toInt(),
      latencyMs: (json['latency_ms'] as num?)?.toDouble(),
    );

Map<String, dynamic> _$TunnelStatusToJson(TunnelStatus instance) =>
    <String, dynamic>{
      'is_up': instance.isUp,
      'tunnel_ip': instance.tunnelIp,
      'server_endpoint': instance.serverEndpoint,
      'last_handshake': instance.lastHandshake,
      'rx_bytes': instance.rxBytes,
      'tx_bytes': instance.txBytes,
      'latency_ms': instance.latencyMs,
    };

WgConfig _$WgConfigFromJson(Map<String, dynamic> json) => WgConfig(
      privateKey: json['private_key'] as String,
      publicKey: json['public_key'] as String,
      tunnelIp: json['tunnel_ip'] as String,
      serverPublicKey: json['server_public_key'] as String,
      serverEndpoint: json['server_endpoint'] as String,
      dnsServer: json['dns_server'] as String?,
      listenPort: (json['listen_port'] as num).toInt(),
      allowedIps: (json['allowed_ips'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      keepalive: (json['keepalive'] as num).toInt(),
    );

Map<String, dynamic> _$WgConfigToJson(WgConfig instance) => <String, dynamic>{
      'private_key': instance.privateKey,
      'public_key': instance.publicKey,
      'tunnel_ip': instance.tunnelIp,
      'server_public_key': instance.serverPublicKey,
      'server_endpoint': instance.serverEndpoint,
      'dns_server': instance.dnsServer,
      'listen_port': instance.listenPort,
      'allowed_ips': instance.allowedIps,
      'keepalive': instance.keepalive,
    };

WgKeypair _$WgKeypairFromJson(Map<String, dynamic> json) => WgKeypair(
      privateKey: json['private_key'] as String,
      publicKey: json['public_key'] as String,
    );

Map<String, dynamic> _$WgKeypairToJson(WgKeypair instance) => <String, dynamic>{
      'private_key': instance.privateKey,
      'public_key': instance.publicKey,
    };

MeshPeer _$MeshPeerFromJson(Map<String, dynamic> json) => MeshPeer(
      nodeId: json['node_id'] as String,
      hostname: json['hostname'] as String?,
      wgPubkey: json['wg_pubkey'] as String,
      tunnelIp: json['tunnel_ip'] as String?,
      privateSubnet: json['private_subnet'] as String?,
      endpoint: json['endpoint'] as String?,
      relayEndpoint: json['relay_endpoint'] as String?,
      isOnline: json['is_online'] as bool,
      lastHandshake: json['last_handshake'] as String?,
      rxBytes: (json['rx_bytes'] as num?)?.toInt(),
      txBytes: (json['tx_bytes'] as num?)?.toInt(),
      latencyMs: (json['latency_ms'] as num?)?.toDouble(),
      keepalive: (json['keepalive'] as num).toInt(),
    );

Map<String, dynamic> _$MeshPeerToJson(MeshPeer instance) => <String, dynamic>{
      'node_id': instance.nodeId,
      'hostname': instance.hostname,
      'wg_pubkey': instance.wgPubkey,
      'tunnel_ip': instance.tunnelIp,
      'private_subnet': instance.privateSubnet,
      'endpoint': instance.endpoint,
      'relay_endpoint': instance.relayEndpoint,
      'is_online': instance.isOnline,
      'last_handshake': instance.lastHandshake,
      'rx_bytes': instance.rxBytes,
      'tx_bytes': instance.txBytes,
      'latency_ms': instance.latencyMs,
      'keepalive': instance.keepalive,
    };

MeshStatus _$MeshStatusFromJson(Map<String, dynamic> json) => MeshStatus(
      isUp: json['is_up'] as bool,
      tunnelIp: json['tunnel_ip'] as String?,
      peerCount: (json['peer_count'] as num).toInt(),
      onlineCount: (json['online_count'] as num).toInt(),
      totalRxBytes: (json['total_rx_bytes'] as num).toInt(),
      totalTxBytes: (json['total_tx_bytes'] as num).toInt(),
      peers: (json['peers'] as List<dynamic>)
          .map((e) => MeshPeer.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$MeshStatusToJson(MeshStatus instance) =>
    <String, dynamic>{
      'is_up': instance.isUp,
      'tunnel_ip': instance.tunnelIp,
      'peer_count': instance.peerCount,
      'online_count': instance.onlineCount,
      'total_rx_bytes': instance.totalRxBytes,
      'total_tx_bytes': instance.totalTxBytes,
      'peers': instance.peers,
    };

ServiceStats _$ServiceStatsFromJson(Map<String, dynamic> json) => ServiceStats(
      service: json['service'] as String,
      peerCount: (json['peer_count'] as num).toInt(),
      privateApiEnabled: json['private_api_enabled'] as bool,
    );

Map<String, dynamic> _$ServiceStatsToJson(ServiceStats instance) =>
    <String, dynamic>{
      'service': instance.service,
      'peer_count': instance.peerCount,
      'private_api_enabled': instance.privateApiEnabled,
    };

ServerInfo _$ServerInfoFromJson(Map<String, dynamic> json) => ServerInfo(
      id: json['id'] as String,
      host: json['host'] as String,
      port: (json['port'] as num).toInt(),
      region: json['region'] as String,
      available: json['available'] as bool,
      latencyMs: (json['latency_ms'] as num?)?.toDouble(),
    );

Map<String, dynamic> _$ServerInfoToJson(ServerInfo instance) =>
    <String, dynamic>{
      'id': instance.id,
      'host': instance.host,
      'port': instance.port,
      'region': instance.region,
      'available': instance.available,
      'latency_ms': instance.latencyMs,
    };

TrustStatus _$TrustStatusFromJson(Map<String, dynamic> json) => TrustStatus(
      trustTier: json['trust_tier'] as String,
      peerCount: (json['peer_count'] as num).toInt(),
      peers: (json['peers'] as List<dynamic>?)
          ?.map((e) => TrustPeerInfo.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$TrustStatusToJson(TrustStatus instance) =>
    <String, dynamic>{
      'trust_tier': instance.trustTier,
      'peer_count': instance.peerCount,
      'peers': instance.peers,
    };

TrustPeerInfo _$TrustPeerInfoFromJson(Map<String, dynamic> json) =>
    TrustPeerInfo(
      pubkey: json['pubkey'] as String,
      trustLevel: json['trust_level'] as String,
      attestations: (json['attestations'] as num).toInt(),
      lastSeen: json['last_seen'] as String?,
    );

Map<String, dynamic> _$TrustPeerInfoToJson(TrustPeerInfo instance) =>
    <String, dynamic>{
      'pubkey': instance.pubkey,
      'trust_level': instance.trustLevel,
      'attestations': instance.attestations,
      'last_seen': instance.lastSeen,
    };

DdnsStatus _$DdnsStatusFromJson(Map<String, dynamic> json) => DdnsStatus(
      hasCredentials: json['has_credentials'] as bool? ?? false,
      lastIp: json['last_ip'] as String?,
      binaryHash: json['binary_hash'] as String?,
      binaryApproved: json['binary_approved'] as bool?,
      error: json['error'] as String?,
    );

Map<String, dynamic> _$DdnsStatusToJson(DdnsStatus instance) =>
    <String, dynamic>{
      'has_credentials': instance.hasCredentials,
      'last_ip': instance.lastIp,
      'binary_hash': instance.binaryHash,
      'binary_approved': instance.binaryApproved,
      'error': instance.error,
    };

EnrollmentEntry _$EnrollmentEntryFromJson(Map<String, dynamic> json) =>
    EnrollmentEntry(
      requestId: json['request_id'] as String,
      candidatePubkey: json['candidate_pubkey'] as String?,
      candidateServerId: json['candidate_server_id'] as String?,
      sponsorPubkey: json['sponsor_pubkey'] as String?,
      state: (json['state'] as num?)?.toInt() ?? 0,
      stateName: json['state_name'] as String?,
      createdAt: json['created_at'] as String?,
      timeoutAt: json['timeout_at'] as String?,
      retries: (json['retries'] as num?)?.toInt() ?? 0,
    );

Map<String, dynamic> _$EnrollmentEntryToJson(EnrollmentEntry instance) =>
    <String, dynamic>{
      'request_id': instance.requestId,
      'candidate_pubkey': instance.candidatePubkey,
      'candidate_server_id': instance.candidateServerId,
      'sponsor_pubkey': instance.sponsorPubkey,
      'state': instance.state,
      'state_name': instance.stateName,
      'created_at': instance.createdAt,
      'timeout_at': instance.timeoutAt,
      'retries': instance.retries,
    };

GovernanceProposal _$GovernanceProposalFromJson(Map<String, dynamic> json) =>
    GovernanceProposal(
      proposalId: json['proposal_id'] as String,
      proposerPubkey: json['proposer_pubkey'] as String?,
      parameter: (json['parameter'] as num).toInt(),
      newValue: json['new_value'] as String? ?? '',
      oldValue: json['old_value'] as String? ?? '',
      rationale: json['rationale'] as String? ?? '',
      createdAt: json['created_at'] as String?,
      expiresAt: json['expires_at'] as String?,
      state: (json['state'] as num?)?.toInt() ?? 0,
      stateName: json['state_name'] as String?,
    );

Map<String, dynamic> _$GovernanceProposalToJson(GovernanceProposal instance) =>
    <String, dynamic>{
      'proposal_id': instance.proposalId,
      'proposer_pubkey': instance.proposerPubkey,
      'parameter': instance.parameter,
      'new_value': instance.newValue,
      'old_value': instance.oldValue,
      'rationale': instance.rationale,
      'created_at': instance.createdAt,
      'expires_at': instance.expiresAt,
      'state': instance.state,
      'state_name': instance.stateName,
    };

ProposeResponse _$ProposeResponseFromJson(Map<String, dynamic> json) =>
    ProposeResponse(
      proposalId: json['proposal_id'] as String?,
      status: json['status'] as String,
      error: json['error'] as String?,
    );

Map<String, dynamic> _$ProposeResponseToJson(ProposeResponse instance) =>
    <String, dynamic>{
      'proposal_id': instance.proposalId,
      'status': instance.status,
      'error': instance.error,
    };

AttestationManifest _$AttestationManifestFromJson(Map<String, dynamic> json) =>
    AttestationManifest(
      version: json['version'] as String? ?? '',
      platform: json['platform'] as String?,
      binarySha256: json['binary_sha256'] as String? ?? '',
      timestamp: (json['timestamp'] as num?)?.toInt(),
    );

Map<String, dynamic> _$AttestationManifestToJson(
        AttestationManifest instance) =>
    <String, dynamic>{
      'version': instance.version,
      'platform': instance.platform,
      'binary_sha256': instance.binarySha256,
      'timestamp': instance.timestamp,
    };

HealthResponse _$HealthResponseFromJson(Map<String, dynamic> json) =>
    HealthResponse(
      status: json['status'] as String,
      service: json['service'] as String? ?? '',
      dnsBaseDomain: json['dns_base_domain'] as String?,
      ok: json['ok'] as bool?,
      error: json['error'] as String?,
    );

Map<String, dynamic> _$HealthResponseToJson(HealthResponse instance) =>
    <String, dynamic>{
      'status': instance.status,
      'service': instance.service,
      'dns_base_domain': instance.dnsBaseDomain,
      'ok': instance.ok,
      'error': instance.error,
    };

IdentityInfo _$IdentityInfoFromJson(Map<String, dynamic> json) => IdentityInfo(
      pubkey: json['pubkey'] as String,
      fingerprint: json['fingerprint'] as String?,
    );

Map<String, dynamic> _$IdentityInfoToJson(IdentityInfo instance) =>
    <String, dynamic>{
      'pubkey': instance.pubkey,
      'fingerprint': instance.fingerprint,
    };
