/// @title Test Fixtures
/// @description Pre-built test data for Lemonade Nexus tests.
///
/// Contains JSON fixtures and model instances for testing.

import 'dart:convert';

import 'package:lemonade_nexus/src/sdk/models.dart';

// =========================================================================
// JSON Fixtures
// =========================================================================

/// JSON fixture for authentication responses.
class AuthFixtures {
  static const String validAuthResponse = '''
  {
    "authenticated": true,
    "userId": "user_test_123",
    "sessionToken": "sess_abc123xyz",
    "error": null
  }
  ''';

  static const String invalidAuthResponse = '''
  {
    "authenticated": false,
    "userId": null,
    "sessionToken": null,
    "error": "Invalid credentials"
  }
  ''';

  static const String emptyAuthResponse = '''
  {
    "authenticated": false,
    "userId": null,
    "sessionToken": null,
    "error": null
  }
  ''';
}

/// JSON fixture for tree node responses.
class TreeFixtures {
  static const String rootNode = '''
  {
    "id": "root",
    "parentId": "",
    "nodeType": "root",
    "ownerId": "owner_123",
    "data": {},
    "version": 1,
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z"
  }
  ''';

  static const String customerNode = '''
  {
    "id": "customer_abc",
    "parentId": "root",
    "nodeType": "customer",
    "ownerId": "owner_123",
    "data": {
      "name": "Test Customer"
    },
    "version": 1,
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z",
    "hostname": "customer-host",
    "tunnelIp": "10.0.0.5",
    "region": "us-east"
  }
  ''';

  static const String endpointNode = '''
  {
    "id": "endpoint_xyz",
    "parentId": "customer_abc",
    "nodeType": "endpoint",
    "ownerId": "owner_123",
    "data": {
      "name": "Test Endpoint"
    },
    "version": 1,
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z",
    "hostname": "endpoint-host",
    "tunnelIp": "10.0.0.10",
    "mgmtPubkey": "mgmt_pubkey_base64",
    "wgPubkey": "wg_pubkey_base64"
  }
  ''';

  static const String treeNodeList = '''
  [
    {
      "id": "customer_abc",
      "parentId": "root",
      "nodeType": "customer",
      "ownerId": "owner_123",
      "data": {"name": "Test Customer"},
      "version": 1,
      "createdAt": "2024-01-01T00:00:00Z",
      "updatedAt": "2024-01-01T00:00:00Z",
      "hostname": "customer-host",
      "tunnelIp": "10.0.0.5"
    },
    {
      "id": "endpoint_xyz",
      "parentId": "customer_abc",
      "nodeType": "endpoint",
      "ownerId": "owner_123",
      "data": {"name": "Test Endpoint"},
      "version": 1,
      "createdAt": "2024-01-01T00:00:00Z",
      "updatedAt": "2024-01-01T00:00:00Z",
      "hostname": "endpoint-host",
      "tunnelIp": "10.0.0.10"
    }
  ]
  ''';
}

/// JSON fixture for WireGuard tunnel responses.
class TunnelFixtures {
  static const String tunnelUp = '''
  {
    "isUp": true,
    "tunnelIp": "10.0.0.1",
    "serverEndpoint": "server.example.com:9100",
    "lastHandshake": "2024-01-01T12:00:00Z",
    "rxBytes": 1024000,
    "txBytes": 512000,
    "latencyMs": 25.5
  }
  ''';

  static const String tunnelDown = '''
  {
    "isUp": false,
    "tunnelIp": null,
    "serverEndpoint": null,
    "lastHandshake": null,
    "rxBytes": 0,
    "txBytes": 0,
    "latencyMs": null
  }
  ''';

  static const String wgConfig = '''
  {
    "privateKey": "wg_private_key_base64",
    "publicKey": "wg_public_key_base64",
    "tunnelIp": "10.0.0.1",
    "serverPublicKey": "server_pubkey_base64",
    "serverEndpoint": "server.example.com:9100",
    "dnsServer": "10.0.0.1",
    "listenPort": 51820,
    "allowedIps": ["10.0.0.0/24"],
    "keepalive": 25
  }
  ''';

  static const String wgKeypair = '''
  {
    "privateKey": "wg_private_key_base64",
    "publicKey": "wg_public_key_base64"
  }
  ''';
}

/// JSON fixture for mesh peer responses.
class MeshFixtures {
  static const String meshStatus = '''
  {
    "isUp": true,
    "tunnelIp": "10.0.0.1",
    "peerCount": 5,
    "onlineCount": 3,
    "totalRxBytes": 10485760,
    "totalTxBytes": 5242880,
    "peers": [
      {
        "nodeId": "peer_1",
        "hostname": "peer1.local",
        "wgPubkey": "peer1_pubkey_base64",
        "tunnelIp": "10.0.0.2",
        "privateSubnet": "10.1.0.0/24",
        "endpoint": "192.168.1.100:51820",
        "relayEndpoint": null,
        "isOnline": true,
        "lastHandshake": 1704110400,
        "rxBytes": 1024000,
        "txBytes": 512000,
        "latencyMs": 15.5,
        "keepalive": 25
      },
      {
        "nodeId": "peer_2",
        "hostname": "peer2.local",
        "wgPubkey": "peer2_pubkey_base64",
        "tunnelIp": "10.0.0.3",
        "privateSubnet": "10.1.1.0/24",
        "endpoint": null,
        "relayEndpoint": "relay.example.com:9101",
        "isOnline": true,
        "lastHandshake": 1704110300,
        "rxBytes": 2048000,
        "txBytes": 1024000,
        "latencyMs": 45.2,
        "keepalive": 25
      },
      {
        "nodeId": "peer_3",
        "hostname": "peer3.local",
        "wgPubkey": "peer3_pubkey_base64",
        "tunnelIp": "10.0.0.4",
        "privateSubnet": "10.1.2.0/24",
        "endpoint": "192.168.1.102:51820",
        "relayEndpoint": null,
        "isOnline": false,
        "lastHandshake": 1704100000,
        "rxBytes": 512000,
        "txBytes": 256000,
        "latencyMs": null,
        "keepalive": 25
      }
    ]
  }
  ''';

  static const String emptyMeshStatus = '''
  {
    "isUp": false,
    "tunnelIp": null,
    "peerCount": 0,
    "onlineCount": 0,
    "totalRxBytes": 0,
    "totalTxBytes": 0,
    "peers": []
  }
  ''';
}

/// JSON fixture for server responses.
class ServerFixtures {
  static const String serverList = '''
  [
    {
      "id": "server_1",
      "host": "us-east-1.lemonade-nexus.com",
      "port": 9100,
      "region": "us-east",
      "available": true,
      "latencyMs": 25.5
    },
    {
      "id": "server_2",
      "host": "us-west-1.lemonade-nexus.com",
      "port": 9100,
      "region": "us-west",
      "available": true,
      "latencyMs": 45.2
    },
    {
      "id": "server_3",
      "host": "eu-central-1.lemonade-nexus.com",
      "port": 9100,
      "region": "eu-central",
      "available": false,
      "latencyMs": null
    }
  ]
  ''';
}

/// JSON fixture for relay responses.
class RelayFixtures {
  static const String relayList = '''
  [
    {
      "id": "relay_1",
      "host": "relay-us-east.lemonade-nexus.com",
      "port": 9101,
      "region": "us-east",
      "available": true,
      "latencyMs": 30.0
    },
    {
      "id": "relay_2",
      "host": "relay-eu-west.lemonade-nexus.com",
      "port": 9101,
      "region": "eu-west",
      "available": true,
      "latencyMs": 55.0
    }
  ]
  ''';

  static const String relayTicket = '''
  {
    "ticket": "relay_ticket_abc123",
    "peerId": "peer_123",
    "relayId": "relay_1",
    "expiresAt": "2024-01-01T13:00:00Z"
  }
  ''';
}

/// JSON fixture for certificate responses.
class CertificateFixtures {
  static const String certStatus = '''
  {
    "domain": "example.com",
    "isIssued": true,
    "expiresAt": "2025-01-01T00:00:00Z",
    "issuedAt": "2024-01-01T00:00:00Z",
    "status": "active"
  }
  ''';

  static const String certBundle = '''
  {
    "domain": "example.com",
    "fullchainPem": "-----BEGIN CERTIFICATE-----\\nMIIC...\\n-----END CERTIFICATE-----",
    "privkeyPem": "-----BEGIN PRIVATE KEY-----\\nMIIE...\\n-----END PRIVATE KEY-----",
    "expiresAt": "2025-01-01T00:00:00Z"
  }
  ''';
}

/// JSON fixture for trust responses.
class TrustFixtures {
  static const String trustStatus = '''
  {
    "trustTier": 1,
    "peerCount": 5,
    "peers": [
      {
        "pubkey": "trusted_peer_1",
        "trustLevel": "verified",
        "attestations": 3,
        "lastSeen": "2024-01-01T12:00:00Z"
      },
      {
        "pubkey": "trusted_peer_2",
        "trustLevel": "attested",
        "attestations": 2,
        "lastSeen": "2024-01-01T11:00:00Z"
      }
    ]
  }
  ''';
}

/// JSON fixture for health responses.
class HealthFixtures {
  static const String healthOk = '''
  {
    "status": "ok",
    "version": "1.0.0",
    "uptime": 86400
  }
  ''';

  static const String healthError = '''
  {
    "status": "error",
    "version": "unknown",
    "uptime": 0
  }
  ''';
}

/// JSON fixture for stats responses.
class StatsFixtures {
  static const String serviceStats = '''
  {
    "service": "lemonade-nexus",
    "peerCount": 10,
    "privateApiEnabled": true
  }
  ''';
}

/// JSON fixture for IPAM responses.
class IpamFixtures {
  static const String ipAllocation = '''
  {
    "nodeId": "node_123",
    "blockType": "/24",
    "allocatedIp": "10.0.0.5",
    "subnet": "10.0.0.0/24",
    "allocatedAt": "2024-01-01T00:00:00Z"
  }
  ''';
}

/// JSON fixture for group membership responses.
class GroupFixtures {
  static const String groupMembers = '''
  [
    {
      "nodeId": "member_1",
      "pubkey": "pubkey_1_base64",
      "permissions": ["read", "write"],
      "joinedAt": "2024-01-01T00:00:00Z"
    },
    {
      "nodeId": "member_2",
      "pubkey": "pubkey_2_base64",
      "permissions": ["read"],
      "joinedAt": "2024-01-02T00:00:00Z"
    }
  ]
  ''';

  static const String groupJoinResponse = '''
  {
    "success": true,
    "endpointNodeId": "endpoint_123",
    "tunnelIp": "10.0.0.10",
    "error": null
  }
  ''';
}

// =========================================================================
// Model Instance Factories
// =========================================================================

/// Factory class for creating model instances for testing.
class ModelFactory {
  /// Create a test AuthResponse.
  static AuthResponse createAuthResponse({
    bool authenticated = true,
    String? userId,
    String? sessionToken,
    String? error,
  }) {
    return AuthResponse(
      authenticated: authenticated,
      userId: userId,
      sessionToken: sessionToken,
      error: error,
    );
  }

  /// Create a test TreeNode.
  static TreeNode createTreeNode({
    required String id,
    required String parentId,
    required String nodeType,
    String? hostname,
    String? tunnelIp,
    Map<String, dynamic>? data,
  }) {
    return TreeNode(
      id: id,
      parentId: parentId,
      nodeType: nodeType,
      ownerId: 'owner_test',
      data: data ?? {},
      version: 1,
      createdAt: DateTime.now().toIso8601String(),
      updatedAt: DateTime.now().toIso8601String(),
      hostname: hostname,
      tunnelIp: tunnelIp,
    );
  }

  /// Create a test TunnelStatus.
  static TunnelStatus createTunnelStatus({
    bool isUp = false,
    String? tunnelIp,
    String? serverEndpoint,
    int? rxBytes,
    int? txBytes,
    double? latencyMs,
  }) {
    return TunnelStatus(
      isUp: isUp,
      tunnelIp: tunnelIp,
      serverEndpoint: serverEndpoint,
      rxBytes: rxBytes,
      txBytes: txBytes,
      latencyMs: latencyMs,
    );
  }

  /// Create a test MeshPeer.
  static MeshPeer createMeshPeer({
    required String nodeId,
    String? hostname,
    bool isOnline = true,
    String? tunnelIp,
    double? latencyMs,
  }) {
    return MeshPeer(
      nodeId: nodeId,
      hostname: hostname,
      wgPubkey: 'pubkey_$nodeId',
      tunnelIp: tunnelIp,
      isOnline: isOnline,
      rxBytes: 1024,
      txBytes: 512,
      latencyMs: latencyMs,
      keepalive: 25,
    );
  }

  /// Create a test MeshStatus.
  static MeshStatus createMeshStatus({
    bool isUp = false,
    String? tunnelIp,
    int peerCount = 0,
    int onlineCount = 0,
    List<MeshPeer>? peers,
  }) {
    return MeshStatus(
      isUp: isUp,
      tunnelIp: tunnelIp,
      peerCount: peerCount,
      onlineCount: onlineCount,
      totalRxBytes: 1024,
      totalTxBytes: 512,
      peers: peers ?? [],
    );
  }

  /// Create a test ServerInfo.
  static ServerInfo createServerInfo({
    required String id,
    required String host,
    int port = 9100,
    String region = 'test',
    bool available = true,
    double? latencyMs,
  }) {
    return ServerInfo(
      id: id,
      host: host,
      port: port,
      region: region,
      available: available,
      latencyMs: latencyMs,
    );
  }

  /// Create a test RelayInfo.
  static RelayInfo createRelayInfo({
    required String id,
    required String host,
    int port = 9101,
    String region = 'test',
    bool available = true,
    double? latencyMs,
  }) {
    return RelayInfo(
      id: id,
      host: host,
      port: port,
      region: region,
      available: available,
      latencyMs: latencyMs,
    );
  }

  /// Create a test CertStatus.
  static CertStatus createCertStatus({
    required String domain,
    bool isIssued = false,
    String? expiresAt,
    String? issuedAt,
    String? status,
  }) {
    return CertStatus(
      domain: domain,
      isIssued: isIssued,
      expiresAt: expiresAt,
      issuedAt: issuedAt,
      status: status,
    );
  }

  /// Create a test TrustStatus.
  static TrustStatus createTrustStatus({
    String trustTier = '1',
    int peerCount = 0,
    List<TrustPeerInfo>? peers,
  }) {
    return TrustStatus(
      trustTier: trustTier,
      peerCount: peerCount,
      peers: peers,
    );
  }

  /// Create a test TrustPeerInfo.
  static TrustPeerInfo createTrustPeerInfo({
    required String pubkey,
    String trustLevel = 'unknown',
    int attestations = 0,
    String? lastSeen,
  }) {
    return TrustPeerInfo(
      pubkey: pubkey,
      trustLevel: trustLevel,
      attestations: attestations,
      lastSeen: lastSeen,
    );
  }

  /// Create a test HealthResponse.
  static HealthResponse createHealthResponse({
    String status = 'ok',
    String version = '1.0.0',
    int uptime = 1000,
  }) {
    return HealthResponse(
      status: status,
      version: version,
      uptime: uptime,
    );
  }

  /// Create a test ServiceStats.
  static ServiceStats createServiceStats({
    String service = 'lemonade-nexus',
    int peerCount = 0,
    bool privateApiEnabled = false,
  }) {
    return ServiceStats(
      service: service,
      peerCount: peerCount,
      privateApiEnabled: privateApiEnabled,
    );
  }

  /// Create a test IpAllocation.
  static IpAllocation createIpAllocation({
    required String nodeId,
    String blockType = '/24',
    String? allocatedIp,
    String? subnet,
  }) {
    return IpAllocation(
      nodeId: nodeId,
      blockType: blockType,
      allocatedIp: allocatedIp ?? '10.0.0.1',
      subnet: subnet,
      allocatedAt: DateTime.now().toIso8601String(),
    );
  }

  /// Create a test GroupMember.
  static GroupMember createGroupMember({
    required String nodeId,
    required String pubkey,
    List<String>? permissions,
  }) {
    return GroupMember(
      nodeId: nodeId,
      pubkey: pubkey,
      permissions: permissions ?? ['read'],
      joinedAt: DateTime.now().toIso8601String(),
    );
  }
}
