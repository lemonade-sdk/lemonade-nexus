/// @title SDK Model Tests
/// @description Tests for SDK model classes and JSON serialization.
///
/// Coverage Target: 90%
/// Priority: High

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../fixtures/fixtures.dart';

void main() {
  group('AuthResponse Tests', () {
    test('should deserialize valid auth response', () {
      final json = jsonDecode(AuthFixtures.validAuthResponse) as Map<String, dynamic>;
      final response = AuthResponse.fromJson(json);

      expect(response.authenticated, isTrue);
      expect(response.userId, equals('user_test_123'));
      expect(response.sessionToken, equals('sess_abc123xyz'));
      expect(response.error, isNull);
    });

    test('should deserialize invalid auth response', () {
      final json = jsonDecode(AuthFixtures.invalidAuthResponse) as Map<String, dynamic>;
      final response = AuthResponse.fromJson(json);

      expect(response.authenticated, isFalse);
      expect(response.userId, isNull);
      expect(response.sessionToken, isNull);
      expect(response.error, equals('Invalid credentials'));
    });

    test('should serialize auth response', () {
      final response = ModelFactory.createAuthResponse(
        authenticated: true,
        userId: 'user_123',
        sessionToken: 'token_abc',
      );

      final json = response.toJson();

      expect(json['authenticated'], isTrue);
      expect(json['userId'], equals('user_123'));
      expect(json['sessionToken'], equals('token_abc'));
    });
  });

  group('TreeNode Tests', () {
    test('should deserialize root node', () {
      final json = jsonDecode(TreeFixtures.rootNode) as Map<String, dynamic>;
      final node = TreeNode.fromJson(json);

      expect(node.id, equals('root'));
      expect(node.parentId, equals(''));
      expect(node.nodeType, equals('root'));
      expect(node.ownerId, equals('owner_123'));
      expect(node.version, equals(1));
    });

    test('should deserialize customer node with extended fields', () {
      final json = jsonDecode(TreeFixtures.customerNode) as Map<String, dynamic>;
      final node = TreeNode.fromJson(json);

      expect(node.id, equals('customer_abc'));
      expect(node.hostname, equals('customer-host'));
      expect(node.tunnelIp, equals('10.0.0.5'));
      expect(node.region, equals('us-east'));
      expect(node.displayName, equals('customer-host'));
      expect(node.displayTunnelIp, equals('10.0.0.5'));
    });

    test('should deserialize endpoint node with pubkeys', () {
      final json = jsonDecode(TreeFixtures.endpointNode) as Map<String, dynamic>;
      final node = TreeNode.fromJson(json);

      expect(node.id, equals('endpoint_xyz'));
      expect(node.mgmtPubkey, equals('mgmt_pubkey_base64'));
      expect(node.wgPubkey, equals('wg_pubkey_base64'));
    });

    test('should deserialize tree node list', () {
      final json = jsonDecode(TreeFixtures.treeNodeList) as List<dynamic>;
      final nodes = json
          .cast<Map<String, dynamic>>()
          .map((j) => TreeNode.fromJson(j))
          .toList();

      expect(nodes.length, equals(2));
      expect(nodes[0].id, equals('customer_abc'));
      expect(nodes[1].id, equals('endpoint_xyz'));
    });

    test('displayName should use hostname when available', () {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: 'my-hostname',
      );

      expect(node.displayName, equals('my-hostname'));
    });

    test('displayName should fall back to id when no hostname', () {
      final node = ModelFactory.createTreeNode(
        id: 'test_node_123',
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: null,
      );

      expect(node.displayName, equals('test_node_123'));
    });

    test('displayTunnelIp should use tunnelIp field', () {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        tunnelIp: '10.0.0.5',
      );

      expect(node.displayTunnelIp, equals('10.0.0.5'));
    });

    test('displayTunnelIp should use data tunnel_ip as fallback', () {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'endpoint',
        tunnelIp: null,
        data: {'tunnel_ip': '10.0.0.10'},
      );

      expect(node.displayTunnelIp, equals('10.0.0.10'));
    });

    test('should serialize TreeNode', () {
      final node = ModelFactory.createTreeNode(
        id: 'test_node',
        parentId: 'root',
        nodeType: 'customer',
        hostname: 'test-host',
        tunnelIp: '10.0.0.5',
      );

      final json = node.toJson();

      expect(json['id'], equals('test_node'));
      expect(json['hostname'], equals('test-host'));
      expect(json['tunnelIp'], equals('10.0.0.5'));
    });
  });

  group('TunnelStatus Tests', () {
    test('should deserialize tunnel up status', () {
      final json = jsonDecode(TunnelFixtures.tunnelUp) as Map<String, dynamic>;
      final status = TunnelStatus.fromJson(json);

      expect(status.isUp, isTrue);
      expect(status.tunnelIp, equals('10.0.0.1'));
      expect(status.serverEndpoint, equals('server.example.com:9100'));
      expect(status.rxBytes, equals(1024000));
      expect(status.txBytes, equals(512000));
      expect(status.latencyMs, equals(25.5));
    });

    test('should deserialize tunnel down status', () {
      final json = jsonDecode(TunnelFixtures.tunnelDown) as Map<String, dynamic>;
      final status = TunnelStatus.fromJson(json);

      expect(status.isUp, isFalse);
      expect(status.tunnelIp, isNull);
      expect(status.serverEndpoint, isNull);
    });

    test('should serialize TunnelStatus', () {
      final status = ModelFactory.createTunnelStatus(
        isUp: true,
        tunnelIp: '10.0.0.1',
        rxBytes: 1000,
        txBytes: 500,
        latencyMs: 30.0,
      );

      final json = status.toJson();

      expect(json['isUp'], isTrue);
      expect(json['tunnelIp'], equals('10.0.0.1'));
      expect(json['rxBytes'], equals(1000));
    });
  });

  group('WgConfig Tests', () {
    test('should deserialize WireGuard config', () {
      final json = jsonDecode(TunnelFixtures.wgConfig) as Map<String, dynamic>;
      final config = WgConfig.fromJson(json);

      expect(config.privateKey, equals('wg_private_key_base64'));
      expect(config.publicKey, equals('wg_public_key_base64'));
      expect(config.tunnelIp, equals('10.0.0.1'));
      expect(config.listenPort, equals(51820));
      expect(config.keepalive, equals(25));
      expect(config.allowedIps, contains('10.0.0.0/24'));
    });

    test('should serialize WgConfig', () {
      final config = WgConfig(
        privateKey: 'priv_key',
        publicKey: 'pub_key',
        tunnelIp: '10.0.0.1',
        serverPublicKey: 'server_key',
        serverEndpoint: 'server:9100',
        dnsServer: '10.0.0.1',
        listenPort: 51820,
        allowedIps: ['10.0.0.0/24'],
        keepalive: 25,
      );

      final json = config.toJson();

      expect(json['privateKey'], equals('priv_key'));
      expect(json['listenPort'], equals(51820));
    });
  });

  group('WgKeypair Tests', () {
    test('should deserialize keypair', () {
      final json = jsonDecode(TunnelFixtures.wgKeypair) as Map<String, dynamic>;
      final keypair = WgKeypair.fromJson(json);

      expect(keypair.privateKey, equals('wg_private_key_base64'));
      expect(keypair.publicKey, equals('wg_public_key_base64'));
    });

    test('should serialize keypair', () {
      final keypair = WgKeypair(
        privateKey: 'priv',
        publicKey: 'pub',
      );

      final json = keypair.toJson();

      expect(json['privateKey'], equals('priv'));
      expect(json['publicKey'], equals('pub'));
    });
  });

  group('MeshStatus Tests', () {
    test('should deserialize mesh status with peers', () {
      final json = jsonDecode(MeshFixtures.meshStatus) as Map<String, dynamic>;
      final status = MeshStatus.fromJson(json);

      expect(status.isUp, isTrue);
      expect(status.tunnelIp, equals('10.0.0.1'));
      expect(status.peerCount, equals(5));
      expect(status.onlineCount, equals(3));
      expect(status.peers.length, equals(3));
    });

    test('should deserialize empty mesh status', () {
      final json = jsonDecode(MeshFixtures.emptyMeshStatus) as Map<String, dynamic>;
      final status = MeshStatus.fromJson(json);

      expect(status.isUp, isFalse);
      expect(status.peerCount, equals(0));
      expect(status.onlineCount, equals(0));
      expect(status.peers, isEmpty);
    });

    test('should serialize MeshStatus', () {
      final status = ModelFactory.createMeshStatus(
        isUp: true,
        peerCount: 5,
        onlineCount: 3,
      );

      final json = status.toJson();

      expect(json['isUp'], isTrue);
      expect(json['peerCount'], equals(5));
    });
  });

  group('MeshPeer Tests', () {
    test('should deserialize online peer with direct endpoint', () {
      final json = jsonDecode(MeshFixtures.meshStatus) as Map<String, dynamic>;
      final peers = (json['peers'] as List)
          .cast<Map<String, dynamic>>()
          .map((j) => MeshPeer.fromJson(j))
          .toList();

      final peer1 = peers[0];
      expect(peer1.nodeId, equals('peer_1'));
      expect(peer1.hostname, equals('peer1.local'));
      expect(peer1.isOnline, isTrue);
      expect(peer1.endpoint, equals('192.168.1.100:51820'));
      expect(peer1.relayEndpoint, isNull);
      expect(peer1.latencyMs, equals(15.5));
    });

    test('should deserialize peer with relay endpoint', () {
      final json = jsonDecode(MeshFixtures.meshStatus) as Map<String, dynamic>;
      final peers = (json['peers'] as List)
          .cast<Map<String, dynamic>>()
          .map((j) => MeshPeer.fromJson(j))
          .toList();

      final peer2 = peers[1];
      expect(peer2.nodeId, equals('peer_2'));
      expect(peer2.endpoint, isNull);
      expect(peer2.relayEndpoint, equals('relay.example.com:9101'));
    });

    test('should deserialize offline peer', () {
      final json = jsonDecode(MeshFixtures.meshStatus) as Map<String, dynamic>;
      final peers = (json['peers'] as List)
          .cast<Map<String, dynamic>>()
          .map((j) => MeshPeer.fromJson(j))
          .toList();

      final peer3 = peers[2];
      expect(peer3.isOnline, isFalse);
      expect(peer3.latencyMs, isNull);
    });

    test('should serialize MeshPeer', () {
      final peer = ModelFactory.createMeshPeer(
        nodeId: 'test_peer',
        hostname: 'test.local',
        isOnline: true,
        tunnelIp: '10.0.0.5',
        latencyMs: 25.0,
      );

      final json = peer.toJson();

      expect(json['nodeId'], equals('test_peer'));
      expect(json['hostname'], equals('test.local'));
      expect(json['isOnline'], isTrue);
    });
  });

  group('ServerInfo Tests', () {
    test('should deserialize server list', () {
      final json = jsonDecode(ServerFixtures.serverList) as List<dynamic>;
      final servers = json
          .cast<Map<String, dynamic>>()
          .map((j) => ServerInfo.fromJson(j))
          .toList();

      expect(servers.length, equals(3));
      expect(servers[0].id, equals('server_1'));
      expect(servers[0].region, equals('us-east'));
      expect(servers[0].available, isTrue);
      expect(servers[0].latencyMs, equals(25.5));
    });

    test('should handle server with null latency', () {
      final json = jsonDecode(ServerFixtures.serverList) as List<dynamic>;
      final servers = json
          .cast<Map<String, dynamic>>()
          .map((j) => ServerInfo.fromJson(j))
          .toList();

      final unhealthyServer = servers[2];
      expect(unhealthyServer.available, isFalse);
      expect(unhealthyServer.latencyMs, isNull);
    });

    test('should serialize ServerInfo', () {
      final server = ModelFactory.createServerInfo(
        id: 'test_server',
        host: 'test.example.com',
        port: 9100,
        region: 'test-region',
        available: true,
        latencyMs: 30.0,
      );

      final json = server.toJson();

      expect(json['id'], equals('test_server'));
      expect(json['host'], equals('test.example.com'));
      expect(json['port'], equals(9100));
    });
  });

  group('RelayInfo Tests', () {
    test('should deserialize relay list', () {
      final json = jsonDecode(RelayFixtures.relayList) as List<dynamic>;
      final relays = json
          .cast<Map<String, dynamic>>()
          .map((j) => RelayInfo.fromJson(j))
          .toList();

      expect(relays.length, equals(2));
      expect(relays[0].id, equals('relay_1'));
      expect(relays[0].region, equals('us-east'));
      expect(relays[0].available, isTrue);
    });

    test('should serialize RelayInfo', () {
      final relay = ModelFactory.createRelayInfo(
        id: 'test_relay',
        host: 'relay.test.com',
        port: 9101,
        region: 'test',
      );

      final json = relay.toJson();

      expect(json['id'], equals('test_relay'));
      expect(json['host'], equals('relay.test.com'));
    });
  });

  group('RelayTicket Tests', () {
    test('should deserialize relay ticket', () {
      final json = jsonDecode(RelayFixtures.relayTicket) as Map<String, dynamic>;
      final ticket = RelayTicket.fromJson(json);

      expect(ticket.ticket, equals('relay_ticket_abc123'));
      expect(ticket.peerId, equals('peer_123'));
      expect(ticket.relayId, equals('relay_1'));
    });

    test('should serialize RelayTicket', () {
      final ticket = RelayTicket(
        ticket: 'ticket_123',
        peerId: 'peer_456',
        relayId: 'relay_789',
        expiresAt: '2024-01-01T00:00:00Z',
      );

      final json = ticket.toJson();

      expect(json['ticket'], equals('ticket_123'));
    });
  });

  group('CertStatus Tests', () {
    test('should deserialize issued cert status', () {
      final json = jsonDecode(CertificateFixtures.certStatus) as Map<String, dynamic>;
      final status = CertStatus.fromJson(json);

      expect(status.domain, equals('example.com'));
      expect(status.isIssued, isTrue);
      expect(status.expiresAt, equals('2025-01-01T00:00:00Z'));
      expect(status.status, equals('active'));
    });

    test('should serialize CertStatus', () {
      final status = ModelFactory.createCertStatus(
        domain: 'test.com',
        isIssued: true,
        expiresAt: '2025-01-01T00:00:00Z',
      );

      final json = status.toJson();

      expect(json['domain'], equals('test.com'));
      expect(json['isIssued'], isTrue);
    });
  });

  group('CertBundle Tests', () {
    test('should deserialize cert bundle', () {
      final json = jsonDecode(CertificateFixtures.certBundle) as Map<String, dynamic>;
      final bundle = CertBundle.fromJson(json);

      expect(bundle.domain, equals('example.com'));
      expect(bundle.fullchainPem, contains('BEGIN CERTIFICATE'));
      expect(bundle.privkeyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('should serialize CertBundle', () {
      final bundle = CertBundle(
        domain: 'test.com',
        fullchainPem: '-----CERT-----',
        privkeyPem: '-----KEY-----',
        expiresAt: '2025-01-01T00:00:00Z',
      );

      final json = bundle.toJson();

      expect(json['domain'], equals('test.com'));
      expect(json['fullchainPem'], equals('-----CERT-----'));
    });
  });

  group('TrustStatus Tests', () {
    test('should deserialize trust status with peers', () {
      final json = jsonDecode(TrustFixtures.trustStatus) as Map<String, dynamic>;
      final status = TrustStatus.fromJson(json);

      expect(status.trustTier, equals('1'));
      expect(status.peerCount, equals(5));
      expect(status.peers?.length, equals(2));
    });

    test('should serialize TrustStatus', () {
      final status = ModelFactory.createTrustStatus(
        trustTier: '2',
        peerCount: 10,
      );

      final json = status.toJson();

      expect(json['trustTier'], equals('2'));
      expect(json['peerCount'], equals(10));
    });
  });

  group('TrustPeerInfo Tests', () {
    test('should deserialize trust peer', () {
      final json = jsonDecode(TrustFixtures.trustStatus) as Map<String, dynamic>;
      final peers = (json['peers'] as List)
          .cast<Map<String, dynamic>>()
          .map((j) => TrustPeerInfo.fromJson(j))
          .toList();

      expect(peers[0].pubkey, equals('trusted_peer_1'));
      expect(peers[0].trustLevel, equals('verified'));
      expect(peers[0].attestations, equals(3));
    });

    test('should serialize TrustPeerInfo', () {
      final peer = ModelFactory.createTrustPeerInfo(
        pubkey: 'test_peer',
        trustLevel: 'attested',
        attestations: 5,
      );

      final json = peer.toJson();

      expect(json['pubkey'], equals('test_peer'));
      expect(json['trustLevel'], equals('attested'));
    });
  });

  group('HealthResponse Tests', () {
    test('should deserialize healthy response', () {
      final json = jsonDecode(HealthFixtures.healthOk) as Map<String, dynamic>;
      final health = HealthResponse.fromJson(json);

      expect(health.status, equals('ok'));
      expect(health.version, equals('1.0.0'));
      expect(health.uptime, equals(86400));
    });

    test('should serialize HealthResponse', () {
      final health = ModelFactory.createHealthResponse(
        status: 'ok',
        version: '2.0.0',
        uptime: 10000,
      );

      final json = health.toJson();

      expect(json['status'], equals('ok'));
      expect(json['version'], equals('2.0.0'));
    });
  });

  group('ServiceStats Tests', () {
    test('should deserialize service stats', () {
      final json = jsonDecode(StatsFixtures.serviceStats) as Map<String, dynamic>;
      final stats = ServiceStats.fromJson(json);

      expect(stats.service, equals('lemonade-nexus'));
      expect(stats.peerCount, equals(10));
      expect(stats.privateApiEnabled, isTrue);
    });

    test('should serialize ServiceStats', () {
      final stats = ModelFactory.createServiceStats(
        service: 'test-service',
        peerCount: 5,
        privateApiEnabled: false,
      );

      final json = stats.toJson();

      expect(json['service'], equals('test-service'));
      expect(json['peerCount'], equals(5));
    });
  });

  group('IpAllocation Tests', () {
    test('should deserialize IP allocation', () {
      final json = jsonDecode(IpamFixtures.ipAllocation) as Map<String, dynamic>;
      final allocation = IpAllocation.fromJson(json);

      expect(allocation.nodeId, equals('node_123'));
      expect(allocation.blockType, equals('/24'));
      expect(allocation.allocatedIp, equals('10.0.0.5'));
      expect(allocation.subnet, equals('10.0.0.0/24'));
    });

    test('should serialize IpAllocation', () {
      final allocation = ModelFactory.createIpAllocation(
        nodeId: 'test_node',
        blockType: '/24',
        allocatedIp: '10.0.0.10',
      );

      final json = allocation.toJson();

      expect(json['nodeId'], equals('test_node'));
      expect(json['allocatedIp'], equals('10.0.0.10'));
    });
  });

  group('GroupMember Tests', () {
    test('should deserialize group members', () {
      final json = jsonDecode(GroupFixtures.groupMembers) as List<dynamic>;
      final members = json
          .cast<Map<String, dynamic>>()
          .map((j) => GroupMember.fromJson(j))
          .toList();

      expect(members.length, equals(2));
      expect(members[0].permissions, contains('read'));
      expect(members[0].permissions, contains('write'));
    });

    test('should serialize GroupMember', () {
      final member = ModelFactory.createGroupMember(
        nodeId: 'test_member',
        pubkey: 'test_pubkey',
        permissions: ['read', 'write', 'admin'],
      );

      final json = member.toJson();

      expect(json['nodeId'], equals('test_member'));
      expect(json['permissions'].length, equals(3));
    });
  });

  group('GroupJoinResponse Tests', () {
    test('should deserialize successful join response', () {
      final json = jsonDecode(GroupFixtures.groupJoinResponse) as Map<String, dynamic>;
      final response = GroupJoinResponse.fromJson(json);

      expect(response.success, isTrue);
      expect(response.endpointNodeId, equals('endpoint_123'));
      expect(response.tunnelIp, equals('10.0.0.10'));
      expect(response.error, isNull);
    });

    test('should serialize GroupJoinResponse', () {
      final response = GroupJoinResponse(
        success: true,
        endpointNodeId: 'endpoint_1',
        tunnelIp: '10.0.0.5',
      );

      final json = response.toJson();

      expect(json['success'], isTrue);
      expect(json['endpointNodeId'], equals('endpoint_1'));
    });
  });

  group('NodeAssignment Tests', () {
    test('should deserialize node assignment', () {
      final json = {
        'managementPubkey': 'mgmt_key_123',
        'permissions': ['read', 'write'],
      };
      final assignment = NodeAssignment.fromJson(json);

      expect(assignment.managementPubkey, equals('mgmt_key_123'));
      expect(assignment.permissions.length, equals(2));
    });

    test('should serialize NodeAssignment', () {
      final assignment = NodeAssignment(
        managementPubkey: 'mgmt_key',
        permissions: ['admin'],
      );

      final json = assignment.toJson();

      expect(json['managementPubkey'], equals('mgmt_key'));
      expect(json['permissions'].length, equals(1));
    });
  });

  group('TreeOperationResponse Tests', () {
    test('should deserialize successful operation', () {
      final json = {
        'success': true,
        'node': jsonDecode(TreeFixtures.rootNode),
        'error': null,
      };
      final response = TreeOperationResponse.fromJson(json);

      expect(response.success, isTrue);
      expect(response.node, isNotNull);
      expect(response.error, isNull);
    });

    test('should deserialize failed operation', () {
      final json = {
        'success': false,
        'node': null,
        'error': 'Operation failed',
      };
      final response = TreeOperationResponse.fromJson(json);

      expect(response.success, isFalse);
      expect(response.node, isNull);
      expect(response.error, equals('Operation failed'));
    });
  });

  group('NetworkJoinResponse Tests', () {
    test('should deserialize successful join', () {
      final json = {
        'success': true,
        'nodeId': 'node_123',
        'tunnelIp': '10.0.0.5',
        'sessionToken': 'sess_abc',
        'error': null,
      };
      final response = NetworkJoinResponse.fromJson(json);

      expect(response.success, isTrue);
      expect(response.nodeId, equals('node_123'));
      expect(response.tunnelIp, equals('10.0.0.5'));
    });
  });

  group('DdnsStatus Tests', () {
    test('should deserialize DDNS status', () {
      final json = {
        'isEnabled': true,
        'hostname': 'myhost.lemonade-nexus.com',
        'lastUpdated': '2024-01-01T00:00:00Z',
        'status': 'active',
      };
      final status = DdnsStatus.fromJson(json);

      expect(status.isEnabled, isTrue);
      expect(status.hostname, equals('myhost.lemonade-nexus.com'));
    });
  });

  group('EnrollmentEntry Tests', () {
    test('should deserialize enrollment entry', () {
      final json = {
        'id': 'enroll_123',
        'status': 'pending',
        'createdAt': '2024-01-01T00:00:00Z',
        'expiresAt': '2024-02-01T00:00:00Z',
      };
      final entry = EnrollmentEntry.fromJson(json);

      expect(entry.id, equals('enroll_123'));
      expect(entry.status, equals('pending'));
    });
  });

  group('GovernanceProposal Tests', () {
    test('should deserialize governance proposal', () {
      final json = {
        'id': 'prop_123',
        'parameter': 1,
        'currentValue': '100',
        'proposedValue': '200',
        'rationale': 'Increase limit',
        'proposerId': 'user_123',
        'votesFor': 10,
        'votesAgainst': 2,
        'status': 'active',
        'createdAt': '2024-01-01T00:00:00Z',
      };
      final proposal = GovernanceProposal.fromJson(json);

      expect(proposal.id, equals('prop_123'));
      expect(proposal.votesFor, equals(10));
      expect(proposal.votesAgainst, equals(2));
    });
  });

  group('ProposeResponse Tests', () {
    test('should deserialize successful proposal response', () {
      final json = {
        'proposalId': 'prop_123',
        'status': 'submitted',
        'error': null,
      };
      final response = ProposeResponse.fromJson(json);

      expect(response.proposalId, equals('prop_123'));
      expect(response.status, equals('submitted'));
    });
  });

  group('AttestationManifest Tests', () {
    test('should deserialize attestation manifest', () {
      final json = {
        'id': 'attest_123',
        'nodeId': 'node_456',
        'statement': 'I attest to this',
        'signature': 'sig_base64',
        'createdAt': '2024-01-01T00:00:00Z',
      };
      final manifest = AttestationManifest.fromJson(json);

      expect(manifest.id, equals('attest_123'));
      expect(manifest.signature, equals('sig_base64'));
    });
  });

  group('IdentityInfo Tests', () {
    test('should deserialize identity info', () {
      final json = {
        'pubkey': 'identity_pubkey_base64',
        'fingerprint': 'SHA256:abc123',
      };
      final info = IdentityInfo.fromJson(json);

      expect(info.pubkey, equals('identity_pubkey_base64'));
      expect(info.fingerprint, equals('SHA256:abc123'));
    });

    test('should handle null fingerprint', () {
      final json = {
        'pubkey': 'identity_pubkey_base64',
        'fingerprint': null,
      };
      final info = IdentityInfo.fromJson(json);

      expect(info.pubkey, equals('identity_pubkey_base64'));
      expect(info.fingerprint, isNull);
    });
  });
}
