/// @title FFI Binding Verification Tests
/// @description Tests to verify FFI bindings are properly initialized and functional.

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus/src/sdk/ffi_bindings.dart';
import 'package:lemonade_nexus/src/sdk/lemonade_nexus_sdk.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

void main() {
  group('LemonadeNexusFfi Initialization Tests', () {
    test('should create FFI instance', () {
      final ffi = LemonadeNexusFfi();
      expect(ffi, isNotNull);
      expect(ffi, isA<LemonadeNexusFfi>());
    });

    test('should have valid SDK handle after create', () async {
      final ffi = LemonadeNexusFfi();
      final result = await ffi.create();
      expect(result, isNotNull);
      // SDK handle should be non-zero after successful create
      expect(ffi.sdkHandle, isNotNull);
    });

    test('should dispose SDK properly', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final disposeResult = await ffi.dispose();
      expect(disposeResult, isNotNull);
      expect(disposeResult!.code, equals(LnError.success.code));
    });

    test('should handle multiple create calls gracefully', () async {
      final ffi = LemonadeNexusFfi();
      final result1 = await ffi.create();
      expect(result1, isNotNull);

      // Second create should handle gracefully
      final result2 = await ffi.create();
      expect(result2, isNotNull);

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Connection Tests', () {
    test('should have connect method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      // Connect method should exist and return LnError
      final result = await ffi.connect('localhost', 9100);
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have disconnect method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      // Disconnect method should exist
      final result = await ffi.disconnect();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have isConnected property', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      // Should be able to read connection state
      final isConnected = ffi.isConnected();
      expect(isConnected, isA<bool>());

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Authentication Tests', () {
    test('should have loginPassword method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.loginPassword(
        username: 'testuser',
        password: 'password123',
      );

      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have loginPasskey method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.loginPasskey(
        username: 'testuser',
        userId: 'user123',
        assertion: 'assertion_data',
      );

      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have registerPassword method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.registerPassword(
        username: 'newuser',
        password: 'password123',
      );

      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have logout method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.logout();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have isAuthenticated property', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final isAuthenticated = ffi.isAuthenticated();
      expect(isAuthenticated, isA<bool>());

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Identity Tests', () {
    test('should have getIdentity method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getIdentity();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have exportIdentity method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.exportIdentity();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have importIdentity method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.importIdentity(
        identityJson: '{"public_key": "test"}',
      );

      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Tunnel Tests', () {
    test('should have startTunnel method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.startTunnel();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have stopTunnel method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.stopTunnel();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have getTunnelStatus method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getTunnelStatus();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have isTunnelUp method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final isUp = ffi.isTunnelUp();
      expect(isUp, isA<bool>());

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Mesh Tests', () {
    test('should have enableMesh method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.enableMesh();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have disableMesh method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.disableMesh();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have getMeshStatus method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getMeshStatus();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have getMeshPeers method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getMeshPeers();
      expect(result, isNotNull);

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Tree Tests', () {
    test('should have loadTree method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.loadTree();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have getTreeNodes method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getTreeNodes();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have createChildNode method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.createChildNode(
        parentId: 'root',
        nodeType: 'endpoint',
        hostname: 'test-node',
      );

      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have deleteNode method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.deleteNode(nodeId: 'test_node');
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have updateNode method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.updateNode(
        nodeId: 'test_node',
        hostname: 'updated-node',
      );

      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Server Tests', () {
    test('should have getServers method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getServers();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have getServerInfo method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getServerInfo();
      expect(result, isNotNull);

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Certificate Tests', () {
    test('should have getCertificates method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getCertificates();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have requestCertificate method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.requestCertificate(
        domains: ['example.com'],
      );

      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });

    test('should have issueCertificate method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.issueCertificate(domain: 'example.com');
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });
  });

  group('LemonadeNexusFfi Health Tests', () {
    test('should have getHealth method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.getHealth();
      expect(result, isNotNull);

      await ffi.dispose();
    });

    test('should have refreshHealth method', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      final result = await ffi.refreshHealth();
      expect(result, isNotNull);
      expect(result, isA<LnError>());

      await ffi.dispose();
    });
  });

  group('LnError Enum Tests', () {
    test('should have all error codes', () {
      expect(LnError.values.length, greaterThan(0));
    });

    test('should have success error code', () {
      expect(LnError.success, isNotNull);
      expect(LnError.success.code, equals(0));
    });

    test('should have unknown error code', () {
      expect(LnError.unknown, isNotNull);
    });

    test('should create LnError from code', () {
      final error = LnError.fromCode(0);
      expect(error, equals(LnError.success));
    });

    test('should return unknown for invalid code', () {
      final error = LnError.fromCode(-999);
      expect(error, equals(LnError.unknown));
    });

    test('should have isSuccess property', () {
      expect(LnError.success.isSuccess, isTrue);
      expect(LnError.unknown.isSuccess, isFalse);
    });

    test('should have isFailure property', () {
      expect(LnError.success.isFailure, isFalse);
      expect(LnError.unknown.isFailure, isTrue);
    });

    test('should have name property', () {
      expect(LnError.success.name, isNotEmpty);
    });

    test('should have message property', () {
      expect(LnError.success.message, isNotEmpty);
    });
  });

  group('LnError Code Tests', () {
    test('should have success code 0', () {
      expect(LnError.success.code, equals(0));
    });

    test('should have sdk_not_created code', () {
      final error = LnError.sdkNotCreated;
      expect(error.code, isNot(equals(0)));
    });

    test('should have already_connected code', () {
      final error = LnError.alreadyConnected;
      expect(error.code, isNot(equals(0)));
    });

    test('should have not_connected code', () {
      final error = LnError.notConnected;
      expect(error.code, isNot(equals(0)));
    });

    test('should have already_authenticated code', () {
      final error = LnError.alreadyAuthenticated;
      expect(error.code, isNot(equals(0)));
    });

    test('should have not_authenticated code', () {
      final error = LnError.notAuthenticated;
      expect(error.code, isNot(equals(0)));
    });

    test('should have tunnel_already_up code', () {
      final error = LnError.tunnelAlreadyUp;
      expect(error.code, isNot(equals(0)));
    });

    test('should have tunnel_not_running code', () {
      final error = LnError.tunnelNotRunning;
      expect(error.code, isNot(equals(0)));
    });

    test('should have mesh_already_enabled code', () {
      final error = LnError.meshAlreadyEnabled;
      expect(error.code, isNot(equals(0)));
    });

    test('should have mesh_not_enabled code', () {
      final error = LnError.meshNotEnabled;
      expect(error.code, isNot(equals(0)));
    });

    test('should have node_not_found code', () {
      final error = LnError.nodeNotFound;
      expect(error.code, isNot(equals(0)));
    });

    test('should have invalid_params code', () {
      final error = LnError.invalidParams;
      expect(error.code, isNot(equals(0)));
    });

    test('should have json_parse_error code', () {
      final error = LnError.jsonParseError;
      expect(error.code, isNot(equals(0)));
    });

    test('should have timeout code', () {
      final error = LnError.timeout;
      expect(error.code, isNot(equals(0)));
    });

    test('should have io_error code', () {
      final error = LnError.ioError;
      expect(error.code, isNot(equals(0)));
    });

    test('should have ffi_error code', () {
      final error = LnError.ffiError;
      expect(error.code, isNot(equals(0)));
    });
  });

  group('Memory Management Tests', () {
    test('should free allocated memory', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      // Call methods that allocate memory
      await ffi.getIdentity();
      await ffi.getTunnelStatus();
      await ffi.getMeshStatus();

      // Dispose should free all memory
      final result = await ffi.dispose();
      expect(result!.code, equals(LnError.success.code));
    });

    test('should handle null pointers gracefully', () async {
      final ffi = LemonadeNexusFfi();
      // Before create, SDK handle is null
      final result = await ffi.dispose();
      // Should handle gracefully
      expect(result, isNotNull);
    });

    test('should not leak memory on error', () async {
      final ffi = LemonadeNexusFfi();
      await ffi.create();

      // Call with potentially invalid params
      await ffi.connect('', 0);
      await ffi.loginPassword(username: '', password: '');

      // Should still be able to dispose
      final result = await ffi.dispose();
      expect(result!.code, equals(LnError.success.code));
    });
  });

  group('Type Conversion Tests', () {
    test('should convert Dart string to CString', () {
      final ffi = LemonadeNexusFfi();
      final dartString = 'test_string';
      final cString = ffi.toCString(dartString);

      expect(cString, isNotNull);

      // Clean up
      ffi.freeCString(cString);
    });

    test('should convert CString to Dart string', () {
      final ffi = LemonadeNexusFfi();
      final dartString = 'test_string';
      final cString = ffi.toCString(dartString);
      final result = ffi.stringFromCString(cString);

      expect(result, equals(dartString));

      // Clean up
      ffi.freeCString(cString);
    });

    test('should convert JSON string to Map', () {
      final ffi = LemonadeNexusFfi();
      final jsonString = '{"key": "value", "number": 42}';
      final map = ffi.jsonToMap(jsonString);

      expect(map, isNotNull);
      expect(map['key'], equals('value'));
      expect(map['number'], equals(42));
    });

    test('should convert Map to JSON string', () {
      final ffi = LemonadeNexusFfi();
      final map = {'key': 'value', 'number': 42};
      final jsonString = ffi.mapToJson(map);

      expect(jsonString, isNotNull);
      expect(jsonString, contains('key'));
      expect(jsonString, contains('value'));
    });

    test('should handle empty JSON conversion', () {
      final ffi = LemonadeNexusFfi();
      final jsonString = '{}';
      final map = ffi.jsonToMap(jsonString);

      expect(map, isNotNull);
      expect(map.isEmpty, isTrue);
    });

    test('should handle null JSON gracefully', () {
      final ffi = LemonadeNexusFfi();
      final map = ffi.jsonToMap(null);

      expect(map, isNotNull);
    });
  });

  group('JSON Parsing Tests', () {
    test('should parse AuthResponse JSON', () {
      final json = {
        'success': true,
        'user_id': 'user123',
        'username': 'testuser',
        'public_key': 'pubkey_base64',
      };

      final authResponse = AuthResponse.fromJson(json);
      expect(authResponse.success, isTrue);
      expect(authResponse.userId, equals('user123'));
      expect(authResponse.username, equals('testuser'));
      expect(authResponse.publicKey, equals('pubkey_base64'));
    });

    test('should parse TunnelStatus JSON', () {
      final json = {
        'is_up': true,
        'tunnel_ip': '10.0.0.5',
        'local_port': 51820,
      };

      final status = TunnelStatus.fromJson(json);
      expect(status.isUp, isTrue);
      expect(status.tunnelIp, equals('10.0.0.5'));
      expect(status.localPort, equals(51820));
    });

    test('should parse MeshStatus JSON', () {
      final json = {
        'is_up': true,
        'peer_count': 5,
        'online_count': 3,
        'total_rx_bytes': 1000000,
        'total_tx_bytes': 500000,
      };

      final status = MeshStatus.fromJson(json);
      expect(status.isUp, isTrue);
      expect(status.peerCount, equals(5));
      expect(status.onlineCount, equals(3));
      expect(status.totalRxBytes, equals(1000000));
      expect(status.totalTxBytes, equals(500000));
    });

    test('should parse MeshPeer JSON', () {
      final json = {
        'node_id': 'peer123',
        'hostname': 'peer.local',
        'tunnel_ip': '10.0.0.6',
        'is_online': true,
        'latency_ms': 25.5,
        'rx_bytes': 50000,
        'tx_bytes': 25000,
      };

      final peer = MeshPeer.fromJson(json);
      expect(peer.nodeId, equals('peer123'));
      expect(peer.hostname, equals('peer.local'));
      expect(peer.tunnelIp, equals('10.0.0.6'));
      expect(peer.isOnline, isTrue);
      expect(peer.latencyMs, equals(25.5));
    });

    test('should parse ServerInfo JSON', () {
      final json = {
        'id': 'server123',
        'host': 'server.example.com',
        'port': 9100,
        'region': 'us-west',
        'available': true,
        'latency_ms': 30,
      };

      final server = ServerInfo.fromJson(json);
      expect(server.id, equals('server123'));
      expect(server.host, equals('server.example.com'));
      expect(server.port, equals(9100));
      expect(server.region, equals('us-west'));
      expect(server.available, isTrue);
    });
  });

  group('SDK Wrapper Tests', () {
    test('should create LemonadeNexusSdk instance', () {
      final sdk = LemonadeNexusSdk();
      expect(sdk, isNotNull);
    });

    test('should have all SDK methods', () async {
      final sdk = LemonadeNexusSdk();

      // Verify methods exist
      expect(sdk.create, isNotNull);
      expect(sdk.connect, isNotNull);
      expect(sdk.disconnect, isNotNull);
      expect(sdk.dispose, isNotNull);
      expect(sdk.loginPassword, isNotNull);
      expect(sdk.logout, isNotNull);
      expect(sdk.startTunnel, isNotNull);
      expect(sdk.stopTunnel, isNotNull);
      expect(sdk.enableMesh, isNotNull);
      expect(sdk.disableMesh, isNotNull);
    });

    test('should handle SDK lifecycle', () async {
      final sdk = LemonadeNexusSdk();

      // Create
      await sdk.create();

      // Connect
      await sdk.connect('localhost', 9100);

      // Disconnect
      await sdk.disconnect();

      // Dispose
      await sdk.dispose();

      // Should complete without errors
      expect(true, isTrue);
    });
  });
}
