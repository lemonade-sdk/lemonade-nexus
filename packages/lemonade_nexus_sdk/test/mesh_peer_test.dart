import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

void main() {
  test('a peer keeps the time the server last heard from it', () {
    final peer = MeshPeer.fromJson(const {
      'node_id': 'gpu',
      'mesh_pubkey': 'key',
      'is_online': false,
      'last_seen': 1793600000,
    });
    expect(peer.lastSeen, 1793600000);
    expect(MeshPeer.fromJson(peer.toJson()).lastSeen, 1793600000);
  });

  test('a peer the server never heard from reads 0', () {
    expect(MeshPeer.fromJson(const {'node_id': 'gpu', 'mesh_pubkey': 'key'}).lastSeen, 0);
  });
}
