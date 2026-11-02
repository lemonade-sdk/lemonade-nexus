import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

void main() {
  test("a peer keeps the server's online bit apart from its path", () {
    final peer = MeshPeer.fromJson(const {
      'node_id': 'gpu',
      'mesh_pubkey': 'key',
      'is_online': false,
      'server_online': true,
    });
    expect(peer.isOnline, isFalse);
    expect(peer.serverOnline, isTrue);
    expect(MeshPeer.fromJson(peer.toJson()).serverOnline, isTrue);
  });

  test('an SDK without the bit reads offline at the server', () {
    expect(MeshPeer.fromJson(const {'node_id': 'gpu', 'mesh_pubkey': 'key'}).serverOnline, isFalse);
  });
}
