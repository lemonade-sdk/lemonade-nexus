import 'package:flutter_test/flutter_test.dart';
import 'package:nexus_client/src/sdk/models.dart';
import 'package:nexus_client/src/state/cluster_keyring.dart';

void main() {
  test('canonicalPrincipal matches both base64 spellings of one key', () {
    const std = 'ed25519:ab+c/d0=';
    const urlSafe = 'ed25519:ab-c_d0';
    expect(canonicalPrincipal(std), canonicalPrincipal(urlSafe));
    expect(canonicalPrincipal('ab+c/d0='), canonicalPrincipal(urlSafe));
    expect(canonicalPrincipal(std) == canonicalPrincipal('ed25519:ab+c/d1='), isFalse);
  });

  test('ServerInfo keeps the identity key and last-seen time', () {
    final s = ServerInfo.fromJson({
      'endpoint': '192.102.139.3:9102',
      'pubkey': 'QKXlF/rmQ2AM',
      'http_port': 9100,
      'last_seen': 1792700000,
      'healthy': true,
    });
    expect(s.host, '192.102.139.3');
    expect(s.port, 9100);
    expect(s.endpoint, '192.102.139.3:9102');
    expect(s.pubkey, 'QKXlF/rmQ2AM');
    expect(s.lastSeen, 1792700000);
    expect(s.available, isTrue);
  });
}
