import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

Map<String, dynamic> _status({bool gpuOnline = true}) => {
      'running': true,
      'port': 13306,
      'scheme': 'http',
      'selection': {'target': 'auto', 'peer_key_set': false},
      'tls': {'state': 'waiting'},
      'urls': [
        {'node_id': 'self', 'device_name': 'phone', 'url': 'http://127.0.0.1:13306', 'self': true},
      ],
      'devices': [
        {'node_id': 'gpu', 'device_name': 'GPU tower', 'is_online': gpuOnline},
      ],
    };

void main() {
  test('a status read twice compares equal', () {
    expect(MeshPortStatus.fromJson(_status()), MeshPortStatus.fromJson(_status()));
    expect(MeshPortStatus.fromJson(_status()).hashCode,
        MeshPortStatus.fromJson(_status()).hashCode);
  });

  test('a device that went offline makes the status differ', () {
    expect(MeshPortStatus.fromJson(_status()),
        isNot(MeshPortStatus.fromJson(_status(gpuOnline: false))));
  });

  test('network devices compare by value', () {
    final json = {'node_id': 'gpu', 'device_name': 'GPU tower', 'can_connect': true};
    expect(NetworkDevice.fromJson(json), NetworkDevice.fromJson(json));
    expect(NetworkDevice.fromJson(json),
        isNot(NetworkDevice.fromJson({...json, 'device_name': 'tower'})));
  });
}
