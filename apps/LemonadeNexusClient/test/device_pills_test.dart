// Device pills: the labels a device list shows for a device, and the online
// state merged from the mesh peers. No native SDK library is needed.

import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
import 'package:nexus_client/src/state/cluster_keyring.dart';
import 'package:nexus_client/src/state/device_pills.dart';

List<DevicePillKind> _kinds(ClusterDevice d, {bool online = false}) =>
    devicePills(d, online: online).map((p) => p.kind).toList();

MeshPeer _peer(String nodeId, {required bool online, String? tunnelIp}) =>
    MeshPeer(
      nodeId: nodeId,
      meshPubkey: '',
      tunnelIp: tunnelIp,
      isOnline: online,
      keepalive: 25,
    );

void main() {
  group('devicePills', () {
    test('this device in its own Cluster: this device, client, online, admin', () {
      const d = ClusterDevice(
        nodeId: 'n1',
        hostname: 'laptop',
        needsKey: false,
        isThisDevice: true,
        isAdmin: true,
        groupRole: 'home',
      );
      expect(_kinds(d, online: true), [
        DevicePillKind.thisDevice,
        DevicePillKind.client,
        DevicePillKind.online,
        DevicePillKind.admin,
      ]);
    });

    test('an inference server is a server, never a client', () {
      const d = ClusterDevice(
          nodeId: 'n2', hostname: 'gpu', needsKey: false, isThisDevice: false, isInference: true);
      final kinds = _kinds(d);
      expect(kinds, contains(DevicePillKind.server));
      expect(kinds, isNot(contains(DevicePillKind.client)));
      expect(kinds, contains(DevicePillKind.offline));
      expect(kinds, isNot(contains(DevicePillKind.thisDevice)));
    });

    test('a device that joined from its own network is a member, not of another network', () {
      const d = ClusterDevice(
        nodeId: 'n3',
        hostname: 'friend',
        needsKey: false,
        isThisDevice: false,
        isMember: true,
        groupRole: 'home',
        networkName: 'Home',
        placedInCluster: false,
      );
      final kinds = _kinds(d);
      expect(kinds, contains(DevicePillKind.member));
      expect(kinds, isNot(contains(DevicePillKind.joinedNetwork)));
      expect(kinds, isNot(contains(DevicePillKind.otherNetwork)));
    });

    test('a device of a joined network names that network', () {
      const d = ClusterDevice(
        nodeId: 'n4',
        hostname: 'their-pc',
        needsKey: false,
        isThisDevice: false,
        groupRole: 'member',
        networkName: 'Office',
        inHomeNetwork: false,
        placedInCluster: false,
      );
      final pills = devicePills(d, online: false);
      final joined = pills.where((p) => p.kind == DevicePillKind.joinedNetwork);
      expect(joined, hasLength(1));
      expect(joined.single.label, contains('Office'));
      expect(pills.map((p) => p.kind), isNot(contains(DevicePillKind.otherNetwork)));
    });

    test('a joined network without a known name still gets the pill', () {
      const d = ClusterDevice(
          nodeId: 'n5', hostname: 'x', needsKey: false, isThisDevice: false, groupRole: 'member');
      expect(_kinds(d), contains(DevicePillKind.joinedNetwork));
    });

    test('a device of another own network gets an other-network pill', () {
      const d = ClusterDevice(
        nodeId: 'n6',
        hostname: 'nas',
        needsKey: false,
        isThisDevice: false,
        groupRole: 'home',
        networkName: 'Lab',
        inHomeNetwork: false,
        placedInCluster: false,
      );
      final pills = devicePills(d, online: true);
      final other = pills.singleWhere((p) => p.kind == DevicePillKind.otherNetwork);
      expect(other.label, 'Lab');
    });

    test('a device without the account key says so', () {
      const d = ClusterDevice(nodeId: 'n7', hostname: 'new', needsKey: true, isThisDevice: false);
      expect(_kinds(d).last, DevicePillKind.needsKey);
    });

    test('online and offline are exclusive', () {
      const d = ClusterDevice(nodeId: 'n8', hostname: 'h', needsKey: false, isThisDevice: false);
      expect(_kinds(d, online: true), contains(DevicePillKind.online));
      expect(_kinds(d, online: true), isNot(contains(DevicePillKind.offline)));
      expect(_kinds(d, online: false), contains(DevicePillKind.offline));
      expect(_kinds(d, online: false), isNot(contains(DevicePillKind.online)));
    });
  });

  group('isDeviceOnline', () {
    const other = ClusterDevice(
        nodeId: 'peer-1', hostname: 'p', needsKey: false, isThisDevice: false, tunnelIp: '10.64.0.7/32');
    const self = ClusterDevice(nodeId: 'me', hostname: 'm', needsKey: false, isThisDevice: true);

    test('this device follows the mesh state, not the peer list', () {
      expect(isDeviceOnline(self, peers: const [], meshUp: true), isTrue);
      expect(isDeviceOnline(self, peers: [_peer('me', online: true)], meshUp: false), isFalse);
    });

    test('another device follows its mesh peer, matched by node id', () {
      expect(isDeviceOnline(other, peers: [_peer('peer-1', online: true)], meshUp: true), isTrue);
      expect(isDeviceOnline(other, peers: [_peer('peer-1', online: false)], meshUp: true), isFalse);
    });

    test('a node id match wins over a tunnel address match', () {
      final peers = [
        _peer('someone-else', online: true, tunnelIp: '10.64.0.7'),
        _peer('peer-1', online: false),
      ];
      expect(isDeviceOnline(other, peers: peers, meshUp: true), isFalse);
    });

    test('without a node id match, the tunnel address matches with or without a prefix', () {
      expect(
          isDeviceOnline(other,
              peers: [_peer('different-id', online: true, tunnelIp: '10.64.0.7')], meshUp: true),
          isTrue);
      expect(
          isDeviceOnline(other,
              peers: [_peer('different-id', online: true, tunnelIp: '10.64.0.8/32')], meshUp: true),
          isFalse);
    });

    test('a device with no mesh peer is offline', () {
      expect(isDeviceOnline(other, peers: const [], meshUp: true), isFalse);
    });
  });
}
