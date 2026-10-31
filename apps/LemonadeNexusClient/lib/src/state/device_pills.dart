/// @title Device pills
/// @description Maps a listed device and its online state to the short labels
/// ("pills") the device lists show. Pure logic with no Flutter dependency, so
/// views choose the colors and tests check the mapping.
library;

import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';

import 'cluster_keyring.dart';

/// What a pill says about a device. Views map each kind to a color.
enum DevicePillKind {
  thisDevice,
  server,
  client,
  online,
  offline,
  member,
  joinedNetwork,
  otherNetwork,
  admin,
  needsKey,
}

/// One pill: a short [label] and a [tooltip] that explains it.
class DevicePill {
  final DevicePillKind kind;
  final String label;
  final String tooltip;

  const DevicePill(this.kind, this.label, this.tooltip);

  @override
  String toString() => 'DevicePill($kind, $label)';
}

/// The pills for [device], in display order. [online] comes from
/// [isDeviceOnline] because the device list does not carry online state.
List<DevicePill> devicePills(ClusterDevice device, {required bool online}) {
  final network = device.networkName;
  return [
    if (device.isThisDevice)
      const DevicePill(DevicePillKind.thisDevice, 'This device',
          'The device this app runs on.'),
    if (device.isInference)
      const DevicePill(DevicePillKind.server, 'Server',
          'A Lemonade inference server.')
    else
      const DevicePill(DevicePillKind.client, 'Client', 'A client device.'),
    if (online)
      const DevicePill(DevicePillKind.online, 'Online',
          'Reachable over the mesh now.')
    else
      const DevicePill(DevicePillKind.offline, 'Offline',
          'Not reachable over the mesh now.'),
    if (device.isMember)
      DevicePill(
          DevicePillKind.member,
          'Member',
          'Joined ${network.isEmpty ? 'this network' : '"$network"'} from its '
              'own network with an invite. It stays placed in its own network.'),
    if (device.inJoinedNetwork)
      DevicePill(
          DevicePillKind.joinedNetwork,
          network.isEmpty ? 'Joined network' : 'Joined: $network',
          'A device of ${network.isEmpty ? 'a network' : '"$network", a network'} '
              'this identity joined with an invite.')
    else if (!device.inHomeNetwork)
      DevicePill(
          DevicePillKind.otherNetwork,
          network.isEmpty ? 'Other network' : network,
          'A device of another network that this identity owns.'),
    if (device.isAdmin)
      DevicePill(
          DevicePillKind.admin,
          'Admin',
          'Administers ${network.isEmpty ? 'this network' : '"$network"'}: it '
              'can change access in the group and on its devices.'),
    if (device.needsKey)
      const DevicePill(DevicePillKind.needsKey, 'Needs key',
          'Cannot read Cluster data until a device shares the account key.'),
  ];
}

/// Whether [device] is online. The device lists carry no online state, so it
/// comes from the mesh peer list: this device is online while the mesh is up
/// ([meshUp]); another device is online when its mesh peer is. A peer is
/// matched by node id, then by tunnel address.
bool isDeviceOnline(ClusterDevice device,
    {required Iterable<MeshPeer> peers, required bool meshUp}) {
  if (device.isThisDevice) return meshUp;
  final ip = _bareAddress(device.tunnelIp);
  for (final peer in peers) {
    if (peer.nodeId == device.nodeId) return peer.isOnline;
  }
  if (ip.isEmpty) return false;
  for (final peer in peers) {
    if (_bareAddress(peer.tunnelIp) == ip) return peer.isOnline;
  }
  return false;
}

/// "10.0.0.5/32" and "10.0.0.5" name the same tunnel address.
String _bareAddress(String? address) {
  if (address == null) return '';
  final slash = address.indexOf('/');
  return (slash < 0 ? address : address.substring(0, slash)).trim();
}
