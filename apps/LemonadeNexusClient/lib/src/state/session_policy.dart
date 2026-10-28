/// Pure session decisions for [AppNotifier]: which errors end a session,
/// how the Tier 1 epoch floor moves, and how a device is named. They take
/// plain values so unit tests cover them without the native SDK.
library;

import '../sdk/sdk.dart';

/// True only when the network refused the credentials. The SDK maps HTTP 401
/// and 403 to [LnError.auth]; every other outcome keeps the account and the
/// app retries: an unreachable server, a timeout, or a 5xx answer
/// ([LnError.connect]), a local failure ([LnError.internal]), and the SDK's
/// Tier 1 errors ("no verified Tier 1 server is reachable", "the session's
/// server is no longer a verified Tier 1 server").
///
/// `ln_join_network` answers [LnError.auth] for every failure, unreachable
/// servers included, so a join result is never passed here.
bool isAuthenticationRefusal(Object error) =>
    error is SdkException && error.error == LnError.auth;

/// The Tier 1 epoch floor to keep after the SDK reported [reported]. The floor
/// grows and never shrinks; a missing or malformed value keeps [stored].
int nextTier1MinEpoch(int stored, Object? reported) {
  final int? epoch = switch (reported) {
    num n => n.toInt(),
    String s => int.tryParse(s),
    _ => null,
  };
  if (epoch == null || epoch <= stored) return stored;
  return epoch;
}

/// Longest device name the server accepts.
const int maxDeviceNameLength = 128;

/// Device name when the machine reports no usable host name.
const String fallbackDeviceName = 'My device';

/// The machine's host name as a device name: surrounding white space, a
/// trailing ".local" (mDNS) and trailing dots removed, then cut to
/// [maxDeviceNameLength]. Returns [fallbackDeviceName] when nothing is left.
String machineDeviceName(String hostName) {
  var name = hostName.trim();
  const localSuffix = '.local';
  if (name.length > localSuffix.length &&
      name.toLowerCase().endsWith(localSuffix)) {
    name = name.substring(0, name.length - localSuffix.length);
  }
  while (name.endsWith('.')) {
    name = name.substring(0, name.length - 1);
  }
  if (name.length > maxDeviceNameLength) {
    name = name.substring(0, maxDeviceNameLength);
  }
  return name.isEmpty ? fallbackDeviceName : name;
}

/// The name a new endpoint carries until someone names it: the server sets
/// "endpoint-" and the first 8 characters of the node id.
String serverDefaultDeviceName(String nodeId) =>
    'endpoint-${nodeId.length > 8 ? nodeId.substring(0, 8) : nodeId}';

/// The name to give this device's endpoint after a join, or null when its
/// current name stays. Only a missing name or the server default is replaced
/// by [machineName]; a name set earlier, in this app or another client, is
/// never changed.
String? deviceNameToApply({
  required String? currentHostname,
  required String nodeId,
  required String machineName,
}) {
  final current = currentHostname?.trim() ?? '';
  if (current.isNotEmpty && current != serverDefaultDeviceName(nodeId)) {
    return null;
  }
  if (current == machineName) return null;
  return machineName;
}
