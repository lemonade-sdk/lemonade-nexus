# Command: Create Model Classes

## Description
Create Dart model classes for JSON responses from C SDK.

## Purpose
Type-safe data models for API responses.

## Model Categories

### Identity Models
```dart
@JsonSerializable()
class Identity {
  final String publicKey;
  final String? privateKey;
  final DateTime? createdAt;

  Identity({required this.publicKey, this.privateKey, this.createdAt});

  factory Identity.fromJson(Map<String, dynamic> json) => _$IdentityFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityToJson(this);
}
```

### Auth Models
```dart
@JsonSerializable()
class AuthResult {
  final bool authenticated;
  final User? user;
  final String? sessionToken;
  final String? error;

  AuthResult({required this.authenticated, this.user, this.sessionToken, this.error});

  factory AuthResult.fromJson(Map<String, dynamic> json) => _$AuthResultFromJson(json);
}

@JsonSerializable()
class User {
  final String id;
  final String username;
  final String? email;

  User({required this.id, required this.username, this.email});

  factory User.fromJson(Map<String, dynamic> json) => _$UserFromJson(json);
}
```

### Tunnel Models
```dart
enum TunnelStatus { disconnected, connecting, connected, error }

@JsonSerializable()
class TunnelStatusModel {
  final TunnelStatus status;
  final String? tunnelIp;
  final String? serverEndpoint;
  final int rxBytes;
  final int txBytes;
  final double? latency;

  TunnelStatusModel({
    required this.status,
    this.tunnelIp,
    this.serverEndpoint,
    this.rxBytes = 0,
    this.txBytes = 0,
    this.latency,
  });

  factory TunnelStatusModel.fromJson(Map<String, dynamic> json) =>
      _$TunnelStatusModelFromJson(json);
}
```

### Peer Models
```dart
@JsonSerializable()
class Peer {
  final String nodeId;
  final String hostname;
  final String wgPubkey;
  final String? tunnelIp;
  final String? privateSubnet;
  final String? endpoint;
  final bool isOnline;
  final DateTime? lastHandshake;
  final int rxBytes;
  final int txBytes;
  final double? latency;

  Peer({
    required this.nodeId,
    required this.hostname,
    required this.wgPubkey,
    this.tunnelIp,
    this.privateSubnet,
    this.endpoint,
    required this.isOnline,
    this.lastHandshake,
    this.rxBytes = 0,
    this.txBytes = 0,
    this.latency,
  });

  factory Peer.fromJson(Map<String, dynamic> json) => _$PeerFromJson(json);
}
```

## Process
1. Analyze JSON response structures
2. Create Dart class definitions
3. Add JsonSerializable annotations
4. Run build_runner to generate code

## Output
- Model classes in `lib/src/sdk/types.dart`
- Generated `.g.dart` files
- Type converters for enums
