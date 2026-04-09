/// @title Lemonade Nexus SDK
/// @description High-level Dart API for the Lemonade Nexus Client SDK.
///
/// This class provides a type-safe, async Dart API wrapping the
/// low-level FFI bindings. It handles memory management, JSON parsing,
/// and error handling automatically.

import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';

import 'ffi_bindings.dart';
import 'models.dart';

/// Exception thrown when an SDK operation fails.
class SdkException implements Exception {
  final LnError error;
  final String? message;
  final String? rawJson;

  SdkException(this.error, {this.message, this.rawJson});

  @override
  String toString() {
    return 'SdkException(${error.name}): ${message ?? error.toString()}';
  }
}

/// Exception thrown when JSON parsing fails.
class JsonParseException implements Exception {
  final String rawJson;
  final String error;

  JsonParseException(this.rawJson, this.error);

  @override
  String toString() {
    return 'JsonParseException: $error (json: $rawJson)';
  }
}

/// High-level Dart SDK for Lemonade Nexus.
///
/// Provides async, type-safe access to all C SDK functions.
/// Call [dispose()] when done to release resources.
class LemonadeNexusSdk {
  late final LemonadeNexusFfi _ffi;
  ffi.Pointer<ffi.Void>? _client;
  ffi.Pointer<ffi.Void>? _identity;
  bool _isDisposed = false;

  /// Creates a new SDK instance.
  ///
  /// [libraryPath] - Optional path to the C SDK dynamic library.
  /// If not provided, uses platform default naming.
  LemonadeNexusSdk({String? libraryPath}) {
    _ffi = LemonadeNexusFfi(libraryPath: libraryPath);
  }

  /// Checks if the SDK is disposed.
  void _checkDisposed() {
    if (_isDisposed) {
      throw StateError('SDK has been disposed');
    }
  }

  /// Checks if the client is connected.
  void _checkConnected() {
    if (_client == null) {
      throw StateError('Not connected. Call connect() first.');
    }
  }

  /// Parses JSON response and handles errors.
  T _parseJson<T>(String? json, T Function(Map<String, dynamic>) fromJson) {
    if (json == null) {
      throw JsonParseException('null', 'Received null JSON response');
    }
    try {
      final Map<String, dynamic> map = jsonDecode(json) as Map<String, dynamic>;
      return fromJson(map);
    } catch (e) {
      throw JsonParseException(json, e.toString());
    }
  }

  /// Parses JSON list response.
  List<T> _parseJsonList<T>(
    String? json,
    T Function(Map<String, dynamic>) fromJson,
  ) {
    if (json == null) {
      throw JsonParseException('null', 'Received null JSON response');
    }
    try {
      final List<dynamic> list = jsonDecode(json) as List<dynamic>;
      return list
          .whereType<Map<String, dynamic>>()
          .map((m) => fromJson(m))
          .toList();
    } catch (e) {
      throw JsonParseException(json, e.toString());
    }
  }

  // =========================================================================
  // Lifecycle
  // =========================================================================

  /// Connects to a Lemonade Nexus server via plaintext HTTP.
  ///
  /// [host] - Server hostname or IP address.
  /// [port] - Server port number.
  Future<void> connect(String host, int port) async {
    _checkDisposed();
    _client = _ffi.create(host, port);
    if (_client == ffi.nullptr) {
      throw SdkException(LnError.connect, message: 'Failed to create client');
    }
  }

  /// Connects to a Lemonade Nexus server via TLS.
  ///
  /// [host] - Server hostname or IP address.
  /// [port] - Server port number.
  Future<void> connectTls(String host, int port) async {
    _checkDisposed();
    _client = _ffi.createTls(host, port);
    if (_client == ffi.nullptr) {
      throw SdkException(LnError.connect, message: 'Failed to create client');
    }
  }

  /// Disconnects and releases all resources.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;

    if (_identity != null) {
      _ffi.identityDestroy(_identity!);
      _identity = null;
    }

    if (_client != null) {
      _ffi.destroy(_client!);
      _client = null;
    }
  }

  // =========================================================================
  // Identity Management
  // =========================================================================

  /// Generates a new Ed25519 identity keypair.
  Future<IdentityInfo> generateIdentity() async {
    _checkDisposed();
    _identity = _ffi.identityGenerate();
    final pubkey = _ffi.identityPubkey(_identity!);
    return IdentityInfo(pubkey: pubkey ?? '');
  }

  /// Loads an identity from a JSON file.
  Future<IdentityInfo> loadIdentity(String path) async {
    _checkDisposed();
    if (_identity != null) {
      _ffi.identityDestroy(_identity!);
    }
    _identity = _ffi.identityLoad(path);
    final pubkey = _ffi.identityPubkey(_identity!);
    return IdentityInfo(pubkey: pubkey ?? '');
  }

  /// Saves the current identity to a JSON file.
  Future<void> saveIdentity(String path) async {
    _checkDisposed();
    _checkIdentity();
    final error = _ffi.identitySave(_identity!, path);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to save identity');
    }
  }

  /// Checks if identity is loaded.
  void _checkIdentity() {
    if (_identity == null) {
      throw StateError('No identity loaded. Call generateIdentity() or loadIdentity() first.');
    }
  }

  /// Gets the current identity's public key.
  String? get identityPubkey {
    _checkDisposed();
    if (_identity == null) return null;
    return _ffi.identityPubkey(_identity!);
  }

  /// Sets the current identity for the client.
  Future<void> setIdentity() async {
    _checkDisposed();
    _checkIdentity();
    final error = _ffi.setIdentity(_client!, _identity!);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to set identity');
    }
  }

  /// Creates an identity from a seed.
  Future<IdentityInfo> createIdentityFromSeed(Uint8List seed) async {
    _checkDisposed();
    _identity = _ffi.identityFromSeed(seed);
    final pubkey = _ffi.identityPubkey(_identity!);
    return IdentityInfo(pubkey: pubkey ?? '');
  }

  /// Derives a seed from username and password.
  Future<String> deriveSeed(String username, String password) async {
    _checkDisposed();
    final seed = _ffi.deriveSeed(username, password);
    if (seed == null) {
      throw SdkException(LnError.internal, message: 'Failed to derive seed');
    }
    return seed;
  }

  // =========================================================================
  // Health
  // =========================================================================

  /// Checks server health.
  Future<HealthResponse> health() async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.health(_client!);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Health check failed');
    }
    // Note: FFI health() already frees the JSON
    return HealthResponse(status: 'ok', version: 'unknown', uptime: 0);
  }

  // =========================================================================
  // Authentication
  // =========================================================================

  /// Authenticates with username and password.
  Future<AuthResponse> authPassword(String username, String password) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.authPassword(_client!, username, password);
    if (json == null) {
      throw SdkException(LnError.auth, message: 'Authentication failed');
    }
    return _parseJson(json, AuthResponse.fromJson);
  }

  /// Authenticates with a passkey credential.
  Future<AuthResponse> authPasskey(Map<String, dynamic> passkeyData) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(passkeyData);
    final result = _ffi.authPasskey(_client!, json);
    if (result == null) {
      throw SdkException(LnError.auth, message: 'Passkey authentication failed');
    }
    return _parseJson(result, AuthResponse.fromJson);
  }

  /// Authenticates with a token.
  Future<AuthResponse> authToken(String token) async {
    _checkDisposed();
    _checkConnected();
    final result = _ffi.authToken(_client!, token);
    if (result == null) {
      throw SdkException(LnError.auth, message: 'Token authentication failed');
    }
    return _parseJson(result, AuthResponse.fromJson);
  }

  /// Authenticates using Ed25519 challenge-response.
  Future<AuthResponse> authEd25519() async {
    _checkDisposed();
    _checkConnected();
    _checkIdentity();
    final result = _ffi.authEd25519(_client!);
    if (result == null) {
      throw SdkException(LnError.auth, message: 'Ed25519 authentication failed');
    }
    return _parseJson(result, AuthResponse.fromJson);
  }

  /// Registers a passkey credential.
  Future<Map<String, dynamic>> registerPasskey({
    required String userId,
    required String credentialId,
    required String publicKeyX,
    required String publicKeyY,
  }) async {
    _checkDisposed();
    _checkConnected();
    final result = _ffi.registerPasskey(
      _client!,
      userId,
      credentialId,
      publicKeyX,
      publicKeyY,
    );
    if (result == null) {
      throw SdkException(LnError.auth, message: 'Failed to register passkey');
    }
    return jsonDecode(result) as Map<String, dynamic>;
  }

  // =========================================================================
  // Tree Operations
  // =========================================================================

  /// Gets a node by ID.
  Future<TreeNode> getNode(String nodeId) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.treeGetNode(_client!, nodeId);
    if (json == null) {
      throw SdkException(LnError.notFound, message: 'Node not found: $nodeId');
    }
    return _parseJson(json, TreeNode.fromJson);
  }

  /// Submits a tree delta.
  Future<Map<String, dynamic>> submitDelta(Map<String, dynamic> delta) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(delta);
    final result = _ffi.treeSubmitDelta(_client!, json);
    if (result == null) {
      throw SdkException(LnError.internal, message: 'Failed to submit delta');
    }
    return jsonDecode(result) as Map<String, dynamic>;
  }

  /// Creates a child node.
  Future<TreeNode> createChildNode({
    required String parentId,
    required String nodeType,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.createChildNode(_client!, parentId, nodeType);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to create child node');
    }
    return _parseJson(json, TreeNode.fromJson);
  }

  /// Updates a node.
  Future<TreeNode> updateNode({
    required String nodeId,
    required Map<String, dynamic> updates,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(updates);
    final result = _ffi.updateNode(_client!, nodeId, json);
    if (result == null) {
      throw SdkException(LnError.internal, message: 'Failed to update node');
    }
    return _parseJson(result, TreeNode.fromJson);
  }

  /// Deletes a node.
  Future<void> deleteNode(String nodeId) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.deleteNode(_client!, nodeId);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to delete node');
    }
    // Success
  }

  /// Gets children of a node.
  Future<List<TreeNode>> getChildren(String parentId) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.treeGetChildren(_client!, parentId);
    if (json == null) {
      throw SdkException(LnError.notFound, message: 'Parent not found: $parentId');
    }
    return _parseJsonList(json, TreeNode.fromJson);
  }

  // =========================================================================
  // IPAM
  // =========================================================================

  /// Allocates an IP address block.
  Future<IpAllocation> allocateIp({
    required String nodeId,
    required String blockType,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.ipamAllocate(_client!, nodeId, blockType);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to allocate IP');
    }
    return _parseJson(json, IpAllocation.fromJson);
  }

  // =========================================================================
  // Relay
  // =========================================================================

  /// Lists available relay servers.
  Future<List<RelayInfo>> listRelays() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.relayList(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to list relays');
    }
    return _parseJsonList(json, RelayInfo.fromJson);
  }

  /// Gets a relay ticket for a peer connection.
  Future<RelayTicket> getRelayTicket({
    required String peerId,
    required String relayId,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.relayTicket(_client!, peerId, relayId);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get relay ticket');
    }
    return _parseJson(json, RelayTicket.fromJson);
  }

  /// Registers with a relay server.
  Future<void> registerRelay(Map<String, dynamic> registrationData) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(registrationData);
    final result = _ffi.relayRegister(_client!, json);
    if (result == null) {
      throw SdkException(LnError.internal, message: 'Failed to register relay');
    }
    // Success
  }

  // =========================================================================
  // Certificates
  // =========================================================================

  /// Gets certificate status for a domain.
  Future<CertStatus> getCertStatus(String domain) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.certStatus(_client!, domain);
    if (json == null) {
      throw SdkException(LnError.notFound, message: 'Cert not found for: $domain');
    }
    return _parseJson(json, CertStatus.fromJson);
  }

  /// Requests a TLS certificate.
  Future<Map<String, dynamic>> requestCert(String hostname) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.certRequest(_client!, hostname);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to request cert');
    }
    return jsonDecode(json) as Map<String, dynamic>;
  }

  /// Decrypts a certificate bundle.
  Future<CertBundle> decryptCert(String bundleJson) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.certDecrypt(_client!, bundleJson);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to decrypt cert');
    }
    return _parseJson(json, CertBundle.fromJson);
  }

  // =========================================================================
  // Group Membership
  // =========================================================================

  /// Adds a member to a group.
  Future<void> addGroupMember({
    required String nodeId,
    required String pubkey,
    required List<String> permissions,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(permissions);
    final result = _ffi.addGroupMember(_client!, nodeId, pubkey, json);
    if (result == null) {
      throw SdkException(LnError.internal, message: 'Failed to add group member');
    }
    // Success
  }

  /// Removes a member from a group.
  Future<void> removeGroupMember({
    required String nodeId,
    required String pubkey,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.removeGroupMember(_client!, nodeId, pubkey);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to remove group member');
    }
    // Success
  }

  /// Gets group members.
  Future<List<GroupMember>> getGroupMembers(String nodeId) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.getGroupMembers(_client!, nodeId);
    if (json == null) {
      throw SdkException(LnError.notFound, message: 'Group not found: $nodeId');
    }
    return _parseJsonList(json, GroupMember.fromJson);
  }

  /// Joins a group by creating an endpoint and allocating an IP.
  Future<GroupJoinResponse> joinGroup(String parentNodeId) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.joinGroup(_client!, parentNodeId);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to join group');
    }
    return _parseJson(json, GroupJoinResponse.fromJson);
  }

  // =========================================================================
  // Network Operations
  // =========================================================================

  /// Joins a network with username/password authentication.
  Future<NetworkJoinResponse> joinNetwork({
    required String username,
    required String password,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.joinNetwork(_client!, username, password);
    if (json == null) {
      throw SdkException(LnError.auth, message: 'Failed to join network');
    }
    return _parseJson(json, NetworkJoinResponse.fromJson);
  }

  /// Leaves the current network.
  Future<void> leaveNetwork() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.leaveNetwork(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to leave network');
    }
    // Success
  }

  // =========================================================================
  // Auto-switching
  // =========================================================================

  /// Enables automatic server switching based on latency.
  Future<void> enableAutoSwitching({
    double thresholdMs = 200.0,
    double hysteresis = 0.3,
    int cooldownSec = 60,
  }) async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.enableAutoSwitching(
      _client!,
      thresholdMs,
      hysteresis,
      cooldownSec,
    );
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to enable auto-switching');
    }
  }

  /// Disables automatic server switching.
  Future<void> disableAutoSwitching() async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.disableAutoSwitching(_client!);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to disable auto-switching');
    }
  }

  /// Gets current latency to the active server.
  Future<double> getCurrentLatency() async {
    _checkDisposed();
    _checkConnected();
    return _ffi.currentLatencyMs(_client!);
  }

  /// Gets latency stats for all servers.
  Future<List<ServerLatency>> getServerLatencies() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.serverLatencies(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get server latencies');
    }
    return _parseJsonList(json, ServerLatency.fromJson);
  }

  // =========================================================================
  // WireGuard Tunnel
  // =========================================================================

  /// Brings up the WireGuard tunnel.
  Future<void> tunnelUp(WgConfig config) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(config.toJson());
    final result = _ffi.tunnelUp(_client!, json);
    if (result == null) {
      throw SdkException(LnError.internal, message: 'Failed to bring up tunnel');
    }
    // Success
  }

  /// Tears down the WireGuard tunnel.
  Future<void> tunnelDown() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.tunnelDown(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to bring down tunnel');
    }
    // Success
  }

  /// Gets the WireGuard tunnel status.
  Future<TunnelStatus> getTunnelStatus() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.tunnelStatus(_client!);
    if (json == null) {
      return TunnelStatus(isUp: false);
    }
    return _parseJson(json, TunnelStatus.fromJson);
  }

  /// Gets the WireGuard configuration in wg-quick format.
  Future<String?> getWgConfig() async {
    _checkDisposed();
    _checkConnected();
    return _ffi.getWgConfig(_client!);
  }

  /// Gets the WireGuard configuration as JSON.
  Future<WgConfig?> getWgConfigJson() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.getWgConfigJson(_client!);
    if (json == null) return null;
    return _parseJson(json, WgConfig.fromJson);
  }

  /// Generates a WireGuard keypair.
  Future<WgKeypair> generateWgKeypair() async {
    _checkDisposed();
    final json = _ffi.wgGenerateKeypair();
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to generate keypair');
    }
    return _parseJson(json, WgKeypair.fromJson);
  }

  // =========================================================================
  // Mesh P2P
  // =========================================================================

  /// Enables mesh networking with default config.
  Future<void> enableMesh() async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.meshEnable(_client!);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to enable mesh');
    }
  }

  /// Enables mesh networking with custom config.
  Future<void> enableMeshWithConfig(Map<String, dynamic> config) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(config);
    final error = _ffi.meshEnableConfig(_client!, json);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to enable mesh with config');
    }
  }

  /// Disables mesh networking.
  Future<void> disableMesh() async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.meshDisable(_client!);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to disable mesh');
    }
  }

  /// Gets mesh tunnel status.
  Future<MeshStatus> getMeshStatus() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.meshStatus(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get mesh status');
    }
    return _parseJson(json, MeshStatus.fromJson);
  }

  /// Gets mesh peers.
  Future<List<MeshPeer>> getMeshPeers() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.meshPeers(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get mesh peers');
    }
    return _parseJsonList(json, MeshPeer.fromJson);
  }

  /// Forces an immediate mesh peer refresh.
  Future<void> refreshMesh() async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.meshRefresh(_client!);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to refresh mesh');
    }
  }

  // =========================================================================
  // Stats & Servers
  // =========================================================================

  /// Gets service statistics.
  Future<ServiceStats> getStats() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.stats(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get stats');
    }
    return _parseJson(json, ServiceStats.fromJson);
  }

  /// Lists available servers.
  Future<List<ServerInfo>> listServers() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.servers(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to list servers');
    }
    return _parseJsonList(json, ServerInfo.fromJson);
  }

  // =========================================================================
  // Trust & Attestation
  // =========================================================================

  /// Gets trust status.
  Future<TrustStatus> getTrustStatus() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.trustStatus(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get trust status');
    }
    return _parseJson(json, TrustStatus.fromJson);
  }

  /// Gets trust info for a specific peer.
  Future<TrustPeerInfo> getTrustPeer(String pubkey) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.trustPeer(_client!, pubkey);
    if (json == null) {
      throw SdkException(LnError.notFound, message: 'Peer not found: $pubkey');
    }
    return _parseJson(json, TrustPeerInfo.fromJson);
  }

  // =========================================================================
  // DDNS
  // =========================================================================

  /// Gets DDNS status.
  Future<DdnsStatus> getDdnsStatus() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.ddnsStatus(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get DDNS status');
    }
    return _parseJson(json, DdnsStatus.fromJson);
  }

  // =========================================================================
  // Enrollment
  // =========================================================================

  /// Gets enrollment status.
  Future<List<EnrollmentEntry>> getEnrollmentStatus() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.enrollmentStatus(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get enrollment status');
    }
    return _parseJsonList(json, EnrollmentEntry.fromJson);
  }

  // =========================================================================
  // Governance
  // =========================================================================

  /// Gets governance proposals.
  Future<List<GovernanceProposal>> getGovernanceProposals() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.governanceProposals(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get proposals');
    }
    return _parseJsonList(json, GovernanceProposal.fromJson);
  }

  /// Submits a governance proposal.
  Future<ProposeResponse> submitGovernanceProposal({
    required int parameter,
    required String newValue,
    required String rationale,
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.governancePropose(_client!, parameter, newValue, rationale);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to submit proposal');
    }
    return _parseJson(json, ProposeResponse.fromJson);
  }

  // =========================================================================
  // Attestation
  // =========================================================================

  /// Gets attestation manifests.
  Future<List<AttestationManifest>> getAttestationManifests() async {
    _checkDisposed();
    _checkConnected();
    final json = _ffi.attestationManifests(_client!);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get manifests');
    }
    return _parseJsonList(json, AttestationManifest.fromJson);
  }

  // =========================================================================
  // Session Management
  // =========================================================================

  /// Sets the session token.
  Future<void> setSessionToken(String token) async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.setSessionToken(_client!, token);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to set session token');
    }
  }

  /// Gets the current session token.
  Future<String?> getSessionToken() async {
    _checkDisposed();
    _checkConnected();
    return _ffi.getSessionToken(_client!);
  }

  /// Sets the node ID.
  Future<void> setNodeId(String nodeId) async {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.setNodeId(_client!, nodeId);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to set node ID');
    }
  }

  /// Gets the current node ID.
  Future<String?> getNodeId() async {
    _checkDisposed();
    _checkConnected();
    return _ffi.getNodeId(_client!);
  }
}
