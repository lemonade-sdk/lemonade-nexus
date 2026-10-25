/// @title Lemonade Nexus SDK
/// @description High-level Dart API for the Lemonade Nexus Client SDK.
///
/// This class provides a type-safe, async Dart API wrapping the
/// low-level FFI bindings. It handles memory management, JSON parsing,
/// and error handling automatically.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'ffi_bindings.dart';
import 'mesh_port.dart';
import 'models.dart';

export 'mesh_port.dart';

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
  LemonadeNexusSdk({String? libraryPath}) : _libraryPath = libraryPath {
    _ffi = LemonadeNexusFfi(libraryPath: libraryPath);
  }

  /// Kept so a worker isolate can load the same library (see [_privateApiRaw]).
  final String? _libraryPath;

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

  /// Symbol lookups are lazy, so without this a stale native library surfaces
  /// as a raw dlsym error partway through an unrelated flow.
  void _checkNativeAbi() {
    final missing = _ffi.missingSymbols();
    if (missing.isEmpty) return;
    throw SdkException(
      LnError.internal,
      message: 'The native Lemonade Nexus SDK on this device is out of date — '
          'it is missing ${missing.join(', ')}. Rebuild it from the repo root:\n'
          '  cmake --build build --target LemonadeNexusSDKShared',
    );
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

  /// Parses a list that the SDK nests inside an envelope object.
  ///
  /// Some endpoints (e.g. `ln_attestation_manifests`)
  /// return `{...meta, "<key>": [ ... ]}` rather than a bare array. This
  /// extracts the nested array under [key]; if the SDK instead returns a bare
  /// array, that is handled too.
  List<T> _parseNestedList<T>(
    String? json,
    String key,
    T Function(Map<String, dynamic>) fromJson,
  ) {
    if (json == null) {
      throw JsonParseException('null', 'Received null JSON response');
    }
    try {
      final decoded = jsonDecode(json);
      final List<dynamic> list = decoded is List
          ? decoded
          : (decoded is Map<String, dynamic>
              ? (decoded[key] as List<dynamic>? ?? const [])
              : const []);
      return list.whereType<Map<String, dynamic>>().map(fromJson).toList();
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
    _checkNativeAbi();
    _destroyClient();
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
    _checkNativeAbi();
    _destroyClient();
    _client = _ffi.createTls(host, port);
    if (_client == ffi.nullptr) {
      throw SdkException(LnError.connect, message: 'Failed to create client');
    }
  }

  /// Tears down the active client (and, optionally, the identity) while keeping
  /// the SDK reusable — unlike [dispose], this leaves [_isDisposed] false so a
  /// subsequent [connect]/[connectTls] can bring up a fresh client.
  ///
  /// Used for logout and for failover reconnects. The identity is preserved by
  /// default so a reconnect can re-bind it (via [setIdentity]) and re-join;
  /// pass [clearIdentity] on logout to start the next session clean.
  void disconnect({bool clearIdentity = false}) {
    if (_isDisposed) return;
    _destroyClient();
    if (clearIdentity) {
      _destroyIdentity();
    }
  }

  /// Destroys the native client handle if present. Destroying the client also
  /// tears down its boringtun dataplane (the tunnel), which is owned by value
  /// inside the C client.
  void _destroyClient() {
    final client = _client;
    if (client == null) return;
    _client = null;
    if ((_inFlight[client.address] ?? 0) > 0) {
      _destroyPending.add(client.address);
    } else {
      _ffi.destroy(client);
    }
  }

  /// Destroys the native identity handle if present.
  void _destroyIdentity() {
    if (_identity != null) {
      _ffi.identityDestroy(_identity!);
      _identity = null;
    }
  }

  /// Disposes the SDK for good and releases all resources.
  ///
  /// Reserved for teardown (Riverpod provider / notifier disposal). After this
  /// the instance is permanently unusable — use [disconnect] to close a
  /// connection while keeping the SDK reusable.
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _destroyIdentity();
    _destroyClient();
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
  // Account group-key envelopes + device linking
  // =========================================================================

  /// Generate a fresh account (Cluster) group key (base64).
  String generateGroupKey() {
    _checkDisposed();
    final key = _ffi.groupKeyGenerate();
    if (key == null) {
      throw SdkException(LnError.internal, message: 'Failed to generate group key');
    }
    return key;
  }

  /// Seal [groupKey] to a recipient device's Ed25519 public key. Returns the
  /// envelope `{ephemeral_pubkey, wrapped_key}`.
  Map<String, dynamic> wrapGroupKey(String recipientPubkey, String groupKey) {
    _checkDisposed();
    final json = _ffi.groupKeyWrap(recipientPubkey, groupKey);
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to wrap group key');
    }
    return _parseJson<Map<String, dynamic>>(json, (m) => m);
  }

  /// Open a group-key [envelope] with the loaded identity. Returns the group key
  /// (base64), or null if it isn't addressed to us / is corrupt.
  String? unwrapGroupKey(Map<String, dynamic> envelope) {
    _checkDisposed();
    _checkIdentity();
    return _ffi.groupKeyUnwrap(_identity!, jsonEncode(envelope));
  }

  // =========================================================================
  // Tier 1 servers (tree traffic)
  // =========================================================================

  /// Pin the network's Genesis public key (base64, the server config's
  /// `genesis_pubkey`). The SDK sends every tree, session, and private-API
  /// request only to Tier 1 servers it verifies from this key, and fails over
  /// between them. Without a key those requests are not sent. [minEpoch] is
  /// the lowest Tier 1 epoch to accept (the last one this app verified).
  void setGenesisKey(String genesisPubkeyB64, {int minEpoch = 0}) {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.setGenesisKey(_client!, genesisPubkeyB64, minEpoch: minEpoch);
    if (error != LnError.success) {
      throw SdkException(error,
          message: 'The network key must be a base64 Ed25519 public key');
    }
  }

  /// Verify the Tier 1 membership now. Returns {epoch, members, servers}.
  Future<Map<String, dynamic>> refreshTier1() async {
    _checkDisposed();
    _checkConnected();
    final (error, json) = await _offThread((f, c) => f.tier1Refresh(c));
    return _tier1Result(error, json, 'Tier 1 verification failed');
  }

  /// The last verified Tier 1 membership, without network I/O.
  Future<Map<String, dynamic>> tier1Membership() async {
    _checkDisposed();
    _checkConnected();
    final (error, json) = _ffi.tier1Membership(_client!);
    return _tier1Result(error, json, 'Tier 1 membership is not available');
  }

  Map<String, dynamic> _tier1Result(LnError error, String? json, String fallback) {
    if (error != LnError.success || json == null) {
      String? reason;
      if (json != null) {
        try {
          reason = (jsonDecode(json) as Map<String, dynamic>)['error']?.toString();
        } catch (_) {}
      }
      throw SdkException(error == LnError.success ? LnError.internal : error,
          message: reason ?? fallback, rawJson: json);
    }
    return _parseJson<Map<String, dynamic>>(json, (m) => m);
  }

  /// Set the single-use device-link token injected into the next joinNetwork.
  void setLinkToken(String token) {
    _checkDisposed();
    _checkConnected();
    final error = _ffi.setLinkToken(_client!, token);
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to set link token');
    }
  }

  /// Mint a link token so another device can join this account's Cluster.
  /// Returns `{link_token, group_node_id, expires_at}`. Requires the mesh up.
  Future<Map<String, dynamic>> createLinkToken({int ttlSec = 600}) async {
    _checkDisposed();
    _checkConnected();
    final (error, json) = await _offThread((f, c) => f.linkTokenCreate(c, ttlSec));
    if (error != LnError.success || json == null) {
      String? reason;
      if (json != null) {
        try {
          reason = (jsonDecode(json) as Map<String, dynamic>)['error']?.toString();
        } catch (_) {}
      }
      throw SdkException(error == LnError.success ? LnError.internal : error,
          message: reason ?? 'Failed to create link token', rawJson: json);
    }
    return _parseJson<Map<String, dynamic>>(json, (m) => m);
  }

  // =========================================================================
  // Health
  // =========================================================================

  /// Checks server health, returning the parsed `{status, service, rp_id}`.
  Future<HealthResponse> health() async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.health(c));
    if (json == null) {
      throw SdkException(LnError.connect, message: 'Health check failed');
    }
    return _parseJson(json, HealthResponse.fromJson);
  }

  // =========================================================================
  // Authentication
  // =========================================================================

  /// Authenticates with username and password.
  Future<AuthResponse> authPassword(String username, String password) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.authPassword(c, username, password));
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
    final result = await _offThread((f, c) => f.authPasskey(c, json));
    if (result == null) {
      throw SdkException(LnError.auth, message: 'Passkey authentication failed');
    }
    return _parseJson(result, AuthResponse.fromJson);
  }

  /// Fetches the server-issued WebAuthn assertion challenge bound to [userId].
  /// The assertion's clientDataJSON must carry it; it expires server-side and
  /// is single-use.
  Future<String> getPasskeyChallenge(String userId) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.authPasskeyChallenge(c, userId));
    if (json == null) {
      throw SdkException(LnError.connect,
          message: 'Passkey challenge request failed');
    }
    final challenge = _parseJson(json, (m) => m)['challenge'] as String?;
    if (challenge == null || challenge.isEmpty) {
      throw SdkException(LnError.connect, message: 'Empty passkey challenge');
    }
    return challenge;
  }

  /// Authenticates with a token.
  Future<AuthResponse> authToken(String token) async {
    _checkDisposed();
    _checkConnected();
    final result = await _offThread((f, c) => f.authToken(c, token));
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
    final result = await _offThread((f, c) =>
        f.registerPasskey(c, userId, credentialId, publicKeyX, publicKeyY));
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
    final json = await _offThread((f, c) => f.treeGetNode(c, nodeId));
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
    final result = await _offThread((f, c) => f.treeSubmitDelta(c, json));
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
    final json = await _offThread((f, c) => f.createChildNode(c, parentId, nodeType));
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
    final result = await _offThread((f, c) => f.updateNode(c, nodeId, json));
    if (result == null) {
      throw SdkException(LnError.internal, message: 'Failed to update node');
    }
    return _parseJson(result, TreeNode.fromJson);
  }

  /// Deletes a node.
  Future<void> deleteNode(String nodeId) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.deleteNode(c, nodeId));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to delete node');
    }
    // Success
  }

  /// Gets children of a node.
  Future<List<TreeNode>> getChildren(String parentId) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.treeGetChildren(c, parentId));
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
    final json = await _offThread((f, c) => f.ipamAllocate(c, nodeId, blockType));
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
    final json = await _offThread((f, c) => f.relayList(c));
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
    final json = await _offThread((f, c) => f.relayTicket(c, peerId, relayId));
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
    final result = await _offThread((f, c) => f.relayRegister(c, json));
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
    final json = await _offThread((f, c) => f.certStatus(c, domain));
    if (json == null) {
      throw SdkException(LnError.notFound, message: 'Cert not found for: $domain');
    }
    return _parseJson(json, CertStatus.fromJson);
  }

  /// Requests a TLS certificate.
  Future<Map<String, dynamic>> requestCert(String hostname) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.certRequest(c, hostname));
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
    final result = await _offThread((f, c) => f.addGroupMember(c, nodeId, pubkey, json));
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
    final json = await _offThread((f, c) => f.removeGroupMember(c, nodeId, pubkey));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to remove group member');
    }
    // Success
  }

  /// Gets group members.
  Future<List<GroupMember>> getGroupMembers(String nodeId) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.getGroupMembers(c, nodeId));
    if (json == null) {
      throw SdkException(LnError.notFound, message: 'Group not found: $nodeId');
    }
    return _parseJsonList(json, GroupMember.fromJson);
  }

  /// Joins a group by creating an endpoint and allocating an IP.
  Future<GroupJoinResponse> joinGroup(String parentNodeId) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.joinGroup(c, parentNodeId));
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
    final json = await _offThread((f, c) => f.joinNetwork(c, username, password));
    if (json == null) {
      throw SdkException(LnError.auth, message: 'Failed to join network');
    }
    return _parseJson(json, NetworkJoinResponse.fromJson);
  }

  /// Leaves the current network.
  Future<void> leaveNetwork() async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.leaveNetwork(c));
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
  // Mesh P2P
  // =========================================================================

  /// Enables mesh networking with default config.
  Future<void> enableMesh() async {
    _checkDisposed();
    _checkConnected();
    final error = await _offThread((f, c) => f.meshEnable(c));
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to enable mesh');
    }
  }

  /// Enables mesh networking with custom config.
  Future<void> enableMeshWithConfig(Map<String, dynamic> config) async {
    _checkDisposed();
    _checkConnected();
    final json = jsonEncode(config);
    final error = await _offThread((f, c) => f.meshEnableConfig(c, json));
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
    final error = await _offThread((f, c) => f.meshRefresh(c));
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to refresh mesh');
    }
  }

  // =========================================================================
  // Mesh port (loopback listener that serves group devices by name)
  // =========================================================================

  /// Starts the mesh port on 127.0.0.1:[port] with the group loopback
  /// certificate in [certDir]. Throws [SdkException] with [LnError.portInUse]
  /// when another process (for example lemond) already owns the port.
  Future<void> startMeshPort({
    int port = 13306,
    String? localServiceUrl,
    String? certDir,
  }) async {
    _checkDisposed();
    _checkConnected();
    final error = await _offThread((f, c) {
      final dirError = f.meshPortSetCertDir(c, certDir);
      if (dirError != LnError.success) return dirError;
      return f.meshPortStart(c, port, localServiceUrl);
    });
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to start the mesh port');
    }
  }

  /// Stops the mesh port. Does nothing when no client exists.
  Future<void> stopMeshPort() async {
    if (_isDisposed || _client == null) return;
    await _offThread((f, c) => f.meshPortStop(c));
  }

  /// Sets the mesh port selection: "local", "auto", a node ID, or null.
  Future<void> setMeshPortSelection(String? target, {String? peerKey}) async {
    _checkDisposed();
    _checkConnected();
    final error = await _offThread((f, c) => f.meshPortSetSelection(c, target, peerKey));
    if (error != LnError.success) {
      throw SdkException(error, message: 'Failed to set the mesh port selection');
    }
  }

  /// Reads the mesh port status.
  Future<MeshPortStatus> getMeshPortStatus() async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.meshPortStatus(c));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to read the mesh port status');
    }
    return _parseJson(json, MeshPortStatus.fromJson);
  }

  // =========================================================================
  // Stats & Servers
  // =========================================================================

  /// Gets service statistics.
  Future<ServiceStats> getStats() async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.stats(c));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get stats');
    }
    return _parseJson(json, ServiceStats.fromJson);
  }

  /// Lists available servers.
  Future<List<ServerInfo>> listServers() async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.servers(c));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to list servers');
    }
    return _parseJsonList(json, ServerInfo.fromJson);
  }

  // =========================================================================
  // DDNS
  // =========================================================================

  /// Gets DDNS status.
  Future<DdnsStatus> getDdnsStatus() async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.ddnsStatus(c));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get DDNS status');
    }
    return _parseJson(json, DdnsStatus.fromJson);
  }

  // =========================================================================
  // Attestation
  // =========================================================================

  /// Gets attestation manifests.
  Future<List<AttestationManifest>> getAttestationManifests() async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.attestationManifests(c));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get manifests');
    }
    // SDK returns an envelope `{self_hash, ..., manifests: [...]}`.
    return _parseNestedList(json, 'manifests', AttestationManifest.fromJson);
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

  // =========================================================================
  // Routing Layer (connect-by-identifier)
  // =========================================================================

  /// Fetches the authorized endpoint profile (paginated).
  ///
  /// Returns the raw decoded JSON object. Typed models (RoutingProfile,
  /// AuthorizedEndpoint) can be layered on top once json_serializable codegen
  /// is run; the raw map keeps the routing surface usable without codegen.
  Future<Map<String, dynamic>> routingProfile({int page = 0, int pageSize = 200}) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.routingProfile(c, page: page, pageSize: pageSize));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get routing profile');
    }
    return _parseJson<Map<String, dynamic>>(json, (m) => m);
  }

  /// Requests a connection to an endpoint by [identifier].
  ///
  /// [connNonceB64] is a client-chosen 16-byte nonce (base64). [clientMeshPubkey]
  /// is optional. Returns the raw {connection_id, state} JSON.
  Future<Map<String, dynamic>> routingRequest(
    String identifier,
    String connNonceB64, {
    String clientMeshPubkey = '',
  }) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.routingRequest(c, identifier, connNonceB64,
        clientMeshPubkey: clientMeshPubkey));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Routing request failed');
    }
    return _parseJson<Map<String, dynamic>>(json, (m) => m);
  }

  /// Generic authenticated call to a private-mesh API route (e.g. /api/chats).
  /// [method] is "GET" or "POST"; [body] is sent as JSON for POST. Returns the
  /// raw response body decoded as a JSON object. Requires the mesh tunnel.
  /// Native calls that make network requests run on a worker isolate: on the
  /// UI isolate each one would block frame rendering for the full round trip
  /// (or the connect/read timeout when a server is down). The native client
  /// guards its shared transport state, so concurrent calls are safe.
  ///
  /// The client handle stays alive until every call that uses it returns:
  /// [_destroyClient] defers the native destroy while calls are in flight.
  Future<T> _offThread<T>(
      T Function(LemonadeNexusFfi f, ffi.Pointer<ffi.Void> c) call) async {
    final address = _client!.address;
    final libraryPath = _libraryPath;
    _inFlight[address] = (_inFlight[address] ?? 0) + 1;
    try {
      return await Isolate.run(() => call(LemonadeNexusFfi(libraryPath: libraryPath),
          ffi.Pointer<ffi.Void>.fromAddress(address)));
    } finally {
      final left = (_inFlight[address] ?? 1) - 1;
      if (left > 0) {
        _inFlight[address] = left;
      } else {
        _inFlight.remove(address);
        if (_destroyPending.remove(address)) {
          _ffi.destroy(ffi.Pointer<ffi.Void>.fromAddress(address));
        }
      }
    }
  }

  /// Background calls in flight per native client address, and clients whose
  /// destroy waits for those calls to finish.
  final Map<int, int> _inFlight = {};
  final Set<int> _destroyPending = {};

  /// Private-API calls ride the mesh tunnel; they run off the UI isolate like
  /// every other network call (see [_offThread]).
  Future<String?> _privateApiRaw(String method, String path, String body) =>
      _offThread((f, c) => f.privateApiCall(c, method, path, body));

  Future<Map<String, dynamic>> privateApiCall(String method, String path,
      {Map<String, dynamic>? body}) async {
    _checkDisposed();
    _checkConnected();
    final json = await _privateApiRaw(
        method, path, body == null ? '' : jsonEncode(body));
    if (json == null) {
      throw SdkException(LnError.internal, message: '$method $path failed');
    }
    return _parseJson<Map<String, dynamic>>(json, (m) => m);
  }

  /// Like [privateApiCall], for routes that answer with a JSON array (e.g.
  /// /api/tree/children/{id}).
  Future<List<Map<String, dynamic>>> privateApiCallList(String method, String path,
      {Map<String, dynamic>? body}) async {
    _checkDisposed();
    _checkConnected();
    final json = await _privateApiRaw(
        method, path, body == null ? '' : jsonEncode(body));
    if (json == null) {
      throw SdkException(LnError.internal, message: '$method $path failed');
    }
    return _parseJsonList<Map<String, dynamic>>(json, (m) => m);
  }

  /// Queries the current connection/session state by [connectionId].
  Future<Map<String, dynamic>> routingConnectionStatus(String connectionId) async {
    _checkDisposed();
    _checkConnected();
    final json = await _offThread((f, c) => f.routingConnectionStatus(c, connectionId));
    if (json == null) {
      throw SdkException(LnError.internal, message: 'Failed to get connection status');
    }
    return _parseJson<Map<String, dynamic>>(json, (m) => m);
  }
}
