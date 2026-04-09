/// @title Lemonade Nexus SDK FFI Bindings
/// @description Low-level FFI bindings for the Lemonade Nexus C SDK.
///
/// This file contains the raw FFI bindings to the C SDK. Use the
/// [LemonadeNexusSdk] class for a high-level Dart API.

import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:convert';
import 'package:ffi/ffi.dart';

/// Error codes from the C SDK.
enum LnError {
  success(0),
  nullArg(-1),
  connect(-2),
  auth(-3),
  notFound(-4),
  rejected(-5),
  noIdentity(-6),
  internal(-99);

  final int code;
  const LnError(this.code);

  static LnError fromCode(int code) {
    for (final error in LnError.values) {
      if (error.code == code) return error;
    }
    return LnError.internal;
  }

  bool get isSuccess => this == LnError.success;
}

/// Opaque handle types.
/// In FFI, these are represented as Pointer<Void>
typedef LnClientHandle = ffi.Pointer<ffi.Void>;
typedef LnIdentityHandle = ffi.Pointer<ffi.Void>;

/// FFI type mappings for C SDK functions.

// Memory management
typedef _LnFree = ffi.Int32 Function(ffi.Pointer<ffi.Char> ptr);
typedef _LnFreeDart = int Function(ffi.Pointer<ffi.Char> ptr);

// Client lifecycle
typedef _LnCreate = LnClientHandle Function(
  ffi.Pointer<ffi.Char> host,
  ffi.Uint16 port,
);
typedef _LnCreateDart = LnClientHandle Function(
  ffi.Pointer<ffi.Char> host,
  int port,
);

typedef _LnCreateTls = LnClientHandle Function(
  ffi.Pointer<ffi.Char> host,
  ffi.Uint16 port,
);
typedef _LnCreateTlsDart = LnClientHandle Function(
  ffi.Pointer<ffi.Char> host,
  int port,
);

typedef _LnDestroy = ffi.Void Function(LnClientHandle client);
typedef _LnDestroyDart = void Function(LnClientHandle client);

// Identity management
typedef _LnIdentityGenerate = LnIdentityHandle Function();
typedef _LnIdentityGenerateDart = LnIdentityHandle Function();

typedef _LnIdentityLoad = LnIdentityHandle Function(
  ffi.Pointer<ffi.Char> path,
);
typedef _LnIdentityLoadDart = LnIdentityHandle Function(
  ffi.Pointer<ffi.Char> path,
);

typedef _LnIdentitySave = ffi.Int32 Function(
  LnIdentityHandle identity,
  ffi.Pointer<ffi.Char> path,
);
typedef _LnIdentitySaveDart = int Function(
  LnIdentityHandle identity,
  ffi.Pointer<ffi.Char> path,
);

typedef _LnIdentityPubkey = ffi.Pointer<ffi.Char> Function(
  LnIdentityHandle identity,
);
typedef _LnIdentityPubkeyDart = ffi.Pointer<ffi.Char> Function(
  LnIdentityHandle identity,
);

typedef _LnIdentityDestroy = ffi.Void Function(LnIdentityHandle identity);
typedef _LnIdentityDestroyDart = void Function(LnIdentityHandle identity);

typedef _LnSetIdentity = ffi.Int32 Function(
  LnClientHandle client,
  LnIdentityHandle identity,
);
typedef _LnSetIdentityDart = int Function(
  LnClientHandle client,
  LnIdentityHandle identity,
);

typedef _LnIdentityFromSeed = LnIdentityHandle Function(
  ffi.Pointer<ffi.Uint8> seed,
  ffi.Uint32 seedLen,
);
typedef _LnIdentityFromSeedDart = LnIdentityHandle Function(
  ffi.Pointer<ffi.Uint8> seed,
  int seedLen,
);

typedef _LnDeriveSeed = ffi.Pointer<ffi.Char> Function(
  ffi.Pointer<ffi.Char> username,
  ffi.Pointer<ffi.Char> password,
);
typedef _LnDeriveSeedDart = ffi.Pointer<ffi.Char> Function(
  ffi.Pointer<ffi.Char> username,
  ffi.Pointer<ffi.Char> password,
);

// Health
typedef _LnHealth = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnHealthDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Authentication
typedef _LnAuthPassword = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> username,
  ffi.Pointer<ffi.Char> password,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnAuthPasswordDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> username,
  ffi.Pointer<ffi.Char> password,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnAuthPasskey = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> passkeyJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnAuthPasskeyDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> passkeyJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnAuthToken = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> token,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnAuthTokenDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> token,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnAuthEd25519 = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnAuthEd25519Dart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnRegisterPasskey = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> userId,
  ffi.Pointer<ffi.Char> credentialId,
  ffi.Pointer<ffi.Char> publicKeyX,
  ffi.Pointer<ffi.Char> publicKeyY,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnRegisterPasskeyDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> userId,
  ffi.Pointer<ffi.Char> credentialId,
  ffi.Pointer<ffi.Char> publicKeyX,
  ffi.Pointer<ffi.Char> publicKeyY,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Tree operations
typedef _LnTreeGetNode = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTreeGetNodeDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnTreeSubmitDelta = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> deltaJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTreeSubmitDeltaDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> deltaJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnCreateChildNode = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> parentId,
  ffi.Pointer<ffi.Char> nodeType,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnCreateChildNodeDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> parentId,
  ffi.Pointer<ffi.Char> nodeType,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnUpdateNode = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> updatesJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnUpdateNodeDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> updatesJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnDeleteNode = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnDeleteNodeDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnTreeGetChildren = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> parentId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTreeGetChildrenDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> parentId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// IPAM
typedef _LnIpamAllocate = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> blockType,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnIpamAllocateDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> blockType,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Relay
typedef _LnRelayList = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnRelayListDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnRelayTicket = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> peerId,
  ffi.Pointer<ffi.Char> relayId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnRelayTicketDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> peerId,
  ffi.Pointer<ffi.Char> relayId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnRelayRegister = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> regJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnRelayRegisterDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> regJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Certificates
typedef _LnCertStatus = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> domain,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnCertStatusDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> domain,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnCertRequest = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> hostname,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnCertRequestDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> hostname,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnCertDecrypt = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> bundleJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnCertDecryptDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> bundleJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Group membership
typedef _LnAddGroupMember = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> pubkey,
  ffi.Pointer<ffi.Char> permissionsJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnAddGroupMemberDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> pubkey,
  ffi.Pointer<ffi.Char> permissionsJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnRemoveGroupMember = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> pubkey,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnRemoveGroupMemberDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Char> pubkey,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnGetGroupMembers = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnGetGroupMembersDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnJoinGroup = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> parentNodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnJoinGroupDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> parentNodeId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// High-level operations
typedef _LnJoinNetwork = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> username,
  ffi.Pointer<ffi.Char> password,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnJoinNetworkDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> username,
  ffi.Pointer<ffi.Char> password,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnLeaveNetwork = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnLeaveNetworkDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Auto-switching
typedef _LnEnableAutoSwitching = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Double thresholdMs,
  ffi.Double hysteresis,
  ffi.Uint32 cooldownSec,
);
typedef _LnEnableAutoSwitchingDart = int Function(
  LnClientHandle client,
  double thresholdMs,
  double hysteresis,
  int cooldownSec,
);

typedef _LnDisableAutoSwitching = ffi.Int32 Function(
  LnClientHandle client,
);
typedef _LnDisableAutoSwitchingDart = int Function(
  LnClientHandle client,
);

typedef _LnCurrentLatencyMs = ffi.Double Function(
  LnClientHandle client,
);
typedef _LnCurrentLatencyMsDart = double Function(
  LnClientHandle client,
);

typedef _LnServerLatencies = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnServerLatenciesDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// WireGuard tunnel
typedef _LnTunnelUp = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> configJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTunnelUpDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> configJson,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnTunnelDown = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTunnelDownDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnTunnelStatus = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTunnelStatusDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnGetWgConfig = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);
typedef _LnGetWgConfigDart = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);

typedef _LnGetWgConfigJson = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);
typedef _LnGetWgConfigJsonDart = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);

typedef _LnWgGenerateKeypair = ffi.Pointer<ffi.Char> Function();
typedef _LnWgGenerateKeypairDart = ffi.Pointer<ffi.Char> Function();

// Mesh P2P
typedef _LnMeshEnable = ffi.Int32 Function(
  LnClientHandle client,
);
typedef _LnMeshEnableDart = int Function(
  LnClientHandle client,
);

typedef _LnMeshEnableConfig = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> configJson,
);
typedef _LnMeshEnableConfigDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> configJson,
);

typedef _LnMeshDisable = ffi.Int32 Function(
  LnClientHandle client,
);
typedef _LnMeshDisableDart = int Function(
  LnClientHandle client,
);

typedef _LnMeshStatus = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnMeshStatusDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnMeshPeers = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnMeshPeersDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnMeshRefresh = ffi.Int32 Function(
  LnClientHandle client,
);
typedef _LnMeshRefreshDart = int Function(
  LnClientHandle client,
);

// Stats & server listing
typedef _LnStats = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnStatsDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnServers = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnServersDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Trust & attestation
typedef _LnTrustStatus = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTrustStatusDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnTrustPeer = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> pubkey,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnTrustPeerDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> pubkey,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// DDNS status
typedef _LnDdnsStatus = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnDdnsStatusDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Enrollment
typedef _LnEnrollmentStatus = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnEnrollmentStatusDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Governance
typedef _LnGovernanceProposals = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnGovernanceProposalsDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

typedef _LnGovernancePropose = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Uint8 parameter,
  ffi.Pointer<ffi.Char> newValue,
  ffi.Pointer<ffi.Char> rationale,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnGovernanceProposeDart = int Function(
  LnClientHandle client,
  int parameter,
  ffi.Pointer<ffi.Char> newValue,
  ffi.Pointer<ffi.Char> rationale,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Attestation manifests
typedef _LnAttestationManifests = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);
typedef _LnAttestationManifestsDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

// Session management
typedef _LnSetSessionToken = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> token,
);
typedef _LnSetSessionTokenDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> token,
);

typedef _LnGetSessionToken = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);
typedef _LnGetSessionTokenDart = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);

typedef _LnSetNodeId = ffi.Int32 Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
);
typedef _LnSetNodeIdDart = int Function(
  LnClientHandle client,
  ffi.Pointer<ffi.Char> nodeId,
);

typedef _LnGetNodeId = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);
typedef _LnGetNodeIdDart = ffi.Pointer<ffi.Char> Function(
  LnClientHandle client,
);

/// Low-level FFI bindings to the Lemonade Nexus C SDK.
///
/// This class provides direct access to all C SDK functions via FFI.
/// For a higher-level Dart API, use [LemonadeNexusSdk].
class LemonadeNexusFfi {
  late final ffi.DynamicLibrary _lib;

  // Memory management
  late final _lnFree = _lookup<_LnFree, _LnFreeDart>('ln_free');

  // Client lifecycle
  late final _lnCreate = _lookup<_LnCreate, _LnCreateDart>('ln_create');
  late final _lnCreateTls =
      _lookup<_LnCreateTls, _LnCreateTlsDart>('ln_create_tls');
  late final _lnDestroy =
      _lookup<_LnDestroy, _LnDestroyDart>('ln_destroy');

  // Identity management
  late final _lnIdentityGenerate = _lookup<_LnIdentityGenerate,
          _LnIdentityGenerateDart>('ln_identity_generate');
  late final _lnIdentityLoad =
      _lookup<_LnIdentityLoad, _LnIdentityLoadDart>('ln_identity_load');
  late final _lnIdentitySave =
      _lookup<_LnIdentitySave, _LnIdentitySaveDart>('ln_identity_save');
  late final _lnIdentityPubkey = _lookup<_LnIdentityPubkey,
          _LnIdentityPubkeyDart>('ln_identity_pubkey');
  late final _lnIdentityDestroy = _lookup<_LnIdentityDestroy,
          _LnIdentityDestroyDart>('ln_identity_destroy');
  late final _lnSetIdentity =
      _lookup<_LnSetIdentity, _LnSetIdentityDart>('ln_set_identity');
  late final _lnIdentityFromSeed = _lookup<_LnIdentityFromSeed,
          _LnIdentityFromSeedDart>('ln_identity_from_seed');
  late final _lnDeriveSeed =
      _lookup<_LnDeriveSeed, _LnDeriveSeedDart>('ln_derive_seed');

  // Health
  late final _lnHealth =
      _lookup<_LnHealth, _LnHealthDart>('ln_health');

  // Authentication
  late final _lnAuthPassword =
      _lookup<_LnAuthPassword, _LnAuthPasswordDart>('ln_auth_password');
  late final _lnAuthPasskey =
      _lookup<_LnAuthPasskey, _LnAuthPasskeyDart>('ln_auth_passkey');
  late final _lnAuthToken =
      _lookup<_LnAuthToken, _LnAuthTokenDart>('ln_auth_token');
  late final _lnAuthEd25519 =
      _lookup<_LnAuthEd25519, _LnAuthEd25519Dart>('ln_auth_ed25519');
  late final _lnRegisterPasskey = _lookup<_LnRegisterPasskey,
          _LnRegisterPasskeyDart>('ln_register_passkey');

  // Tree operations
  late final _lnTreeGetNode =
      _lookup<_LnTreeGetNode, _LnTreeGetNodeDart>('ln_tree_get_node');
  late final _lnTreeSubmitDelta = _lookup<_LnTreeSubmitDelta,
          _LnTreeSubmitDeltaDart>('ln_tree_submit_delta');
  late final _lnCreateChildNode = _lookup<_LnCreateChildNode,
          _LnCreateChildNodeDart>('ln_create_child_node');
  late final _lnUpdateNode =
      _lookup<_LnUpdateNode, _LnUpdateNodeDart>('ln_update_node');
  late final _lnDeleteNode =
      _lookup<_LnDeleteNode, _LnDeleteNodeDart>('ln_delete_node');
  late final _lnTreeGetChildren = _lookup<_LnTreeGetChildren,
          _LnTreeGetChildrenDart>('ln_tree_get_children');

  // IPAM
  late final _lnIpamAllocate =
      _lookup<_LnIpamAllocate, _LnIpamAllocateDart>('ln_ipam_allocate');

  // Relay
  late final _lnRelayList =
      _lookup<_LnRelayList, _LnRelayListDart>('ln_relay_list');
  late final _lnRelayTicket =
      _lookup<_LnRelayTicket, _LnRelayTicketDart>('ln_relay_ticket');
  late final _lnRelayRegister =
      _lookup<_LnRelayRegister, _LnRelayRegisterDart>('ln_relay_register');

  // Certificates
  late final _lnCertStatus =
      _lookup<_LnCertStatus, _LnCertStatusDart>('ln_cert_status');
  late final _lnCertRequest =
      _lookup<_LnCertRequest, _LnCertRequestDart>('ln_cert_request');
  late final _lnCertDecrypt =
      _lookup<_LnCertDecrypt, _LnCertDecryptDart>('ln_cert_decrypt');

  // Group membership
  late final _lnAddGroupMember = _lookup<_LnAddGroupMember,
          _LnAddGroupMemberDart>('ln_add_group_member');
  late final _lnRemoveGroupMember = _lookup<_LnRemoveGroupMember,
          _LnRemoveGroupMemberDart>('ln_remove_group_member');
  late final _lnGetGroupMembers = _lookup<_LnGetGroupMembers,
          _LnGetGroupMembersDart>('ln_get_group_members');
  late final _lnJoinGroup =
      _lookup<_LnJoinGroup, _LnJoinGroupDart>('ln_join_group');

  // High-level operations
  late final _lnJoinNetwork =
      _lookup<_LnJoinNetwork, _LnJoinNetworkDart>('ln_join_network');
  late final _lnLeaveNetwork =
      _lookup<_LnLeaveNetwork, _LnLeaveNetworkDart>('ln_leave_network');

  // Auto-switching
  late final _lnEnableAutoSwitching = _lookup<_LnEnableAutoSwitching,
          _LnEnableAutoSwitchingDart>('ln_enable_auto_switching');
  late final _lnDisableAutoSwitching = _lookup<_LnDisableAutoSwitching,
          _LnDisableAutoSwitchingDart>('ln_disable_auto_switching');
  late final _lnCurrentLatencyMs = _lookup<_LnCurrentLatencyMs,
          _LnCurrentLatencyMsDart>('ln_current_latency_ms');
  late final _lnServerLatencies =
      _lookup<_LnServerLatencies, _LnServerLatenciesDart>('ln_server_latencies');

  // WireGuard tunnel
  late final _lnTunnelUp =
      _lookup<_LnTunnelUp, _LnTunnelUpDart>('ln_tunnel_up');
  late final _lnTunnelDown =
      _lookup<_LnTunnelDown, _LnTunnelDownDart>('ln_tunnel_down');
  late final _lnTunnelStatus =
      _lookup<_LnTunnelStatus, _LnTunnelStatusDart>('ln_tunnel_status');
  late final _lnGetWgConfig =
      _lookup<_LnGetWgConfig, _LnGetWgConfigDart>('ln_get_wg_config');
  late final _lnGetWgConfigJson = _lookup<_LnGetWgConfigJson,
          _LnGetWgConfigJsonDart>('ln_get_wg_config_json');
  late final _lnWgGenerateKeypair = _lookup<_LnWgGenerateKeypair,
          _LnWgGenerateKeypairDart>('ln_wg_generate_keypair');

  // Mesh P2P
  late final _lnMeshEnable =
      _lookup<_LnMeshEnable, _LnMeshEnableDart>('ln_mesh_enable');
  late final _lnMeshEnableConfig = _lookup<_LnMeshEnableConfig,
          _LnMeshEnableConfigDart>('ln_mesh_enable_config');
  late final _lnMeshDisable =
      _lookup<_LnMeshDisable, _LnMeshDisableDart>('ln_mesh_disable');
  late final _lnMeshStatus =
      _lookup<_LnMeshStatus, _LnMeshStatusDart>('ln_mesh_status');
  late final _lnMeshPeers =
      _lookup<_LnMeshPeers, _LnMeshPeersDart>('ln_mesh_peers');
  late final _lnMeshRefresh =
      _lookup<_LnMeshRefresh, _LnMeshRefreshDart>('ln_mesh_refresh');

  // Stats & server listing
  late final _lnStats =
      _lookup<_LnStats, _LnStatsDart>('ln_stats');
  late final _lnServers =
      _lookup<_LnServers, _LnServersDart>('ln_servers');

  // Trust & attestation
  late final _lnTrustStatus =
      _lookup<_LnTrustStatus, _LnTrustStatusDart>('ln_trust_status');
  late final _lnTrustPeer =
      _lookup<_LnTrustPeer, _LnTrustPeerDart>('ln_trust_peer');

  // DDNS status
  late final _lnDdnsStatus =
      _lookup<_LnDdnsStatus, _LnDdnsStatusDart>('ln_ddns_status');

  // Enrollment
  late final _lnEnrollmentStatus = _lookup<_LnEnrollmentStatus,
          _LnEnrollmentStatusDart>('ln_enrollment_status');

  // Governance
  late final _lnGovernanceProposals = _lookup<_LnGovernanceProposals,
          _LnGovernanceProposalsDart>('ln_governance_proposals');
  late final _lnGovernancePropose = _lookup<_LnGovernancePropose,
          _LnGovernanceProposeDart>('ln_governance_propose');

  // Attestation manifests
  late final _lnAttestationManifests = _lookup<_LnAttestationManifests,
          _LnAttestationManifestsDart>('ln_attestation_manifests');

  // Session management
  late final _lnSetSessionToken = _lookup<_LnSetSessionToken,
          _LnSetSessionTokenDart>('ln_set_session_token');
  late final _lnGetSessionToken = _lookup<_LnGetSessionToken,
          _LnGetSessionTokenDart>('ln_get_session_token');
  late final _lnSetNodeId =
      _lookup<_LnSetNodeId, _LnSetNodeIdDart>('ln_set_node_id');
  late final _lnGetNodeId =
      _lookup<_LnGetNodeId, _LnGetNodeIdDart>('ln_get_node_id');

  /// Creates a new FFI binding instance.
  ///
  /// [libraryPath] - Optional path to the C SDK dynamic library.
  /// If not provided, uses platform default naming.
  LemonadeNexusFfi({String? libraryPath}) {
    if (libraryPath != null) {
      _lib = ffi.DynamicLibrary.open(libraryPath);
    } else {
      // Platform-specific library naming
      if (Platform.isWindows) {
        _lib = ffi.DynamicLibrary.open('lemonade_nexus.dll');
      } else if (Platform.isMacOS) {
        _lib = ffi.DynamicLibrary.open('liblemonade_nexus.dylib');
      } else if (Platform.isLinux) {
        _lib = ffi.DynamicLibrary.open('liblemonade_nexus.so');
      } else {
        throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
      }
    }
  }

  T _lookup<T, D>(String symbol) {
    return _lib.lookup<T>(symbol).asFunction<D>();
  }

  // =========================================================================
  // Memory Management
  // =========================================================================

  /// Frees a string returned by the C SDK.
  void freeString(ffi.Pointer<ffi.Char> ptr) {
    if (ptr != ffi.nullptr) {
      _lnFree(ptr);
    }
  }

  /// Converts a C string pointer to a Dart String and frees the original.
  String? toStringAndFree(ffi.Pointer<ffi.Char> ptr) {
    if (ptr == ffi.nullptr) return null;
    final result = ptr.cast<Utf8>().toDartString();
    _lnFree(ptr);
    return result;
  }

  /// Converts a C string pointer to a Dart String without freeing.
  String? toStringNoFree(ffi.Pointer<ffi.Char> ptr) {
    if (ptr == ffi.nullptr) return null;
    return ptr.cast<Utf8>().toDartString();
  }

  /// Converts a Dart String to a native C string (caller must free).
  ffi.Pointer<ffi.Char> toNativeString(String? str) {
    if (str == null) return ffi.nullptr;
    return str.toNativeUtf8().cast<ffi.Char>();
  }

  // =========================================================================
  // Client Lifecycle
  // =========================================================================

  LnClientHandle create(String host, int port) {
    final hostPtr = host.toNativeUtf8().cast<ffi.Char>();
    final result = _lnCreate(hostPtr, port);
    malloc.free(hostPtr);
    return result;
  }

  LnClientHandle createTls(String host, int port) {
    final hostPtr = host.toNativeUtf8().cast<ffi.Char>();
    final result = _lnCreateTls(hostPtr, port);
    malloc.free(hostPtr);
    return result;
  }

  void destroy(LnClientHandle client) {
    _lnDestroy(client);
  }

  // =========================================================================
  // Identity Management
  // =========================================================================

  LnIdentityHandle identityGenerate() {
    return _lnIdentityGenerate();
  }

  LnIdentityHandle identityLoad(String path) {
    final pathPtr = path.toNativeUtf8().cast<ffi.Char>();
    final result = _lnIdentityLoad(pathPtr);
    malloc.free(pathPtr);
    return result;
  }

  LnError identitySave(LnIdentityHandle identity, String path) {
    final pathPtr = path.toNativeUtf8().cast<ffi.Char>();
    final result = _lnIdentitySave(identity, pathPtr);
    malloc.free(pathPtr);
    return LnError.fromCode(result);
  }

  String? identityPubkey(LnIdentityHandle identity) {
    final ptr = _lnIdentityPubkey(identity);
    return toStringAndFree(ptr);
  }

  void identityDestroy(LnIdentityHandle identity) {
    _lnIdentityDestroy(identity);
  }

  LnError setIdentity(LnClientHandle client, LnIdentityHandle identity) {
    return LnError.fromCode(_lnSetIdentity(client, identity));
  }

  LnIdentityHandle identityFromSeed(Uint8List seed) {
    final native = malloc<ffi.Uint8>(seed.length);
    native.asTypedList(seed.length).setAll(0, seed);
    final result = _lnIdentityFromSeed(native, seed.length);
    malloc.free(native);
    return result;
  }

  String? deriveSeed(String username, String password) {
    final userPtr = username.toNativeUtf8().cast<ffi.Char>();
    final passPtr = password.toNativeUtf8().cast<ffi.Char>();
    final result = _lnDeriveSeed(userPtr, passPtr);
    malloc.free(userPtr);
    malloc.free(passPtr);
    return toStringAndFree(result);
  }

  // =========================================================================
  // Health
  // =========================================================================

  LnError health(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnHealth(client, outJson);
      if (result == 0) {
        freeString(outJson.value);
      }
      return LnError.fromCode(result);
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Authentication
  // =========================================================================

  String? authPassword(LnClientHandle client, String username, String password) {
    final userPtr = username.toNativeUtf8().cast<ffi.Char>();
    final passPtr = password.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnAuthPassword(client, userPtr, passPtr, outJson);
      malloc.free(userPtr);
      malloc.free(passPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? authPasskey(LnClientHandle client, String passkeyJson) {
    final jsonPtr = passkeyJson.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnAuthPasskey(client, jsonPtr, outJson);
      malloc.free(jsonPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? authToken(LnClientHandle client, String token) {
    final tokenPtr = token.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnAuthToken(client, tokenPtr, outJson);
      malloc.free(tokenPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? authEd25519(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnAuthEd25519(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? registerPasskey(
    LnClientHandle client,
    String userId,
    String credentialId,
    String publicKeyX,
    String publicKeyY,
  ) {
    final userIdPtr = userId.toNativeUtf8().cast<ffi.Char>();
    final credIdPtr = credentialId.toNativeUtf8().cast<ffi.Char>();
    final pkXPtr = publicKeyX.toNativeUtf8().cast<ffi.Char>();
    final pkYPtr = publicKeyY.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnRegisterPasskey(
        client,
        userIdPtr,
        credIdPtr,
        pkXPtr,
        pkYPtr,
        outJson,
      );
      malloc.free(userIdPtr);
      malloc.free(credIdPtr);
      malloc.free(pkXPtr);
      malloc.free(pkYPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Tree Operations
  // =========================================================================

  String? treeGetNode(LnClientHandle client, String nodeId) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTreeGetNode(client, nodeIdPtr, outJson);
      malloc.free(nodeIdPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? treeSubmitDelta(LnClientHandle client, String deltaJson) {
    final jsonPtr = deltaJson.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTreeSubmitDelta(client, jsonPtr, outJson);
      malloc.free(jsonPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? createChildNode(
    LnClientHandle client,
    String parentId,
    String nodeType,
  ) {
    final parentIdPtr = parentId.toNativeUtf8().cast<ffi.Char>();
    final nodeTypePtr = nodeType.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnCreateChildNode(client, parentIdPtr, nodeTypePtr, outJson);
      malloc.free(parentIdPtr);
      malloc.free(nodeTypePtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? updateNode(
    LnClientHandle client,
    String nodeId,
    String updatesJson,
  ) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final jsonPtr = updatesJson.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnUpdateNode(client, nodeIdPtr, jsonPtr, outJson);
      malloc.free(nodeIdPtr);
      malloc.free(jsonPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? deleteNode(LnClientHandle client, String nodeId) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnDeleteNode(client, nodeIdPtr, outJson);
      malloc.free(nodeIdPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? treeGetChildren(LnClientHandle client, String parentId) {
    final parentIdPtr = parentId.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTreeGetChildren(client, parentIdPtr, outJson);
      malloc.free(parentIdPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // IPAM
  // =========================================================================

  String? ipamAllocate(
    LnClientHandle client,
    String nodeId,
    String blockType,
  ) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final blockTypePtr = blockType.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnIpamAllocate(client, nodeIdPtr, blockTypePtr, outJson);
      malloc.free(nodeIdPtr);
      malloc.free(blockTypePtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Relay
  // =========================================================================

  String? relayList(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnRelayList(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? relayTicket(
    LnClientHandle client,
    String peerId,
    String relayId,
  ) {
    final peerIdPtr = peerId.toNativeUtf8().cast<ffi.Char>();
    final relayIdPtr = relayId.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnRelayTicket(client, peerIdPtr, relayIdPtr, outJson);
      malloc.free(peerIdPtr);
      malloc.free(relayIdPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? relayRegister(LnClientHandle client, String regJson) {
    final jsonPtr = regJson.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnRelayRegister(client, jsonPtr, outJson);
      malloc.free(jsonPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Certificates
  // =========================================================================

  String? certStatus(LnClientHandle client, String domain) {
    final domainPtr = domain.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnCertStatus(client, domainPtr, outJson);
      malloc.free(domainPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? certRequest(LnClientHandle client, String hostname) {
    final hostnamePtr = hostname.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnCertRequest(client, hostnamePtr, outJson);
      malloc.free(hostnamePtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? certDecrypt(LnClientHandle client, String bundleJson) {
    final jsonPtr = bundleJson.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnCertDecrypt(client, jsonPtr, outJson);
      malloc.free(jsonPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Group Membership
  // =========================================================================

  String? addGroupMember(
    LnClientHandle client,
    String nodeId,
    String pubkey,
    String permissionsJson,
  ) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final pubkeyPtr = pubkey.toNativeUtf8().cast<ffi.Char>();
    final jsonPtr = permissionsJson.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnAddGroupMember(
        client,
        nodeIdPtr,
        pubkeyPtr,
        jsonPtr,
        outJson,
      );
      malloc.free(nodeIdPtr);
      malloc.free(pubkeyPtr);
      malloc.free(jsonPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? removeGroupMember(
    LnClientHandle client,
    String nodeId,
    String pubkey,
  ) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final pubkeyPtr = pubkey.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnRemoveGroupMember(client, nodeIdPtr, pubkeyPtr, outJson);
      malloc.free(nodeIdPtr);
      malloc.free(pubkeyPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? getGroupMembers(LnClientHandle client, String nodeId) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnGetGroupMembers(client, nodeIdPtr, outJson);
      malloc.free(nodeIdPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? joinGroup(LnClientHandle client, String parentNodeId) {
    final parentNodeIdPtr = parentNodeId.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnJoinGroup(client, parentNodeIdPtr, outJson);
      malloc.free(parentNodeIdPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // High-level Operations
  // =========================================================================

  String? joinNetwork(LnClientHandle client, String username, String password) {
    final userPtr = username.toNativeUtf8().cast<ffi.Char>();
    final passPtr = password.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnJoinNetwork(client, userPtr, passPtr, outJson);
      malloc.free(userPtr);
      malloc.free(passPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? leaveNetwork(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnLeaveNetwork(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Auto-switching
  // =========================================================================

  LnError enableAutoSwitching(
    LnClientHandle client,
    double thresholdMs,
    double hysteresis,
    int cooldownSec,
  ) {
    return LnError.fromCode(
      _lnEnableAutoSwitching(client, thresholdMs, hysteresis, cooldownSec),
    );
  }

  LnError disableAutoSwitching(LnClientHandle client) {
    return LnError.fromCode(_lnDisableAutoSwitching(client));
  }

  double currentLatencyMs(LnClientHandle client) {
    return _lnCurrentLatencyMs(client);
  }

  String? serverLatencies(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnServerLatencies(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // WireGuard Tunnel
  // =========================================================================

  String? tunnelUp(LnClientHandle client, String configJson) {
    final jsonPtr = configJson.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTunnelUp(client, jsonPtr, outJson);
      malloc.free(jsonPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? tunnelDown(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTunnelDown(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? tunnelStatus(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTunnelStatus(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? getWgConfig(LnClientHandle client) {
    final ptr = _lnGetWgConfig(client);
    return toStringAndFree(ptr);
  }

  String? getWgConfigJson(LnClientHandle client) {
    final ptr = _lnGetWgConfigJson(client);
    return toStringAndFree(ptr);
  }

  String? wgGenerateKeypair() {
    final ptr = _lnWgGenerateKeypair();
    return toStringAndFree(ptr);
  }

  // =========================================================================
  // Mesh P2P
  // =========================================================================

  LnError meshEnable(LnClientHandle client) {
    return LnError.fromCode(_lnMeshEnable(client));
  }

  LnError meshEnableConfig(LnClientHandle client, String configJson) {
    final jsonPtr = configJson.toNativeUtf8().cast<ffi.Char>();
    final result = _lnMeshEnableConfig(client, jsonPtr);
    malloc.free(jsonPtr);
    return LnError.fromCode(result);
  }

  LnError meshDisable(LnClientHandle client) {
    return LnError.fromCode(_lnMeshDisable(client));
  }

  String? meshStatus(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnMeshStatus(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? meshPeers(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnMeshPeers(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  LnError meshRefresh(LnClientHandle client) {
    return LnError.fromCode(_lnMeshRefresh(client));
  }

  // =========================================================================
  // Stats & Server Listing
  // =========================================================================

  String? stats(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnStats(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? servers(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnServers(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Trust & Attestation
  // =========================================================================

  String? trustStatus(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTrustStatus(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? trustPeer(LnClientHandle client, String pubkey) {
    final pubkeyPtr = pubkey.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnTrustPeer(client, pubkeyPtr, outJson);
      malloc.free(pubkeyPtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // DDNS Status
  // =========================================================================

  String? ddnsStatus(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnDdnsStatus(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Enrollment
  // =========================================================================

  String? enrollmentStatus(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnEnrollmentStatus(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Governance
  // =========================================================================

  String? governanceProposals(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnGovernanceProposals(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  String? governancePropose(
    LnClientHandle client,
    int parameter,
    String newValue,
    String rationale,
  ) {
    final newValuePtr = newValue.toNativeUtf8().cast<ffi.Char>();
    final rationalePtr = rationale.toNativeUtf8().cast<ffi.Char>();
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnGovernancePropose(
        client,
        parameter,
        newValuePtr,
        rationalePtr,
        outJson,
      );
      malloc.free(newValuePtr);
      malloc.free(rationalePtr);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Attestation Manifests
  // =========================================================================

  String? attestationManifests(LnClientHandle client) {
    final outJson = calloc<ffi.Pointer<ffi.Char>>();
    try {
      final result = _lnAttestationManifests(client, outJson);
      if (result == 0) {
        return toStringAndFree(outJson.value);
      }
      freeString(outJson.value);
      return null;
    } finally {
      calloc.free(outJson);
    }
  }

  // =========================================================================
  // Session Management
  // =========================================================================

  LnError setSessionToken(LnClientHandle client, String token) {
    final tokenPtr = token.toNativeUtf8().cast<ffi.Char>();
    final result = _lnSetSessionToken(client, tokenPtr);
    malloc.free(tokenPtr);
    return LnError.fromCode(result);
  }

  String? getSessionToken(LnClientHandle client) {
    final ptr = _lnGetSessionToken(client);
    return toStringAndFree(ptr);
  }

  LnError setNodeId(LnClientHandle client, String nodeId) {
    final nodeIdPtr = nodeId.toNativeUtf8().cast<ffi.Char>();
    final result = _lnSetNodeId(client, nodeIdPtr);
    malloc.free(nodeIdPtr);
    return LnError.fromCode(result);
  }

  String? getNodeId(LnClientHandle client) {
    final ptr = _lnGetNodeId(client);
    return toStringAndFree(ptr);
  }
}
