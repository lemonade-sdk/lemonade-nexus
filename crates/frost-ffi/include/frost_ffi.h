#pragma once

/// C header for the lemonade-frost-ffi crate (crates/frost-ffi/src/lib.rs).
/// Verified against frost-ed25519 2.2.0 (Zcash Foundation) — keep in sync if
/// the crate version changes.
/// See: https://github.com/ZcashFoundation/frost
///
/// FROST(Ed25519, SHA-512) per-epoch dealerless DKG and threshold signing.
/// Secret material (DKG states, key shares, signing nonces) lives only behind
/// opaque handles in Rust memory and is zeroized on free or consumption.
/// Aggregated signatures verify as plain Ed25519.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Status codes. 0 is success; negative values are errors.
#define FROST_OK                   0
#define FROST_ERR_INVALID_ARGUMENT (-1)  ///< Null pointer, zero or duplicate identifier
#define FROST_ERR_CRYPTO           (-2)  ///< The FROST protocol rejected the operation
#define FROST_ERR_SERIALIZATION    (-3)  ///< Byte encoding or decoding failed
#define FROST_ERR_PANIC            (-10) ///< Internal panic caught at the boundary

/// Rust-allocated output buffer. Free only with frost_buffer_free.
typedef struct FrostBuffer {
    uint8_t* data;
    size_t   len;
} FrostBuffer;

/// Caller-supplied (identifier, serialized package) input pair.
/// Identifiers are 1-based participant indices; 0 is invalid.
typedef struct FrostPeerBytes {
    uint16_t       identifier;
    const uint8_t* data;
    size_t         len;
} FrostPeerBytes;

/// Rust-allocated (identifier, buffer) output pair. Free the whole array
/// only with frost_peer_buffers_free.
typedef struct FrostPeerBuffer {
    uint16_t    identifier;
    FrostBuffer buffer;
} FrostPeerBuffer;

/// Opaque handles. Secrets never cross this boundary. Each handle has a
/// dedicated _free function that zeroizes the secret inside.
typedef struct FrostDkgRound1State FrostDkgRound1State;
typedef struct FrostDkgRound2State FrostDkgRound2State;
typedef struct FrostKeyPackage     FrostKeyPackage;
typedef struct FrostSigningNonces  FrostSigningNonces;

/// DKG part 1 for one participant.
/// All randomness comes from the OS RNG; there is no caller-supplied RNG.
/// On success writes a round 1 state (owned by the caller; pass it to
/// frost_dkg_part2 or free it) and the serialized round 1 package to
/// broadcast to every other participant.
/// Out-params are written only on success.
/// @param identifier  1-based participant index (0 returns -1)
/// @param max_signers Total number of participants (n)
/// @param min_signers Signing threshold (t)
int32_t frost_dkg_part1(uint16_t identifier,
                        uint16_t max_signers,
                        uint16_t min_signers,
                        FrostDkgRound1State** out_state,
                        FrostBuffer* out_round1_package);

/// DKG part 2.
/// CONSUMES state on every return path, success and failure alike; the state
/// pointer is invalid after the call. Do not free it again.
/// @param round1_packages Round 1 package of every OTHER participant
///                        (identifier = sender), round1_count entries
/// On success writes a round 2 state and an array of out_count packages.
/// Each output identifier names the RECIPIENT that package must be sent to.
/// Free the array only with frost_peer_buffers_free(array, out_count).
int32_t frost_dkg_part2(FrostDkgRound1State* state,
                        const FrostPeerBytes* round1_packages,
                        size_t round1_count,
                        FrostDkgRound2State** out_state,
                        FrostPeerBuffer** out_round2_packages,
                        size_t* out_count);

/// DKG part 3.
/// CONSUMES state on every return path, success and failure alike; the state
/// pointer is invalid after the call. Do not free it again.
/// @param round1_packages The SAME list given to frost_dkg_part2
/// @param round2_packages Packages addressed to this participant
///                        (identifier = SENDER), round2_count entries
/// On success writes the key package handle, the 32-byte group public key
/// (a plain Ed25519 verifying key, identical for all participants), and the
/// serialized public key package that frost_aggregate needs later.
int32_t frost_dkg_part3(FrostDkgRound2State* state,
                        const FrostPeerBytes* round1_packages,
                        size_t round1_count,
                        const FrostPeerBytes* round2_packages,
                        size_t round2_count,
                        FrostKeyPackage** out_key_package,
                        uint8_t out_group_public_key[32],
                        FrostBuffer* out_public_key_package);

/// Generate fresh signing nonces and their serialized commitments for ONE
/// signing run. The nonces stay behind the handle and are never serialized
/// or persisted. Send the commitments to the coordinator.
int32_t frost_signing_commit(const FrostKeyPackage* key_package,
                             FrostSigningNonces** out_nonces,
                             FrostBuffer* out_commitments);

/// Produce this participant's signature share.
/// CONSUMES nonces on every return path, success and failure alike; the
/// nonce pointer is invalid after the call. A nonce signs at most once;
/// there is no way to reuse it through this API. A new signing run needs a
/// new frost_signing_commit.
/// @param commitments Commitments of ALL selected signers, this participant
///                    included (identifier = signer), commitments_count
///                    entries; at least min_signers entries
int32_t frost_sign(const FrostKeyPackage* key_package,
                   FrostSigningNonces* nonces,
                   const uint8_t* message,
                   size_t message_len,
                   const FrostPeerBytes* commitments,
                   size_t commitments_count,
                   FrostBuffer* out_signature_share);

/// Aggregate signature shares into one 64-byte plain Ed25519 signature.
/// Verifies every share; a tampered share fails the call with -2.
/// @param commitments        The same commitment set the signers used
/// @param signature_shares   One share per signer (identifier = signer)
/// @param public_key_package Serialized output of frost_dkg_part3
int32_t frost_aggregate(const uint8_t* message,
                        size_t message_len,
                        const FrostPeerBytes* commitments,
                        size_t commitments_count,
                        const FrostPeerBytes* signature_shares,
                        size_t shares_count,
                        const uint8_t* public_key_package,
                        size_t public_key_package_len,
                        uint8_t out_signature[64]);

/// Verify a 64-byte signature under the 32-byte group public key.
/// This is plain Ed25519 verification.
/// @return 0 valid, -2 invalid, -3 malformed key or signature
int32_t frost_verify(const uint8_t group_public_key[32],
                     const uint8_t* message,
                     size_t message_len,
                     const uint8_t signature[64]);

/// Read the 1-based participant identifier out of a key package handle.
int32_t frost_key_package_identifier(const FrostKeyPackage* key_package,
                                     uint16_t* out_identifier);

/// Zeroize and free the bytes owned by a buffer, then null its fields, so a
/// second call is a no-op. NULL is a no-op. Use only for buffers written by
/// this library.
void frost_buffer_free(FrostBuffer* buffer);

/// Zeroize and free an array returned by frost_dkg_part2. Pass the exact
/// pointer and count the call returned. NULL is a no-op.
void frost_peer_buffers_free(FrostPeerBuffer* buffers, size_t count);

/// Free an UNUSED round 1 state and zeroize the secret inside. Never call
/// this after frost_dkg_part2 consumed the state. NULL is a no-op.
void frost_dkg_round1_state_free(FrostDkgRound1State* state);

/// Free an UNUSED round 2 state and zeroize the secret inside. Never call
/// this after frost_dkg_part3 consumed the state. NULL is a no-op.
void frost_dkg_round2_state_free(FrostDkgRound2State* state);

/// Free a key package and zeroize the signing share inside. NULL is a no-op.
void frost_key_package_free(FrostKeyPackage* key_package);

/// Free UNUSED signing nonces and zeroize them. Never call this after
/// frost_sign consumed the nonces. NULL is a no-op.
void frost_signing_nonces_free(FrostSigningNonces* nonces);

#ifdef __cplusplus
}
#endif
