#pragma once

/// C header for the lemonade-storage-threshold crate
/// (crates/storage-threshold/src/ffi.rs).
/// Verified against frost-ristretto255 2.2.0 and elastic-elgamal 0.3.1. Keep
/// in sync if a crate version changes.
///
/// Threshold storage key (design Part B). The storage secret s is shared
/// among 5 to 50 holders with threshold t = ceil(0.65 * n) and is never
/// assembled. A data key is wrapped to S = s*G with ECIES: this library
/// returns the ephemeral point R and the shared point r*S; the caller runs
/// the KDF and AEAD. To unwrap, t holders each return s_i*R with a DLEQ proof,
/// and storage_combine interpolates s*R.
///
/// The storage key is its own key role (domain tag
/// LEMONADE-NEXUS-STORAGE-V1). It never signs and never authorizes.
///
/// Conventions:
/// - Every function returns a STORAGE_* status. 0 is success.
/// - Out-parameters are written only on success.
/// - Holder identifiers are nonzero 16-bit indices assigned by the plan.
/// - A "plan" is the serialized public key package: S and every holder's
///   public share commitment Y_i. The threshold is derived from the holder
///   count. Plans are public.
/// - All randomness comes from the OS RNG. There is no caller-supplied RNG.
/// - Functions are thread-safe for distinct handles. A handle must not be
///   used from two threads at once.
///
/// Secret material and where it can appear:
/// - Shares and protocol states: only behind opaque handles. Each handle has
///   one release function that zeroizes it.
/// - Round 2 packages, repair deltas, repair sigmas, and serialized shares:
///   in StorageBuffer / StoragePeerBuffer or caller arrays. Send them only
///   over an authenticated, encrypted pairwise channel, or seal them at rest.
/// - The shared point r*S = s*R: in a 32-byte caller array. Keep it in
///   guarded memory and wipe it after the KDF.
///
/// Messages carry no session binding. The caller must carry key generation,
/// refresh, and repair messages inside authenticated envelopes bound to the
/// network, epoch, and session.

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STORAGE_OK                     0
#define STORAGE_ERR_INVALID_ARGUMENT   (-1)  ///< Null pointer, zero or duplicate identifier, bad length or point
#define STORAGE_ERR_CRYPTO             (-2)  ///< A protocol step rejected its input, or a consistency check failed
#define STORAGE_ERR_SERIALIZATION      (-3)  ///< Byte encoding or decoding failed
#define STORAGE_ERR_BELOW_THRESHOLD    (-4)  ///< Fewer than t distinct partials, helpers, or old holders
#define STORAGE_ERR_THRESHOLD_CHANGE   (-5)  ///< The new holder count needs another t; rotate the key instead
#define STORAGE_ERR_HOLDER_COUNT       (-6)  ///< Holder count outside 5..50
#define STORAGE_ERR_PROOF              (-7)  ///< A partial failed DLEQ verification, or its holder is not in the plan
#define STORAGE_ERR_SHARE_MISMATCH     (-8)  ///< The share does not belong to the plan (stale, removed, other key)
#define STORAGE_ERR_PANIC              (-10) ///< Internal panic caught at the boundary

#define STORAGE_MIN_HOLDERS   5
#define STORAGE_MAX_HOLDERS   50
#define STORAGE_POINT_LEN     32
#define STORAGE_PARTIAL_LEN   96  ///< s_i*R (32 bytes) followed by the DLEQ proof (64 bytes)
#define STORAGE_DOMAIN        "LEMONADE-NEXUS-STORAGE-V1"

/// Rust-allocated output buffer. Free only with storage_buffer_free.
typedef struct StorageBuffer {
    uint8_t* data;
    size_t   len;
} StorageBuffer;

/// Caller-supplied (holder, bytes) input pair. The library reads the bytes
/// during the call only and keeps no pointer.
typedef struct StoragePeerBytes {
    uint16_t       identifier;
    const uint8_t* data;
    size_t         len;
} StoragePeerBytes;

/// Rust-allocated (holder, buffer) output pair. Free the whole array only
/// with storage_peer_buffers_free.
typedef struct StoragePeerBuffer {
    uint16_t      identifier;
    StorageBuffer buffer;
} StoragePeerBuffer;

/// Request fields every partial is bound to. The requester and every holder
/// must pass identical values. The merlin transcript of each proof binds the
/// domain tag, these fields, S, the holder identifier, and R.
typedef struct StorageUnlockContext {
    uint8_t  network_id[32];
    uint64_t epoch;
    uint8_t  plan_digest[32];   ///< Digest of the finalized holder plan (defined by the caller)
    uint8_t  request_nonce[32];
} StorageUnlockContext;

/// Opaque handles.
typedef struct StorageShare              StorageShare;
typedef struct StorageDkgRound1State     StorageDkgRound1State;
typedef struct StorageDkgRound2State     StorageDkgRound2State;
typedef struct StorageRefreshRound1State StorageRefreshRound1State;
typedef struct StorageRefreshRound2State StorageRefreshRound2State;

/// Write t = ceil(0.65 * holder_count) for 1 <= holder_count <= 50.
/// @return STORAGE_ERR_HOLDER_COUNT outside that range.
int32_t storage_threshold_for(uint16_t holder_count, uint16_t* out_threshold);

/* --- Key generation (frost-ristretto255 DKG) ---------------------------- */

/// Part 1 for one holder among holder_count (5..50) holders, t derived.
/// Use this for the first key and for every key rotation.
/// On success the caller owns *out_state (pass it to storage_dkg_part2 or
/// free it) and *out_package (broadcast it, then storage_buffer_free).
int32_t storage_dkg_part1(uint16_t identifier,
                          uint16_t holder_count,
                          StorageDkgRound1State** out_state,
                          StorageBuffer* out_package);

/// Part 2. CONSUMES state on every return path.
/// @param round1 Round 1 package of every OTHER holder (identifier = sender)
/// On success writes a part 2 state and an array of SECRET packages; each
/// identifier names the RECIPIENT. Free the array with
/// storage_peer_buffers_free(array, *out_count).
int32_t storage_dkg_part2(StorageDkgRound1State* state,
                          const StoragePeerBytes* round1,
                          size_t round1_count,
                          StorageDkgRound2State** out_state,
                          StoragePeerBuffer** out_packages,
                          size_t* out_count);

/// Part 3. CONSUMES state on every return path.
/// @param round1 The SAME list given to storage_dkg_part2
/// @param round2 Packages addressed to this holder (identifier = sender)
/// On success writes the share handle, S (32 bytes), and the plan buffer.
/// Every holder must derive byte-identical plans; compare them before use.
int32_t storage_dkg_part3(StorageDkgRound2State* state,
                          const StoragePeerBytes* round1,
                          size_t round1_count,
                          const StoragePeerBytes* round2,
                          size_t round2_count,
                          StorageShare** out_share,
                          uint8_t out_storage_public_key[32],
                          StorageBuffer* out_plan);

/* --- Share refresh (frost refresh_dkg; not audited upstream) ------------- */

/// Part 1 for the holder of current, among new_holder_count holders. S and
/// t stay the same. The new set may drop holders and include holders that
/// storage_repair_part3 enrolled.
/// @return STORAGE_ERR_THRESHOLD_CHANGE when ceil(0.65 * new_holder_count)
///         differs from the current t; run a key rotation instead.
int32_t storage_refresh_part1(const StorageShare* current,
                              uint16_t new_holder_count,
                              StorageRefreshRound1State** out_state,
                              StorageBuffer* out_package);

/// Part 2. CONSUMES state on every return path. Output as storage_dkg_part2.
int32_t storage_refresh_part2(StorageRefreshRound1State* state,
                              const StoragePeerBytes* round1,
                              size_t round1_count,
                              StorageRefreshRound2State** out_state,
                              StoragePeerBuffer** out_packages,
                              size_t* out_count);

/// Part 3. CONSUMES state on every return path. Does NOT consume current;
/// keep it until the new plan is finalized, then free it.
/// @param current  This holder's share under old_plan, or its enrolled share
/// @param old_plan The plan being refreshed
/// @return STORAGE_ERR_BELOW_THRESHOLD when fewer than t participants are
///         holders of old_plan; STORAGE_ERR_SHARE_MISMATCH when current does
///         not match old_plan.
/// On success writes the refreshed share and the new plan, which lists only
/// the refresh participants. Old shares do not combine with new ones. Every
/// participant must derive byte-identical plans; compare them before use.
int32_t storage_refresh_part3(StorageRefreshRound2State* state,
                              const StoragePeerBytes* round1,
                              size_t round1_count,
                              const StoragePeerBytes* round2,
                              size_t round2_count,
                              const StorageShare* current,
                              const uint8_t* old_plan,
                              size_t old_plan_len,
                              StorageShare** out_share,
                              StorageBuffer* out_plan);

/* --- Holder enrollment (frost repairable; not audited upstream) ---------- */

/// Step 1, run by each helper. helpers lists every helper (this one
/// included): at least t distinct holders of plan. new_identifier must not
/// be in plan. Writes one SECRET 32-byte delta per helper (identifier =
/// recipient, this helper included). Free with storage_peer_buffers_free.
int32_t storage_repair_part1(const StorageShare* helper,
                             const uint8_t* plan,
                             size_t plan_len,
                             const uint16_t* helpers,
                             size_t helper_count,
                             uint16_t new_identifier,
                             StoragePeerBuffer** out_deltas,
                             size_t* out_count);

/// Step 2, run by each helper with the delta from every helper (identifier
/// = sender). Writes the SECRET 32-byte sigma for the new holder.
int32_t storage_repair_part2(const StorageShare* helper,
                             const StoragePeerBytes* deltas,
                             size_t delta_count,
                             uint8_t out_sigma[32]);

/// Step 3, run by the new holder with the sigma from every helper
/// (identifier = sender). Checks the result against the commitment
/// interpolated from plan. The share takes part in decryption only after a
/// refresh that includes the new holder.
/// @return STORAGE_ERR_BELOW_THRESHOLD with fewer than t sigmas;
///         STORAGE_ERR_CRYPTO when the result does not match the plan.
int32_t storage_repair_part3(const uint8_t* plan,
                             size_t plan_len,
                             uint16_t new_identifier,
                             const StoragePeerBytes* sigmas,
                             size_t sigma_count,
                             StorageShare** out_share);

/* --- Unlock -------------------------------------------------------------- */

/// Holder side: write the partial s_i*R and its DLEQ proof (96 bytes).
/// @return STORAGE_ERR_SHARE_MISMATCH when share is not the holder's
///         current share in plan; STORAGE_ERR_INVALID_ARGUMENT when R is not
///         a canonical, non-identity Ristretto encoding.
int32_t storage_partial_create(const StorageShare* share,
                               const uint8_t* plan,
                               size_t plan_len,
                               const StorageUnlockContext* context,
                               const uint8_t ephemeral_point[32],
                               uint8_t out_partial[96]);

/// Requester side: verify one partial from holder.
/// @return STORAGE_OK, or STORAGE_ERR_PROOF when it does not verify.
int32_t storage_partial_verify(const uint8_t* plan,
                               size_t plan_len,
                               const StorageUnlockContext* context,
                               const uint8_t ephemeral_point[32],
                               uint16_t holder,
                               const uint8_t* partial,
                               size_t partial_len);

/// Requester side: verify every partial (identifier = holder) and write the
/// SECRET compressed shared point s*R. Needs at least t partials from
/// distinct holders of plan; one invalid partial fails the call.
int32_t storage_combine(const uint8_t* plan,
                        size_t plan_len,
                        const StorageUnlockContext* context,
                        const uint8_t ephemeral_point[32],
                        const StoragePeerBytes* partials,
                        size_t partial_count,
                        uint8_t out_shared_point[32]);

/// Pick a random nonzero r; write R = r*G and the SECRET shared point r*S.
int32_t storage_encapsulate(const uint8_t storage_public_key[32],
                            uint8_t out_ephemeral_point[32],
                            uint8_t out_shared_point[32]);

/* --- Plans and shares ---------------------------------------------------- */

/// Parse and fully check a plan: 5..50 holders, identifiers, and every
/// commitment on one polynomial of degree t - 1 with constant term S.
int32_t storage_plan_validate(const uint8_t* plan,
                              size_t plan_len,
                              uint16_t* out_holder_count,
                              uint16_t* out_threshold,
                              uint8_t out_storage_public_key[32]);

/// Write the holder identifiers in ascending order into out_holders
/// (capacity entries; STORAGE_MAX_HOLDERS always suffices).
int32_t storage_plan_holders(const uint8_t* plan,
                             size_t plan_len,
                             uint16_t* out_holders,
                             size_t capacity,
                             size_t* out_count);

/// Write the public share commitment Y_i of holder.
int32_t storage_plan_commitment(const uint8_t* plan,
                                size_t plan_len,
                                uint16_t holder,
                                uint8_t out_commitment[32]);

/// Write the holder identifier, threshold, and S of a share.
int32_t storage_share_info(const StorageShare* share,
                           uint16_t* out_identifier,
                           uint16_t* out_threshold,
                           uint8_t out_storage_public_key[32]);

/// Serialize a share for sealed storage. The buffer holds the SECRET share;
/// copy it into guarded memory and release it with storage_buffer_free.
int32_t storage_share_serialize(const StorageShare* share, StorageBuffer* out_share);

/// Parse a share written by storage_share_serialize. Checks that the stored
/// commitment matches the secret.
int32_t storage_share_deserialize(const uint8_t* data, size_t len, StorageShare** out_share);

/* --- Release (all accept NULL) ------------------------------------------- */

/// Zeroize and free a buffer's bytes, then null its fields; a second call is
/// a no-op. Use only for buffers written by this library.
void storage_buffer_free(StorageBuffer* buffer);

/// Zeroize and free an array of peer buffers. Pass the exact pointer and
/// count the call returned.
void storage_peer_buffers_free(StoragePeerBuffer* buffers, size_t count);

/// Free UNUSED states. Never call these after a part 2 or part 3 call
/// consumed the state.
void storage_dkg_round1_state_free(StorageDkgRound1State* state);
void storage_dkg_round2_state_free(StorageDkgRound2State* state);
void storage_refresh_round1_state_free(StorageRefreshRound1State* state);
void storage_refresh_round2_state_free(StorageRefreshRound2State* state);

/// Free a share and zeroize it.
void storage_share_free(StorageShare* share);

#ifdef __cplusplus
}
#endif
