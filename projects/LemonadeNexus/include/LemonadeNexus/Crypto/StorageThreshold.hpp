#pragma once

// The threshold storage key boundary (design Part B, Phase 4).
//
// This is the only place that touches the storage-threshold crate. The
// storage secret s is shared among at most 50 holders with threshold
// t = ceil(0.65 * n) and is never assembled. A server wraps its data key to
// the storage public key S with ECIES; unwrapping needs t holders' partials
// s_i*R, each with a DLEQ proof bound to the unlock request.
//
// The storage key is its own key role. It never signs and never authorizes.
// This type knows cryptography only: it knows nothing about holder plans in
// consensus, attestation, or which requester deserves a partial.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

struct StorageShare;
struct StorageDkgRound1State;
struct StorageDkgRound2State;
struct StorageRefreshRound1State;
struct StorageRefreshRound2State;

namespace nexus::crypto {

class SodiumCryptoService;

/// Nonzero holder index assigned by the holder plan.
using StorageHolderId = uint16_t;
using StorageBytes = std::vector<uint8_t>;
/// Messages keyed by holder: the sender for inputs, the recipient for outputs.
using StoragePeerBytesMap = std::map<StorageHolderId, StorageBytes>;
/// A canonical Ristretto255 point encoding.
using StoragePoint = std::array<uint8_t, 32>;

inline constexpr std::size_t kStoragePartialSize = 96;
/// s_i*R (32 bytes) followed by the DLEQ proof (64 bytes).
using StoragePartial = std::array<uint8_t, kStoragePartialSize>;

enum class StorageStatus : int8_t {
    Ok,
    InvalidArgument,
    CryptoFailure,
    Serialization,
    /// Fewer than t distinct partials, helpers, or old holders.
    BelowThreshold,
    /// The new holder count needs another threshold; rotate the key.
    ThresholdChange,
    /// Holder count outside 5..50 (first key) or 3..50 (rotation, refresh,
    /// plan).
    HolderCount,
    /// A partial failed DLEQ verification, or its holder is not in the plan.
    InvalidProof,
    /// The share does not belong to the plan (stale, removed, or another key).
    ShareMismatch,
    Internal,
};

template <typename T>
struct StorageResult {
    std::optional<T> value;
    StorageStatus status = StorageStatus::Internal;

    [[nodiscard]] bool ok() const { return status == StorageStatus::Ok && value.has_value(); }
};

/// The request fields every partial is bound to. The requester and every
/// holder must use identical values; a partial made for other values fails
/// verification. `plan_digest` is the digest of the finalized holder plan.
struct StorageUnlockContext {
    std::array<uint8_t, 32> network_id{};
    uint64_t epoch = 0;
    std::array<uint8_t, 32> plan_digest{};
    std::array<uint8_t, 32> request_nonce{};
};

/// One holder's share of the storage secret. Zeroized on destruction.
/// Persist it only through StorageThreshold::serialize_share into sealed
/// storage.
class StorageKeyShare {
public:
    StorageKeyShare() = default;
    explicit StorageKeyShare(::StorageShare* handle) : handle_(handle) {}
    StorageKeyShare(StorageKeyShare&& other) noexcept;
    StorageKeyShare& operator=(StorageKeyShare&& other) noexcept;
    StorageKeyShare(const StorageKeyShare&) = delete;
    StorageKeyShare& operator=(const StorageKeyShare&) = delete;
    ~StorageKeyShare();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    [[nodiscard]] std::optional<StorageHolderId> holder() const;
    [[nodiscard]] std::optional<uint16_t> threshold() const;
    [[nodiscard]] std::optional<StoragePoint> storage_public_key() const;
    [[nodiscard]] const ::StorageShare* raw() const { return handle_; }

private:
    ::StorageShare* handle_ = nullptr;
};

/// Key generation state after part 1, with the package to broadcast.
class StorageDkgRound1 {
public:
    StorageDkgRound1() = default;
    StorageDkgRound1(::StorageDkgRound1State* handle, StorageBytes package)
        : handle_(handle), package_(std::move(package)) {}
    StorageDkgRound1(StorageDkgRound1&& other) noexcept;
    StorageDkgRound1& operator=(StorageDkgRound1&& other) noexcept;
    StorageDkgRound1(const StorageDkgRound1&) = delete;
    StorageDkgRound1& operator=(const StorageDkgRound1&) = delete;
    ~StorageDkgRound1();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    /// Broadcast to every other holder.
    [[nodiscard]] const StorageBytes& package() const { return package_; }
    [[nodiscard]] ::StorageDkgRound1State* release();

private:
    ::StorageDkgRound1State* handle_ = nullptr;
    StorageBytes package_;
};

/// Key generation state after part 2, with the secret per-recipient packages.
class StorageDkgRound2 {
public:
    StorageDkgRound2() = default;
    StorageDkgRound2(::StorageDkgRound2State* handle, StoragePeerBytesMap packages)
        : handle_(handle), packages_(std::move(packages)) {}
    StorageDkgRound2(StorageDkgRound2&& other) noexcept;
    StorageDkgRound2& operator=(StorageDkgRound2&& other) noexcept;
    StorageDkgRound2(const StorageDkgRound2&) = delete;
    StorageDkgRound2& operator=(const StorageDkgRound2&) = delete;
    ~StorageDkgRound2();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    /// Keyed by RECIPIENT. Secret: send each package only to that holder
    /// over an authenticated, encrypted pairwise channel.
    [[nodiscard]] const StoragePeerBytesMap& packages_for_recipients() const { return packages_; }
    [[nodiscard]] ::StorageDkgRound2State* release();

private:
    ::StorageDkgRound2State* handle_ = nullptr;
    StoragePeerBytesMap packages_;
};

/// Refresh state after part 1, with the package to broadcast.
class StorageRefreshRound1 {
public:
    StorageRefreshRound1() = default;
    StorageRefreshRound1(::StorageRefreshRound1State* handle, StorageBytes package)
        : handle_(handle), package_(std::move(package)) {}
    StorageRefreshRound1(StorageRefreshRound1&& other) noexcept;
    StorageRefreshRound1& operator=(StorageRefreshRound1&& other) noexcept;
    StorageRefreshRound1(const StorageRefreshRound1&) = delete;
    StorageRefreshRound1& operator=(const StorageRefreshRound1&) = delete;
    ~StorageRefreshRound1();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    [[nodiscard]] const StorageBytes& package() const { return package_; }
    [[nodiscard]] ::StorageRefreshRound1State* release();

private:
    ::StorageRefreshRound1State* handle_ = nullptr;
    StorageBytes package_;
};

/// Refresh state after part 2, with the secret per-recipient packages.
class StorageRefreshRound2 {
public:
    StorageRefreshRound2() = default;
    StorageRefreshRound2(::StorageRefreshRound2State* handle, StoragePeerBytesMap packages)
        : handle_(handle), packages_(std::move(packages)) {}
    StorageRefreshRound2(StorageRefreshRound2&& other) noexcept;
    StorageRefreshRound2& operator=(StorageRefreshRound2&& other) noexcept;
    StorageRefreshRound2(const StorageRefreshRound2&) = delete;
    StorageRefreshRound2& operator=(const StorageRefreshRound2&) = delete;
    ~StorageRefreshRound2();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    /// Keyed by RECIPIENT. Secret, as for StorageDkgRound2.
    [[nodiscard]] const StoragePeerBytesMap& packages_for_recipients() const { return packages_; }
    [[nodiscard]] ::StorageRefreshRound2State* release();

private:
    ::StorageRefreshRound2State* handle_ = nullptr;
    StoragePeerBytesMap packages_;
};

/// Output of key generation or refresh.
struct StorageKeyOutcome {
    StorageKeyShare share;
    StoragePoint storage_public_key{};
    /// Public holder plan: S and every holder's share commitment. Every
    /// holder derives the same bytes; compare them before adopting the plan.
    StorageBytes plan;
};

/// Result of a full plan check.
struct StoragePlanInfo {
    uint16_t holder_count = 0;
    uint16_t threshold = 0;
    StoragePoint storage_public_key{};
    /// Ascending.
    std::vector<StorageHolderId> holders;
};

/// A data key wrapped to S. Every field is public.
struct StorageWrappedDataKey {
    StoragePoint storage_public_key{};
    /// R = r*G; holders compute their partials for this point.
    StoragePoint ephemeral_point{};
    EncryptedBlob ciphertext;
};

class StorageThreshold {
public:
    /// The fewest holders the first storage key can be created with.
    static constexpr uint16_t kMinHolders = 5;
    /// The fewest holders a rotation or a refresh can keep after losses
    /// (4 holders give t = 3, 3 holders give t = 2). No plan is smaller.
    static constexpr uint16_t kMinReshareHolders = 3;
    static constexpr uint16_t kMaxHolders = 50;
    /// Upper bound on a wrapped data key and on a server identifier.
    static constexpr std::size_t kMaxDataKeySize = 256;
    static constexpr std::size_t kMaxServerIdSize = 256;

    /// t = ceil(0.65 * holder_count) for 1 <= holder_count <= 50, computed
    /// by the crate.
    [[nodiscard]] static std::optional<uint16_t> threshold_for(uint16_t holder_count);

    // --- Key generation: the first key and every rotation --------------------

    /// Part 1 of the first key, for one holder among holder_count (5..50)
    /// holders.
    [[nodiscard]] static StorageResult<StorageDkgRound1> dkg_part1(StorageHolderId holder,
                                                                   uint16_t holder_count);
    /// Part 1 of a key rotation, for one holder among holder_count (3..50)
    /// holders. Parts 2 and 3 are the same as for the first key.
    [[nodiscard]] static StorageResult<StorageDkgRound1> dkg_rotation_part1(
        StorageHolderId holder, uint16_t holder_count);
    /// round1: every OTHER holder's package, keyed by sender. Consumes round1
    /// on every path.
    [[nodiscard]] static StorageResult<StorageDkgRound2> dkg_part2(
        StorageDkgRound1&& round1, const StoragePeerBytesMap& round1_packages);
    /// round2_packages: the packages addressed to this holder, keyed by
    /// sender. Consumes round2 on every path.
    [[nodiscard]] static StorageResult<StorageKeyOutcome> dkg_part3(
        StorageDkgRound2&& round2, const StoragePeerBytesMap& round1_packages,
        const StoragePeerBytesMap& round2_packages);

    // --- Share refresh: same S and t, possibly a new holder set --------------

    /// Fails with ThresholdChange when the new count needs another t.
    [[nodiscard]] static StorageResult<StorageRefreshRound1> refresh_part1(
        const StorageKeyShare& current, uint16_t new_holder_count);
    [[nodiscard]] static StorageResult<StorageRefreshRound2> refresh_part2(
        StorageRefreshRound1&& round1, const StoragePeerBytesMap& round1_packages);
    /// current: this holder's share under old_plan, or its enrolled share.
    /// Does not consume current; keep it until the new plan is finalized.
    /// Fails with BelowThreshold when fewer than t participants are holders
    /// of old_plan.
    [[nodiscard]] static StorageResult<StorageKeyOutcome> refresh_part3(
        StorageRefreshRound2&& round2, const StoragePeerBytesMap& round1_packages,
        const StoragePeerBytesMap& round2_packages, const StorageKeyShare& current,
        std::span<const uint8_t> old_plan);

    // --- Holder enrollment ---------------------------------------------------

    /// Run by each helper; helpers lists at least t holders of plan, this
    /// one included. Returns one secret 32-byte delta per helper, keyed by
    /// recipient.
    [[nodiscard]] static StorageResult<StoragePeerBytesMap> repair_part1(
        const StorageKeyShare& helper, std::span<const uint8_t> plan,
        std::span<const StorageHolderId> helpers, StorageHolderId new_holder);
    /// Run by each helper with every helper's delta, keyed by sender.
    /// Returns the secret 32-byte sigma for the new holder.
    [[nodiscard]] static StorageResult<StorageBytes> repair_part2(
        const StorageKeyShare& helper, const StoragePeerBytesMap& deltas);
    /// Run by the new holder with every helper's sigma, keyed by sender. The
    /// share decrypts only after a refresh that includes the new holder.
    [[nodiscard]] static StorageResult<StorageKeyShare> repair_part3(
        std::span<const uint8_t> plan, StorageHolderId new_holder,
        const StoragePeerBytesMap& sigmas);

    // --- Unlock ---------------------------------------------------------------

    /// Holder side. Fails with ShareMismatch when share is not the holder's
    /// current share in plan.
    [[nodiscard]] static StorageResult<StoragePartial> create_partial(
        const StorageKeyShare& share, std::span<const uint8_t> plan,
        const StorageUnlockContext& context, const StoragePoint& ephemeral_point);

    /// Requester side: check one partial as it arrives.
    [[nodiscard]] static StorageStatus verify_partial(std::span<const uint8_t> plan,
                                                      const StorageUnlockContext& context,
                                                      const StoragePoint& ephemeral_point,
                                                      StorageHolderId holder,
                                                      std::span<const uint8_t> partial);

    // --- Data-key wrap (ECIES) -----------------------------------------------
    //
    // Wrap key = HKDF-SHA256(ikm = r*S, info = LP("LEMONADE-NEXUS-STORAGE-V1")
    // || LP("data-key-wrap") || LP(S) || LP(R) || LP(server_id)). The AEAD is
    // the XChaCha20-Poly1305 EncryptedBlob with AAD
    // aead_aad("storage-data-key", {S, R, server_id}). The shared point and
    // the wrap key exist only in guarded memory and are wiped before return.

    /// Wrap data_key (1..256 bytes) to storage_public_key for server_id
    /// (1..256 bytes).
    [[nodiscard]] static StorageResult<StorageWrappedDataKey> wrap_data_key(
        SodiumCryptoService& crypto, const StoragePoint& storage_public_key,
        std::span<const uint8_t> data_key, std::span<const uint8_t> server_id);

    /// Verify the partials (keyed by holder; at least t), combine them, and
    /// unwrap. Fails with InvalidArgument when the wrapped key names another
    /// S than plan, BelowThreshold with fewer than t partials, InvalidProof
    /// when any partial fails, and CryptoFailure when the AEAD rejects.
    [[nodiscard]] static StorageResult<SecureBuffer> unwrap_data_key(
        SodiumCryptoService& crypto, const StorageWrappedDataKey& wrapped,
        std::span<const uint8_t> plan, const StorageUnlockContext& context,
        const StoragePeerBytesMap& partials, std::span<const uint8_t> server_id);

    // --- Plans and shares -----------------------------------------------------

    /// Full plan check: 3..50 holders, t derived, and every commitment on one
    /// polynomial of degree t - 1 with constant term S.
    [[nodiscard]] static StorageResult<StoragePlanInfo> validate_plan(std::span<const uint8_t> plan);

    /// The public share commitment Y_i of holder.
    [[nodiscard]] static StorageResult<StoragePoint> plan_commitment(std::span<const uint8_t> plan,
                                                                     StorageHolderId holder);

    /// The share's secret encoding, for sealed storage only.
    [[nodiscard]] static StorageResult<SecureBuffer> serialize_share(const StorageKeyShare& share);
    [[nodiscard]] static StorageResult<StorageKeyShare> deserialize_share(
        std::span<const uint8_t> bytes);
};

}  // namespace nexus::crypto
