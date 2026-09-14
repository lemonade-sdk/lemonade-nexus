#pragma once

// The FROST(Ed25519, SHA-512) primitive boundary.
//
// This is the only place that touches the frost-ffi crate. Secret material —
// DKG states, key shares, signing nonces — lives behind opaque handles in
// Rust memory and never crosses into C++ as bytes. A consumed handle is
// released on every path, so a nonce cannot sign twice through this type.
//
// The provider knows cryptography only. It knows nothing about epochs, Tier 1,
// consensus, or which objects deserve a signature.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

struct FrostDkgRound1State;
struct FrostDkgRound2State;
struct FrostKeyPackage;
struct FrostSigningNonces;

namespace nexus::crypto {

using ParticipantIndex = uint16_t;
using FrostBytes = std::vector<uint8_t>;
using FrostPeerBytesMap = std::map<ParticipantIndex, FrostBytes>;

enum class FrostStatus : int8_t {
    Ok,
    InvalidArgument,
    CryptoFailure,
    Serialization,
    Internal,
};

template <typename T>
struct FrostResult {
    std::optional<T> value;
    FrostStatus status = FrostStatus::Internal;

    [[nodiscard]] bool ok() const { return status == FrostStatus::Ok && value.has_value(); }
};

/// The signing share for one epoch group. Destroyed with the object; never
/// serialized, so a share cannot outlive the process by accident.
class FrostKeyShare {
public:
    FrostKeyShare() = default;
    explicit FrostKeyShare(::FrostKeyPackage* handle) : handle_(handle) {}
    FrostKeyShare(FrostKeyShare&& other) noexcept;
    FrostKeyShare& operator=(FrostKeyShare&& other) noexcept;
    FrostKeyShare(const FrostKeyShare&) = delete;
    FrostKeyShare& operator=(const FrostKeyShare&) = delete;
    ~FrostKeyShare();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    [[nodiscard]] std::optional<ParticipantIndex> identifier() const;
    [[nodiscard]] const ::FrostKeyPackage* raw() const { return handle_; }

private:
    ::FrostKeyPackage* handle_ = nullptr;
};

/// Fresh nonces for exactly one signing run. FrostProvider::sign consumes
/// them; an unused object wipes them on destruction.
class FrostNonces {
public:
    FrostNonces() = default;
    explicit FrostNonces(::FrostSigningNonces* handle) : handle_(handle) {}
    FrostNonces(FrostNonces&& other) noexcept;
    FrostNonces& operator=(FrostNonces&& other) noexcept;
    FrostNonces(const FrostNonces&) = delete;
    FrostNonces& operator=(const FrostNonces&) = delete;
    ~FrostNonces();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    [[nodiscard]] ::FrostSigningNonces* release();

private:
    ::FrostSigningNonces* handle_ = nullptr;
};

class FrostDkgRound1 {
public:
    FrostDkgRound1() = default;
    FrostDkgRound1(::FrostDkgRound1State* handle, FrostBytes package)
        : handle_(handle), package_(std::move(package)) {}
    FrostDkgRound1(FrostDkgRound1&& other) noexcept;
    FrostDkgRound1& operator=(FrostDkgRound1&& other) noexcept;
    FrostDkgRound1(const FrostDkgRound1&) = delete;
    FrostDkgRound1& operator=(const FrostDkgRound1&) = delete;
    ~FrostDkgRound1();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    /// The package to broadcast to every other participant.
    [[nodiscard]] const FrostBytes& package() const { return package_; }
    [[nodiscard]] ::FrostDkgRound1State* release();

private:
    ::FrostDkgRound1State* handle_ = nullptr;
    FrostBytes package_;
};

class FrostDkgRound2 {
public:
    FrostDkgRound2() = default;
    FrostDkgRound2(::FrostDkgRound2State* handle, FrostPeerBytesMap packages)
        : handle_(handle), packages_(std::move(packages)) {}
    FrostDkgRound2(FrostDkgRound2&& other) noexcept;
    FrostDkgRound2& operator=(FrostDkgRound2&& other) noexcept;
    FrostDkgRound2(const FrostDkgRound2&) = delete;
    FrostDkgRound2& operator=(const FrostDkgRound2&) = delete;
    ~FrostDkgRound2();

    [[nodiscard]] bool valid() const { return handle_ != nullptr; }
    /// Keyed by RECIPIENT: each package goes to exactly that participant over
    /// the authenticated pairwise channel, never broadcast.
    [[nodiscard]] const FrostPeerBytesMap& packages_for_recipients() const { return packages_; }
    [[nodiscard]] ::FrostDkgRound2State* release();

private:
    ::FrostDkgRound2State* handle_ = nullptr;
    FrostPeerBytesMap packages_;
};

struct FrostDkgOutcome {
    FrostKeyShare key_share;
    Ed25519PublicKey group_public_key{};
    /// Needed by aggregate(); public, safe to share with the signer set.
    FrostBytes public_key_package;
};

struct FrostCommitment {
    FrostNonces nonces;
    FrostBytes commitments;
};

class FrostProvider {
public:
    [[nodiscard]] static FrostResult<FrostDkgRound1> dkg_part1(ParticipantIndex identifier,
                                                              uint16_t max_signers,
                                                              uint16_t min_signers);

    /// round1_packages: every OTHER participant's round-1 package, keyed by
    /// sender. Consumes round1 on every path.
    [[nodiscard]] static FrostResult<FrostDkgRound2> dkg_part2(
        FrostDkgRound1&& round1, const FrostPeerBytesMap& round1_packages);

    /// round2_packages: the packages addressed to this participant, keyed by
    /// sender. Consumes round2 on every path.
    [[nodiscard]] static FrostResult<FrostDkgOutcome> dkg_part3(
        FrostDkgRound2&& round2, const FrostPeerBytesMap& round1_packages,
        const FrostPeerBytesMap& round2_packages);

    [[nodiscard]] static FrostResult<FrostCommitment> signing_commit(const FrostKeyShare& share);

    /// commitments: ALL selected signers including this one, keyed by signer.
    /// Consumes nonces on every path — a retry needs a new signing_commit.
    [[nodiscard]] static FrostResult<FrostBytes> sign(const FrostKeyShare& share,
                                                      FrostNonces&& nonces,
                                                      std::span<const uint8_t> message,
                                                      const FrostPeerBytesMap& commitments);

    [[nodiscard]] static FrostResult<Ed25519Signature> aggregate(
        std::span<const uint8_t> message, const FrostPeerBytesMap& commitments,
        const FrostPeerBytesMap& signature_shares, std::span<const uint8_t> public_key_package);

    /// Plain Ed25519 verification under the group public key.
    [[nodiscard]] static bool verify(const Ed25519PublicKey& group_public_key,
                                     std::span<const uint8_t> message,
                                     const Ed25519Signature& signature);
};

}  // namespace nexus::crypto
