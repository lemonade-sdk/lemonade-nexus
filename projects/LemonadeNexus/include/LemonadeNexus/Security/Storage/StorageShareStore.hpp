#pragma once

// Where a storage holder keeps its shares of the storage secret (design B6).
//
// The target is the sealed boot set: Phase 6 adds SealedBlobStore
// (Security/Sealing/SealedBlobStore.hpp), which seals a blob to the vTPM
// through nexus-attestd under a sealing domain. The holder's shares belong in
// it under the domain kStorageShareDomain ("storage-share"). Until Phase 6 is
// merged, IStorageShareStore is the seam: it mirrors the SealedBlobStore
// seal/unseal calls and statuses, and FileStorageShareStore implements it with
// today's machine-bound wrapping, which B6 records as a documented limit.
//
// Wiring to SealedBlobStore is a thin adapter: seal() calls
// SealedBlobStore::seal(domain, plaintext) and maps SealReply::status;
// unseal() calls SealedBlobStore::unseal(domain) and moves
// UnsealReply::plaintext; remove() calls SealedBlobStore::remove(domain). The
// status values below have the same names and meanings as SealStatus.
//
// The stored value is one bundle: every share this holder keeps, each under
// the digest of the final plan it belongs to (the current plan, the retiring
// plan during its grace period, and the result of a session awaiting its
// final plan). The bundle is secret.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string_view>

namespace nexus::crypto {
class KeyWrappingService;
class SodiumCryptoService;
}  // namespace nexus::crypto

namespace nexus::security {

/// The sealing domain of the storage share (B6).
inline constexpr std::string_view kStorageShareDomain = "storage-share";

/// Outcome of one seal or unseal. Same names and meanings as SealStatus.
enum class ShareStoreStatus : uint8_t {
    Ok = 0,
    /// Nothing is stored under the domain.
    Missing,
    /// Sealing does not exist on this host or build. Retrying does not help.
    Unavailable,
    /// The sealing daemon could not be reached. Retrying may help.
    Unreachable,
    /// The platform state differs from the one the blob is bound to.
    PolicyMismatch,
    /// The stored value does not parse or does not authenticate.
    Corrupt,
    /// Another failure.
    Failed,
};

struct ShareUnsealResult {
    ShareStoreStatus status = ShareStoreStatus::Failed;
    /// The secret when status is Ok; empty otherwise.
    crypto::SecureBuffer plaintext;
};

/// Seals and unseals one secret per domain. Not thread-safe; the storage
/// service calls it from the security io thread.
class IStorageShareStore {
public:
    virtual ~IStorageShareStore() = default;

    /// Replaces the secret under `domain`. Ok means it is durable.
    [[nodiscard]] virtual ShareStoreStatus seal(std::string_view domain,
                                                std::span<const uint8_t> plaintext) = 0;

    /// The secret under `domain`, or Missing.
    [[nodiscard]] virtual ShareUnsealResult unseal(std::string_view domain) = 0;

    /// Removes the secret under `domain`. True when nothing remains.
    virtual bool remove(std::string_view domain) = 0;
};

/// The file-backed store for builds without sealing and for tests.
///
/// One file per domain, `<directory>/<domain>.share`, mode 0600, written
/// crash-atomically. With a KeyWrappingService the secret is encrypted under a
/// fresh random key that the wrapping service wraps with the machine binding
/// (the local secret and /etc/machine-id), like the epoch vote keys. Without
/// one (tests only) the file holds the plaintext.
class FileStorageShareStore final : public IStorageShareStore {
public:
    /// Not owning: `crypto` and `wrapping` must outlive the store. Pass both
    /// or neither. `binding_key` is this node's identity public key, the
    /// wrapping service's key-derivation input.
    FileStorageShareStore(std::filesystem::path directory,
                          crypto::SodiumCryptoService* crypto = nullptr,
                          crypto::KeyWrappingService* wrapping = nullptr,
                          crypto::Ed25519PublicKey binding_key = {});

    [[nodiscard]] ShareStoreStatus seal(std::string_view domain,
                                        std::span<const uint8_t> plaintext) override;
    [[nodiscard]] ShareUnsealResult unseal(std::string_view domain) override;
    bool remove(std::string_view domain) override;

    [[nodiscard]] std::filesystem::path path_of(std::string_view domain) const;

private:
    std::filesystem::path directory_;
    crypto::SodiumCryptoService* crypto_;
    crypto::KeyWrappingService* wrapping_;
    crypto::Ed25519PublicKey binding_key_{};
};

/// Every share a holder keeps, keyed by the digest of the final plan it
/// belongs to. Values are storage-threshold share encodings (secret).
using StorageShareBundle = std::map<Digest, crypto::SecureBuffer>;

/// The bundle's encoding, in guarded memory. Empty on an oversized entry.
[[nodiscard]] crypto::SecureBuffer encode_share_bundle(const StorageShareBundle& bundle);

/// nullopt when the bytes are not exactly one bundle encoding.
[[nodiscard]] std::optional<StorageShareBundle> decode_share_bundle(
    std::span<const uint8_t> bytes);

}  // namespace nexus::security
