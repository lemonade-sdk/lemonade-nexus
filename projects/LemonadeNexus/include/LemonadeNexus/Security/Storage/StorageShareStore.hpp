#pragma once

// Where a storage holder keeps its shares of the storage secret (design B6).
//
// IStorageShareStore has the SealedBlobStore seal/unseal calls and statuses.
// Two implementations:
//
// - SealedStorageShareStore: the sealed boot set plus a durable copy. It calls
//   SealedBlobStore (Security/Sealing/SealedBlobStore.hpp) under the domain
//   kStorageShareDomain ("storage-share"), with the same seal backend and
//   directory as the gossip identity (Core/BootSet.hpp), and keeps the same
//   share in a FileStorageShareStore so that a TPM that loses its state (a
//   virtual TPM without persistence, a cleared TPM, a replaced board) does not
//   destroy the holder's share. The server uses it when the host can seal.
// - FileStorageShareStore: hosts and builds that cannot seal, and tests. It
//   keeps today's machine-bound wrapping, which B6 records as a documented
//   limit.
//
// Why the durable copy. The storage secret is split across the Tier 1 holders
// with a threshold, so one holder's share is useless alone, and a holder that
// cannot read its share is a holder lost. When every holder reboots at once
// and every TPM comes back empty, the whole network loses its data key, and
// no copy of the shares exists anywhere else. The durable copy is the
// recovery path for that case. It is on the same disk as the local wrapping
// secret, so a reader of the whole disk learns this one share; that is the
// B6 limit of hosts without sealing, now the floor on every host.
//
// The stored value is one bundle: every share this holder keeps, each under
// the digest of the final plan it belongs to (the current plan, the retiring
// plan during its grace period, and the result of a session awaiting its
// final plan). The bundle is secret.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

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
/// (the local secret and /etc/machine-id), like the machine-bound copies of
/// the epoch vote keys (EpochStore). Without one (tests only) the file holds
/// the plaintext.
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

/// The share store status for a sealed-store status (same names and meanings).
[[nodiscard]] ShareStoreStatus share_store_status(SealStatus status);

/// The share store on the sealed boot set with a durable copy. Not owning:
/// `sealed` and `durable` must outlive the adapter.
///
/// `durable` (nullable) is the machine-bound file store. With it:
///
/// - seal() writes the durable copy first and then the sealed copy. Ok means
///   the durable copy is on disk; a seal backend failure is logged and the
///   sealed copy is written again at the next unseal().
/// - unseal() reads the sealed copy first. When it opens, a missing or
///   unreadable durable copy is rewritten from it (the first start after the
///   release that added the copy, or a damaged file). When the sealed copy
///   reports Missing, PolicyMismatch, Corrupt, Unavailable, Unreachable, or
///   Failed, the durable copy is read instead, and if it opens the secret is
///   sealed again under the running platform state, so the sealed copy is
///   current for the next start. Only when neither copy opens does the sealed
///   store's status stand, and nothing is invented.
/// - remove() removes both copies.
///
/// Without `durable` (tests) the adapter is the sealed store alone and every
/// status fails closed.
class SealedStorageShareStore final : public IStorageShareStore {
public:
    explicit SealedStorageShareStore(SealedBlobStore& sealed,
                                     FileStorageShareStore* durable = nullptr);

    [[nodiscard]] ShareStoreStatus seal(std::string_view domain,
                                        std::span<const uint8_t> plaintext) override;
    [[nodiscard]] ShareUnsealResult unseal(std::string_view domain) override;
    bool remove(std::string_view domain) override;

private:
    /// Seals `plaintext` and reads it back; true when the sealed copy opens to
    /// the same bytes.
    bool reseal_checked(std::string_view domain, std::span<const uint8_t> plaintext);

    SealedBlobStore& sealed_;
    FileStorageShareStore* durable_;
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
