#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace nexus::crypto  { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::core {

/// A minted server-admission token, optionally bound to one candidate key.
struct AdmissionTokenRecord {
    std::string candidate_pubkey;  // base64 Ed25519; empty = any candidate
    uint64_t    created_at{0};
    uint64_t    expires_at{0};
};

/// Single-use, short-TTL server-admission enrollment tokens ("adm_" + 64 hex).
/// Distinct prefix and store from device link tokens so the two flows can
/// never cross. Stored sha256-hashed under <data_root>/onboarding/admission_tokens/.
class AdmissionTokenStore {
public:
    AdmissionTokenStore(storage::FileStorageService& storage,
                        crypto::SodiumCryptoService& crypto);

    /// Mint a token; plaintext is only ever returned here. `candidate_pubkey`
    /// (when non-empty) must be a 32-byte base64 Ed25519 key and binds the token.
    [[nodiscard]] std::optional<std::pair<std::string, AdmissionTokenRecord>>
    mint(const std::string& candidate_pubkey, std::chrono::seconds ttl);

    /// Look up without consuming. Expired tokens are removed on sight; a bind
    /// mismatch fails WITHOUT removing (an interceptor can't burn a bound token).
    [[nodiscard]] std::optional<AdmissionTokenRecord>
    verify(std::string_view token, const std::string& candidate_pubkey) const;

    /// Verify and burn (single use). Concurrent losers get nullopt.
    [[nodiscard]] std::optional<AdmissionTokenRecord>
    consume(std::string_view token, const std::string& candidate_pubkey);

    static constexpr std::chrono::seconds kDefaultTtl{600};
    static constexpr std::chrono::seconds kMaxTtl{3600};

private:
    [[nodiscard]] std::filesystem::path token_path(std::string_view token) const;

    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;
};

} // namespace nexus::core
