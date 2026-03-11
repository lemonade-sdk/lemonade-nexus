#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

// Forward declarations
namespace nexus::crypto  { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::auth {

/// Ed25519 identity-based authentication provider.
///
/// Two-phase challenge-response flow:
///   1. Client requests a challenge: POST /api/auth/challenge {"pubkey":"base64..."}
///      Server returns: {"challenge":"base64(32 random bytes)","expires_at":timestamp}
///   2. Client signs the challenge and authenticates: POST /api/auth
///      {"method":"ed25519","pubkey":"base64...","challenge":"base64...","signature":"base64..."}
///      Server verifies signature, auto-registers new pubkeys, returns JWT.
///
/// User ID is derived deterministically: hex(sha256(pubkey))[:32]
/// Credentials stored at data/credentials/{user_id}.json alongside passkey credentials.
class Ed25519AuthProvider : public IAuthProvider<Ed25519AuthProvider> {
    friend class IAuthProvider<Ed25519AuthProvider>;
public:
    Ed25519AuthProvider(nexus::storage::FileStorageService& storage,
                        nexus::crypto::SodiumCryptoService& crypto,
                        std::string jwt_secret);

    /// Authenticate via Ed25519 challenge-response.
    /// Expected JSON:
    ///   { "pubkey": "base64...",
    ///     "challenge": "base64...",
    ///     "signature": "base64..." }
    [[nodiscard]] AuthResult do_authenticate(const nlohmann::json& credentials);

    [[nodiscard]] static constexpr std::string_view auth_provider_name() { return "ed25519"; }

    /// Issue a challenge nonce for a given public key.
    /// Returns JSON: {"challenge":"base64...","expires_at":unix_timestamp}
    [[nodiscard]] nlohmann::json issue_challenge(const std::string& pubkey_b64);

    /// Register an Ed25519 public key with an explicit user_id.
    /// If user_id is empty, derives one from the pubkey.
    [[nodiscard]] AuthResult register_pubkey(const std::string& pubkey_b64,
                                              const std::string& user_id = "");

private:
    // Derive a deterministic user_id from an Ed25519 public key.
    [[nodiscard]] std::string derive_user_id(const crypto::Ed25519PublicKey& pubkey) const;

    // Look up the user_id for a registered pubkey. Returns empty if not found.
    [[nodiscard]] std::string lookup_user_by_pubkey(const std::string& pubkey_b64);

    // Auto-register a new pubkey and return the user_id.
    [[nodiscard]] std::string auto_register(const std::string& pubkey_b64,
                                             const crypto::Ed25519PublicKey& pubkey);

    // Persist pubkey→user_id mapping to credential file.
    bool save_ed25519_credential(const std::string& user_id, const std::string& pubkey_b64);

    // Load pubkey→user_id mappings from disk.
    void load_credentials_from_disk();

    // JWT generation
    [[nodiscard]] std::string generate_jwt(const std::string& user_id,
                                            const std::string& pubkey_b64);

    // Pending challenges: challenge_hex → {pubkey_b64, expires_at}
    struct PendingChallenge {
        std::string pubkey_b64;
        uint64_t    expires_at{0};
    };

    nexus::storage::FileStorageService& storage_;
    nexus::crypto::SodiumCryptoService& crypto_;
    std::string jwt_secret_;

    mutable std::mutex challenge_mutex_;
    std::unordered_map<std::string, PendingChallenge> pending_challenges_;

    // pubkey_b64 → user_id cache
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, std::string> pubkey_to_user_;
    std::atomic<bool> cache_loaded_{false};

    static constexpr uint32_t kChallengeTtlSec = 60;    // 60 second challenge window
    static constexpr std::size_t kChallengeSize = 32;    // 32 bytes of randomness
    static constexpr std::size_t kMaxPendingChallenges = 10000;
};

} // namespace nexus::auth
