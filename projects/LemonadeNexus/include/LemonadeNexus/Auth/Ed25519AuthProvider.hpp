#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

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

    /// Revoke an Ed25519 public key (device deletion); persisted. Idempotent.
    /// Returns false, and changes nothing, while the blocklist is unreadable.
    ///
    /// Adds the canonical key to the authoritative blocklist and, so stale
    /// readers of the credential store cannot resurrect a revoked key, also
    /// removes it from the in-memory pubkey→user cache and from the owning
    /// user's credential file (ed25519_pubkeys[]).
    bool revoke_pubkey(const std::string& pubkey_b64);

    /// Lift a revocation (operator un-revoke). Returns false when the key was
    /// not on the blocklist or the blocklist is unreadable. Persisted.
    bool unrevoke_pubkey(const std::string& pubkey_b64);

    /// True if this key is on the device-revocation blocklist, or when the
    /// blocklist (credentials/revoked.json) is unreadable (fail closed).
    [[nodiscard]] bool is_pubkey_revoked(const std::string& pubkey_b64);

    /// True if `user_id` is the user id (derive_user_id) of a revoked key, or
    /// when the blocklist is unreadable (fail closed). A session token that
    /// names no key (a passkey session) is refused by this check.
    [[nodiscard]] bool is_user_revoked(const std::string& user_id);

    /// Verify the fresh proof of an account deletion: `signature_b64` is the
    /// key's Ed25519 signature over account_delete_proof_message (see
    /// AccountDeletionProof.hpp) for a challenge this provider issued to this
    /// key. Consumes the challenge (single use, kChallengeTtlSec). Refuses a
    /// revoked key. Issues no session and registers nothing. On refusal,
    /// `error` receives the reason. Thread-safe.
    [[nodiscard]] bool verify_account_delete_proof(const std::string& pubkey_b64,
                                                   const std::string& challenge_b64,
                                                   const std::string& signature_b64,
                                                   std::string& error);

private:
    // Check and consume the pending challenge `challenge_b64` for the canonical
    // key `pubkey_b64`. Empty on success, otherwise the refusal reason.
    [[nodiscard]] std::string consume_challenge(const std::string& challenge_b64,
                                                const std::string& pubkey_b64);

    // Derive a deterministic user_id from an Ed25519 public key.
    [[nodiscard]] std::string derive_user_id(const crypto::Ed25519PublicKey& pubkey) const;

    // Look up the user_id for a registered pubkey. Returns empty if not found.
    [[nodiscard]] std::string lookup_user_by_pubkey(const std::string& pubkey_b64);

    // Auto-register a new pubkey and return the user_id, or empty when the
    // file cannot be written or a credential file is unreadable.
    [[nodiscard]] std::string auto_register(const std::string& pubkey_b64,
                                             const crypto::Ed25519PublicKey& pubkey);

    // Persist pubkey→user_id mapping to credential file. Called with
    // cache_mutex_ held. Refuses, and leaves the file as it is, when the file
    // is unreadable or names another user.
    bool save_ed25519_credential(const std::string& user_id, const std::string& pubkey_b64);

    // Remove a pubkey from the owning user's credential file (ed25519_pubkeys[]).
    // Called with cache_mutex_ held. A missing user or a missing entry is not an error.
    bool remove_ed25519_credential(const std::string& user_id, const std::string& pubkey_b64);

    // Write the current blocklist to credentials/revoked.json.
    // Called with cache_mutex_ held.
    bool persist_revoked_list();

    // Load pubkey→user_id mappings and the blocklist through the storage
    // vault (CredentialFile.hpp). Sets cache_loaded_ only when every file
    // opened; otherwise the next call reads again.
    void load_credentials_from_disk();

    // Loads if needed; false while the blocklist is unreadable.
    [[nodiscard]] bool revocations_readable();

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

    // Device-revocation blocklist (deleted devices). Guarded by cache_mutex_,
    // loaded lazily alongside pubkey_to_user_ from credentials/revoked.json.
    std::unordered_set<std::string> revoked_pubkeys_;
    // derive_user_id of each decodable revoked key. Guarded by cache_mutex_.
    std::unordered_set<std::string> revoked_user_ids_;
    // The last load found an unreadable user credential file: a key that is
    // not in the cache may belong to it, so no new identity is registered.
    // Guarded by cache_mutex_.
    bool store_degraded_ = false;
    // The last load could not read the blocklist: every key and user counts
    // as revoked, and the blocklist is not written. Guarded by cache_mutex_.
    bool revocations_unreadable_ = false;

    // derive_user_id for a base64 key, or empty when it does not decode to 32 bytes.
    [[nodiscard]] std::string user_id_of(const std::string& pubkey_b64) const;

    static constexpr uint32_t kChallengeTtlSec = 60;    // 60 second challenge window
    static constexpr std::size_t kChallengeSize = 32;    // 32 bytes of randomness
    static constexpr std::size_t kMaxPendingChallenges = 10000;
};

} // namespace nexus::auth
