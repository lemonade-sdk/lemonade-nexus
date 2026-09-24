#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Forward declarations — avoid pulling full headers into every TU
namespace nexus::crypto  { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }

// Unit test (tests/test_passkey_challenge.cpp): rewinds stored deadlines and
// fills the pending table instead of sleeping or taking a TTL parameter.
class PasskeyChallengeTest;

namespace nexus::auth {

/// A single stored WebAuthn credential (ECDSA-P256).
struct StoredCredential {
    std::string credential_id;   // base64url-encoded
    std::string user_id;
    std::vector<uint8_t> public_key_x;  // 32 bytes, P-256 affine X
    std::vector<uint8_t> public_key_y;  // 32 bytes, P-256 affine Y
    uint32_t sign_count{0};
    uint64_t created_at{0};
};

/// PassKey/FIDO2 authentication provider.
/// Implements real WebAuthn assertion verification using ECDSA-P256 (OpenSSL)
/// and file-based credential storage.
class PasskeyAuthProvider : public IAuthProvider<PasskeyAuthProvider> {
    friend class IAuthProvider<PasskeyAuthProvider>;
    friend class ::PasskeyChallengeTest;

private:
    static constexpr uint32_t kChallengeTtlSec = 60;       // challenge lifetime
    static constexpr std::size_t kChallengeSize = 32;      // issued nonce bytes
    static constexpr std::size_t kMaxPendingChallenges = 10000;
    static constexpr std::size_t kMaxChallengeUserIdLen = 128;
    // base64url of 32 bytes is 43 chars; anything longer cannot be ours.
    static constexpr std::size_t kMaxChallengeEncodedLen = 64;

public:
    /// Construct with dependencies.
    /// @param storage   File storage for credential persistence
    /// @param crypto    Sodium crypto for SHA-256 hashing
    /// @param rp_id     Relying Party ID (e.g. "lemonade-nexus.local")
    /// @param jwt_secret  HMAC secret for JWT session tokens
    PasskeyAuthProvider(nexus::storage::FileStorageService& storage,
                        nexus::crypto::SodiumCryptoService& crypto,
                        std::string rp_id,
                        std::string jwt_secret);

    /// Register a new WebAuthn credential.
    /// Expected JSON:
    ///   { "user_id": "...",
    ///     "credential_id": "base64url...",
    ///     "public_key_x": "hex...",
    ///     "public_key_y": "hex..." }
    [[nodiscard]] AuthResult do_register(const nlohmann::json& registration);

    /// Authenticate via WebAuthn assertion response.
    /// Expected JSON:
    ///   { "assertion": {
    ///       "credential_id": "base64url...",
    ///       "authenticator_data": "base64...",
    ///       "client_data_json": "base64...",
    ///       "signature": "base64..."
    ///     } }
    [[nodiscard]] AuthResult do_authenticate(const nlohmann::json& credentials);

    /// Issue a WebAuthn authentication challenge bound to `user_id`.
    /// The assertion's clientDataJSON must carry this exact challenge; it is
    /// valid for kChallengeTtlSec and is consumed on first presentation.
    /// nullopt when the user id is invalid or the pending table is exhausted.
    /// Returns JSON: {"challenge":"base64url(32 random bytes)","expires_at":unix_timestamp}
    [[nodiscard]] std::optional<nlohmann::json> issue_challenge(const std::string& user_id);

    [[nodiscard]] static constexpr std::string_view auth_provider_name() { return "passkey/fido2"; }

private:
    // --- credential storage ---
    // Atomic add-or-update of the credential in the user's file.
    // Caller must hold cache_mutex_ (serializes all credential file I/O).
    [[nodiscard]] bool persist_credential_file(const StoredCredential& cred);
    [[nodiscard]] std::optional<StoredCredential> lookup_credential(const std::string& credential_id);
    void load_credentials_from_disk();

    // --- WebAuthn assertion verification ---
    [[nodiscard]] bool verify_rp_id_hash(const std::vector<uint8_t>& authenticator_data);
    [[nodiscard]] static bool verify_user_present_flag(const std::vector<uint8_t>& authenticator_data);
    [[nodiscard]] bool verify_ecdsa_p256(const std::vector<uint8_t>& public_key_x,
                                          const std::vector<uint8_t>& public_key_y,
                                          const std::vector<uint8_t>& signed_data,
                                          const std::vector<uint8_t>& der_signature);

    // --- JWT ---
    [[nodiscard]] std::string generate_jwt(const std::string& user_id);

    // --- base64url helpers ---
    [[nodiscard]] static std::vector<uint8_t> base64url_decode(const std::string& input);

    // --- dependencies ---
    nexus::storage::FileStorageService& storage_;
    nexus::crypto::SodiumCryptoService& crypto_;
    std::string rp_id_;
    std::string jwt_secret_;

    // --- WebAuthn clientDataJSON verification ---
    // `credential_user_id` is the user the presented credential belongs to;
    // the challenge must have been issued for that user.
    [[nodiscard]] bool verify_client_data_json(const std::vector<uint8_t>& client_data_json_bytes,
                                               const std::string& credential_user_id);

    // Validate and atomically consume a challenge. Returns false when the
    // challenge was never issued, expired, or was not issued for this user.
    [[nodiscard]] bool consume_challenge(const std::vector<uint8_t>& challenge,
                                         const std::string& credential_user_id);

    // --- issued challenges: canonical base64(challenge_bytes) -> binding ---
    // Expiry is monotonic (steady_clock): wall-clock jumps cannot revive or
    // kill a challenge.
    struct PendingChallenge {
        std::string user_id;
        std::chrono::steady_clock::time_point deadline;
    };
    std::mutex challenge_mutex_;
    std::unordered_map<std::string, PendingChallenge> pending_challenges_;

    // --- credential persistence ---
    // Advances the sign count for an accepted assertion. `verified` is the
    // credential snapshot the assertion's signature was checked against;
    // under cache_mutex_ the stored entry must still be that same credential
    // (same owner and key), or the update is refused — a concurrent same-ID
    // key replacement must not be advanced by an old-key assertion.
    // Counter rules, checked and applied under cache_mutex_:
    //   stored 0, received 0   -> accept, no change (authenticator without counters)
    //   received > stored      -> persist, then publish
    //   anything else          -> reject (regression, replay, or 0 after nonzero)
    // Returns false on rejection, identity change, or persistence failure;
    // the cache and the previous file state are left untouched in all cases.
    [[nodiscard]] bool update_sign_count(const std::string& credential_id,
                                         uint32_t sign_count,
                                         const StoredCredential& verified);

    // --- credential cache (credential_id -> StoredCredential) ---
    // cache_mutex_ guards the cache, the conflict set, and ALL credential
    // file I/O: competing mutations are serialized, so the per-user
    // read-modify-rename cannot lose an update.
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, StoredCredential> credential_cache_;
    // credential_ids persisted under more than one identity. They stay
    // unavailable for authentication (absent from the cache) and for
    // registration (checked in do_register) until the files are repaired.
    std::unordered_set<std::string> conflicted_ids_;
    // Identities whose credential file exists but could not be read or
    // validated at load (unreadable, malformed, invalid structure). While any
    // identity is degraded, registration is refused outright: an unreadable
    // file may hold ownership claims, so absence of ownership cannot be
    // assumed. Authentication of readable credentials is unaffected.
    std::unordered_set<std::string> degraded_identities_;
    std::atomic<bool> cache_loaded_{false};

    // Test fault injection (friend PasskeyChallengeTest): the next credential
    // file write fails before touching disk.
    bool test_fail_next_persist_{false};
    // Test seam (friend PasskeyChallengeTest): invoked after assertion
    // verification, before the sign-count mutation, to complete a concurrent
    // key replacement deterministically.
    std::function<void()> test_hook_before_sign_count_update_;
};

} // namespace nexus::auth
