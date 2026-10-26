#include <LemonadeNexus/Auth/Ed25519AuthProvider.hpp>

#include <LemonadeNexus/Auth/AccountDeletionProof.hpp>
#include <LemonadeNexus/Auth/CredentialFile.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>

namespace nexus::auth {

using json = nlohmann::json;

namespace {

// File-local helpers. They take no locks; callers holding cache_mutex_ may
// invoke them, but they never lock themselves (same discipline as before).

/// Current Unix time in whole seconds.
uint64_t now_unix_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace

// ============================================================================
// Constructor
// ============================================================================

Ed25519AuthProvider::Ed25519AuthProvider(storage::FileStorageService& storage,
                                         crypto::SodiumCryptoService& crypto,
                                         std::string jwt_secret)
    : storage_(storage)
    , crypto_(crypto)
    , jwt_secret_(std::move(jwt_secret))
{
}

// ============================================================================
// Challenge issuance
// ============================================================================

json Ed25519AuthProvider::issue_challenge(const std::string& raw_pubkey_b64) {
    // Bind the challenge to the canonical key so do_authenticate's compare can't
    // be sidestepped by presenting a different encoding of the same key.
    const auto pubkey_b64 = crypto::canonical_key_b64(raw_pubkey_b64);

    // Generate 32 random bytes as the challenge nonce
    std::array<uint8_t, kChallengeSize> nonce{};
    crypto_.random_bytes(std::span<uint8_t>(nonce));

    auto challenge_b64 = crypto::to_base64(std::span<const uint8_t>(nonce));
    auto now = now_unix_seconds();

    {
        std::lock_guard lock(challenge_mutex_);

        // Evict expired challenges
        if (pending_challenges_.size() > kMaxPendingChallenges / 2) {
            std::erase_if(pending_challenges_, [now](const auto& kv) {
                return kv.second.expires_at <= now;
            });
        }

        pending_challenges_[challenge_b64] = PendingChallenge{
            .pubkey_b64 = pubkey_b64,
            .expires_at = now + kChallengeTtlSec,
        };
    }

    spdlog::debug("[ed25519] Issued challenge for pubkey {}", pubkey_b64.substr(0, 16));

    return json{
        {"challenge",  challenge_b64},
        {"expires_at", now + kChallengeTtlSec},
    };
}

// ============================================================================
// Authentication (challenge-response verification)
// ============================================================================

AuthResult Ed25519AuthProvider::do_authenticate(const json& credentials) {
    const auto raw_pubkey_b64 = credentials.value("pubkey", std::string{});
    const auto challenge_b64  = credentials.value("challenge", std::string{});
    const auto signature_b64  = credentials.value("signature", std::string{});

    if (raw_pubkey_b64.empty() || challenge_b64.empty() || signature_b64.empty()) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Missing required fields: pubkey, challenge, signature"
        };
    }

    // Decode the public key
    std::vector<uint8_t> pubkey_bytes;
    try {
        pubkey_bytes = crypto::from_base64(raw_pubkey_b64);
    } catch (const std::exception& e) {
        return AuthResult{
            .authenticated = false,
            .error_message = std::string("Invalid pubkey base64: ") + e.what()
        };
    }

    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Ed25519 public key must be 32 bytes"
        };
    }

    crypto::Ed25519PublicKey pubkey{};
    std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());

    // Canonical form from here down: a variant encoding of the same key would
    // otherwise miss the revocation set and auto-register as a fresh identity.
    const auto pubkey_b64 = crypto::to_base64(std::span<const uint8_t>(pubkey));

    // Without the revocation list no key can be checked against it.
    if (!revocations_readable()) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Credential store unavailable"
        };
    }

    // Revoked (deleted) devices can't re-authenticate or re-join.
    if (is_pubkey_revoked(pubkey_b64)) {
        spdlog::warn("[ed25519] Rejected authentication for revoked pubkey {}",
                     pubkey_b64.substr(0, 16));
        return AuthResult{
            .authenticated = false,
            .error_message = "This identity has been revoked"
        };
    }

    // Validate and consume the challenge
    if (auto refusal = consume_challenge(challenge_b64, pubkey_b64); !refusal.empty()) {
        return AuthResult{.authenticated = false, .error_message = std::move(refusal)};
    }

    // Decode the challenge and signature
    std::vector<uint8_t> challenge_bytes, signature_bytes;
    try {
        challenge_bytes = crypto::from_base64(challenge_b64);
        signature_bytes = crypto::from_base64(signature_b64);
    } catch (const std::exception& e) {
        return AuthResult{
            .authenticated = false,
            .error_message = std::string("Invalid base64: ") + e.what()
        };
    }

    if (signature_bytes.size() != crypto::kEd25519SignatureSize) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Ed25519 signature must be 64 bytes"
        };
    }

    crypto::Ed25519Signature signature{};
    std::copy(signature_bytes.begin(), signature_bytes.end(), signature.begin());

    // Verify the signature over the challenge bytes
    if (!crypto_.ed25519_verify(pubkey,
                                 std::span<const uint8_t>(challenge_bytes),
                                 signature)) {
        spdlog::warn("[ed25519] Signature verification failed for pubkey {}",
                     pubkey_b64.substr(0, 16));
        return AuthResult{
            .authenticated = false,
            .error_message = "Ed25519 signature verification failed"
        };
    }

    // Look up or auto-register the user
    auto user_id = lookup_user_by_pubkey(pubkey_b64);
    if (user_id.empty()) {
        user_id = auto_register(pubkey_b64, pubkey);
        if (user_id.empty()) {
            return AuthResult{
                .authenticated = false,
                .error_message = "Failed to register Ed25519 identity"
            };
        }
        spdlog::info("[ed25519] Auto-registered new identity: user_id={}, pubkey={}",
                     user_id, pubkey_b64.substr(0, 16));
    }

    spdlog::info("[ed25519] Authenticated user '{}' via Ed25519 pubkey {}",
                 user_id, pubkey_b64.substr(0, 16));

    return AuthResult{
        .authenticated = true,
        .user_id       = user_id,
        .session_token = generate_jwt(user_id, pubkey_b64),
    };
}

std::string Ed25519AuthProvider::consume_challenge(const std::string& challenge_b64,
                                                   const std::string& pubkey_b64) {
    std::lock_guard lock(challenge_mutex_);
    auto it = pending_challenges_.find(challenge_b64);
    if (it == pending_challenges_.end()) return "Unknown or expired challenge";

    if (it->second.expires_at <= now_unix_seconds()) {
        pending_challenges_.erase(it);
        return "Challenge expired";
    }

    // Verify the challenge was issued for this pubkey
    if (it->second.pubkey_b64 != pubkey_b64) {
        return "Challenge was not issued for this public key";
    }

    // Consume the challenge (one-time use)
    pending_challenges_.erase(it);
    return {};
}

bool Ed25519AuthProvider::verify_account_delete_proof(const std::string& raw_pubkey_b64,
                                                      const std::string& challenge_b64,
                                                      const std::string& signature_b64,
                                                      std::string& error) {
    std::vector<uint8_t> pubkey_bytes, challenge_bytes, signature_bytes;
    try {
        pubkey_bytes = crypto::from_base64(raw_pubkey_b64);
        challenge_bytes = crypto::from_base64(challenge_b64);
        signature_bytes = crypto::from_base64(signature_b64);
    } catch (const std::exception&) {
        error = "invalid base64 in the deletion proof";
        return false;
    }
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize ||
        signature_bytes.size() != crypto::kEd25519SignatureSize || challenge_bytes.empty()) {
        error = "malformed deletion proof";
        return false;
    }
    crypto::Ed25519PublicKey pubkey{};
    std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());
    const auto pubkey_b64 = crypto::to_base64(std::span<const uint8_t>(pubkey));
    if (is_pubkey_revoked(pubkey_b64)) {
        error = "This identity has been revoked";
        return false;
    }
    if (auto refusal = consume_challenge(challenge_b64, pubkey_b64); !refusal.empty()) {
        error = std::move(refusal);
        return false;
    }
    crypto::Ed25519Signature signature{};
    std::copy(signature_bytes.begin(), signature_bytes.end(), signature.begin());
    const auto message = account_delete_proof_message(challenge_bytes, pubkey);
    if (!crypto_.ed25519_verify(pubkey, std::span<const uint8_t>(message), signature)) {
        spdlog::warn("[ed25519] account deletion proof does not verify for pubkey {}",
                     pubkey_b64.substr(0, 16));
        error = "the deletion proof does not verify";
        return false;
    }
    return true;
}

// ============================================================================
// User ID derivation: hex(sha256(pubkey))[:32]
// ============================================================================

std::string Ed25519AuthProvider::derive_user_id(const crypto::Ed25519PublicKey& pubkey) const {
    auto hash = crypto_.sha256(std::span<const uint8_t>(pubkey));
    auto full_hex = crypto::to_hex(std::span<const uint8_t>(hash));
    return full_hex.substr(0, 32); // 16 bytes = 32 hex chars
}

// ============================================================================
// Pubkey → user_id lookup
// ============================================================================

std::string Ed25519AuthProvider::lookup_user_by_pubkey(const std::string& pubkey_b64) {
    if (!cache_loaded_.load(std::memory_order_acquire)) {
        load_credentials_from_disk();
    }

    std::lock_guard lock(cache_mutex_);
    auto it = pubkey_to_user_.find(pubkey_b64);
    if (it != pubkey_to_user_.end()) {
        return it->second;
    }
    return {};
}

// ============================================================================
// Auto-register a new pubkey
// ============================================================================

std::string Ed25519AuthProvider::auto_register(const std::string& pubkey_b64,
                                                const crypto::Ed25519PublicKey& pubkey) {
    auto user_id = derive_user_id(pubkey);

    std::lock_guard lock(cache_mutex_);
    // An unreadable credential file can name this key under another user, so
    // a new identity for it is not created.
    if (store_degraded_) {
        spdlog::error("[ed25519] refusing to register pubkey {}: a credential file is "
                      "unreadable", pubkey_b64.substr(0, 16));
        return {};
    }
    if (!save_ed25519_credential(user_id, pubkey_b64)) {
        return {};
    }
    pubkey_to_user_[pubkey_b64] = user_id;
    return user_id;
}

// ============================================================================
// Device revocation blocklist
// ============================================================================

// The blocklist is keyed by canonical form on both insert and query, so the same
// key in a different encoding cannot slip past the exact-string match.
bool Ed25519AuthProvider::revocations_readable() {
    if (!cache_loaded_.load(std::memory_order_acquire)) {
        load_credentials_from_disk();
    }
    std::lock_guard lock(cache_mutex_);
    return !revocations_unreadable_;
}

bool Ed25519AuthProvider::is_pubkey_revoked(const std::string& pubkey_b64) {
    if (pubkey_b64.empty()) return false;
    if (!cache_loaded_.load(std::memory_order_acquire)) {
        load_credentials_from_disk();
    }
    std::lock_guard lock(cache_mutex_);
    if (revocations_unreadable_) return true;  // unknown counts as revoked
    // Verbatim first, so an undecodable legacy entry still matches, then by bytes.
    if (revoked_pubkeys_.contains(pubkey_b64)) return true;
    const auto canon = crypto::canonical_key_b64(pubkey_b64);
    return !canon.empty() && revoked_pubkeys_.contains(canon);
}

std::string Ed25519AuthProvider::user_id_of(const std::string& pubkey_b64) const {
    std::vector<uint8_t> bytes;
    try {
        bytes = crypto::from_base64(pubkey_b64);
    } catch (const std::exception&) {
        return {};
    }
    if (bytes.size() != crypto::kEd25519PublicKeySize) return {};
    crypto::Ed25519PublicKey pubkey{};
    std::copy(bytes.begin(), bytes.end(), pubkey.begin());
    return derive_user_id(pubkey);
}

bool Ed25519AuthProvider::is_user_revoked(const std::string& user_id) {
    if (user_id.empty()) return false;
    if (!cache_loaded_.load(std::memory_order_acquire)) {
        load_credentials_from_disk();
    }
    std::lock_guard lock(cache_mutex_);
    if (revocations_unreadable_) return true;  // unknown counts as revoked
    return revoked_user_ids_.contains(user_id);
}

bool Ed25519AuthProvider::revoke_pubkey(const std::string& pubkey_b64) {
    if (pubkey_b64.empty()) return false;
    if (!cache_loaded_.load(std::memory_order_acquire)) {
        load_credentials_from_disk();
    }

    std::lock_guard lock(cache_mutex_);
    // Writing the list now would replace the unreadable one.
    if (revocations_unreadable_) {
        spdlog::error("[ed25519] cannot revoke pubkey {}: the revocation list is unreadable",
                      pubkey_b64.substr(0, 16));
        return false;
    }
    // Never silently drop a revocation: keep the raw string if it won't decode.
    const auto canon = crypto::canonical_key_b64(pubkey_b64);
    const auto key = canon.empty() ? pubkey_b64 : canon;
    revoked_pubkeys_.insert(key);
    if (auto user_id = user_id_of(key); !user_id.empty()) revoked_user_ids_.insert(user_id);

    // Scrub the stale identity so a future reader of ed25519_pubkeys[] that
    // forgets the blocklist cannot resurrect a revoked key.
    if (auto it = pubkey_to_user_.find(key); it != pubkey_to_user_.end()) {
        const auto user_id = it->second;
        pubkey_to_user_.erase(it);
        if (!remove_ed25519_credential(user_id, key)) {
            spdlog::warn("[ed25519] Revocation applied but credential file scrub failed for user {}",
                         user_id);
        }
    }

    if (!persist_revoked_list()) return false;

    spdlog::info("[ed25519] Revoked pubkey {}", pubkey_b64.substr(0, 16));
    return true;
}

bool Ed25519AuthProvider::unrevoke_pubkey(const std::string& pubkey_b64) {
    if (pubkey_b64.empty()) return false;
    if (!cache_loaded_.load(std::memory_order_acquire)) {
        load_credentials_from_disk();
    }

    std::lock_guard lock(cache_mutex_);
    if (revocations_unreadable_) {
        spdlog::error("[ed25519] cannot unrevoke pubkey {}: the revocation list is unreadable",
                      pubkey_b64.substr(0, 16));
        return false;
    }
    const auto canon = crypto::canonical_key_b64(pubkey_b64);
    const auto key = canon.empty() ? pubkey_b64 : canon;

    const auto before = revoked_pubkeys_.size();
    revoked_pubkeys_.erase(key);
    // Legacy pre-canonicalization entries may hold other spellings of the same
    // key; the blocklist is queried verbatim first, so those must go too.
    if (!canon.empty()) {
        std::erase_if(revoked_pubkeys_, [&canon](const std::string& s) {
            return crypto::canonical_key_b64(s) == canon;
        });
    }
    if (revoked_pubkeys_.size() == before) return false;  // nothing was revoked
    if (const auto user_id = user_id_of(key); !user_id.empty()) revoked_user_ids_.erase(user_id);

    if (!persist_revoked_list()) return false;

    spdlog::info("[ed25519] Unrevoked pubkey {}", pubkey_b64.substr(0, 16));
    return true;
}

bool Ed25519AuthProvider::persist_revoked_list() {
    if (revocations_unreadable_) return false;
    json arr = json::array();
    for (const auto& pk : revoked_pubkeys_) arr.push_back(pk);
    return write_credential_file(storage_, revocation_path(storage_), arr);
}

// ============================================================================
// Credential persistence
// ============================================================================

bool Ed25519AuthProvider::save_ed25519_credential(const std::string& user_id,
                                                    const std::string& pubkey_b64) {
    const auto cred_path = credential_path(storage_, user_id);

    // The file may hold passkey credentials too. An unreadable one is refused
    // and left as it is: it is never replaced by a new file.
    auto file = read_credential_file(storage_, cred_path);
    if (file.state == CredentialFileState::Unreadable ||
        (file.state == CredentialFileState::Present && !file.data.is_object())) {
        spdlog::error("[ed25519] refusing to write credential file for user {}: the file is "
                      "unreadable or invalid", user_id);
        return false;
    }
    json file_data = file.state == CredentialFileState::Present ? std::move(file.data)
                                                                : json::object();
    if (file_data.contains("user_id") &&
        (!file_data["user_id"].is_string() || file_data["user_id"].get<std::string>() != user_id)) {
        spdlog::error("[ed25519] refusing to write credential file for user {}: the file "
                      "claims another identity", user_id);
        return false;
    }

    file_data["user_id"] = user_id;

    // Add Ed25519 pubkey to the ed25519_pubkeys array
    if (!file_data.contains("ed25519_pubkeys") || !file_data["ed25519_pubkeys"].is_array()) {
        file_data["ed25519_pubkeys"] = json::array();
    }

    // Duplicate check on key bytes, rewriting any legacy spelling in place — a raw
    // compare would append a second entry for the same key in another encoding.
    bool found = false;
    for (auto& existing : file_data["ed25519_pubkeys"]) {
        if (crypto::canonical_key_b64(existing.value("pubkey", "")) != pubkey_b64) continue;
        existing["pubkey"] = pubkey_b64;
        found = true;
        break;
    }

    if (!found) {
        auto now = now_unix_seconds();

        file_data["ed25519_pubkeys"].push_back(json{
            {"pubkey",     pubkey_b64},
            {"created_at", now},
        });
    }

    return write_credential_file(storage_, cred_path, file_data);
}

bool Ed25519AuthProvider::remove_ed25519_credential(const std::string& user_id,
                                                     const std::string& pubkey_b64) {
    const auto cred_path = credential_path(storage_, user_id);

    // The file may hold passkey credentials too.
    auto file = read_credential_file(storage_, cred_path);
    if (file.state == CredentialFileState::Absent) return true;
    if (file.state == CredentialFileState::Unreadable || !file.data.is_object()) {
        spdlog::error("[ed25519] cannot scrub credential file for user {}: the file is "
                      "unreadable or invalid", user_id);
        return false;
    }
    auto& file_data = file.data;

    // User no longer in the file: nothing to scrub, and the blocklist still
    // guards auth, so this is not an error.
    if (file_data.value("user_id", std::string{}) != user_id) return true;

    bool removed = false;
    if (file_data.contains("ed25519_pubkeys") &&
        file_data["ed25519_pubkeys"].is_array()) {
        // Match on canonical bytes, mirroring save_ed25519_credential, so a
        // legacy variant spelling in the file is removed too.
        auto& pk_arr = file_data["ed25519_pubkeys"];
        for (auto it = pk_arr.begin(); it != pk_arr.end();) {
            if (crypto::canonical_key_b64(it->value("pubkey", std::string{})) == pubkey_b64) {
                it = pk_arr.erase(it);
                removed = true;
            } else {
                ++it;
            }
        }
    }

    if (!removed) return true;  // key not in the file; already clean

    return write_credential_file(storage_, cred_path, file_data);
}

void Ed25519AuthProvider::load_credentials_from_disk() {
    std::lock_guard lock(cache_mutex_);
    if (cache_loaded_) return;

    // Recomputed on every attempt. An attempt that found an unreadable file
    // leaves cache_loaded_ false, so the next call reads again: the file can
    // open once the data key is in memory or the file is restored. Entries
    // already loaded stay, and a revocation is never forgotten.
    store_degraded_ = false;
    revocations_unreadable_ = false;

    const auto listing = list_credential_files(storage_);
    if (!listing.complete) {
        store_degraded_ = true;
        revocations_unreadable_ = true;
    }
    const auto revoked_path = revocation_path(storage_);
    std::size_t unreadable = 0;
    for (const auto& path : listing.files) {
        if (path.filename() == revoked_path.filename()) continue;
        const auto file = read_credential_file(storage_, path);
        if (file.state == CredentialFileState::Absent) continue;  // removed since the scan
        if (file.state == CredentialFileState::Unreadable || !file.data.is_object()) {
            spdlog::error("[ed25519] credential file {} is unreadable or invalid; new "
                          "identities are refused until it opens",
                          path.filename().string());
            store_degraded_ = true;
            ++unreadable;
            continue;
        }
        const auto& file_data = file.data;
        const auto user_id = file_data.value("user_id", std::string{});
        if (user_id.empty()) continue;
        if (!file_data.contains("ed25519_pubkeys") || !file_data["ed25519_pubkeys"].is_array()) {
            continue;
        }
        for (const auto& pk_entry : file_data["ed25519_pubkeys"]) {
            if (!pk_entry.is_object()) continue;
            // Canonicalize on load: files written before canonicalization
            // may hold a variant encoding of the same key.
            auto pk = crypto::canonical_key_b64(pk_entry.value("pubkey", std::string{}));
            if (!pk.empty()) pubkey_to_user_[pk] = user_id;
        }
    }

    // The device-revocation blocklist (deleted devices).
    const auto revoked = read_credential_file(storage_, revoked_path);
    if (revoked.state == CredentialFileState::Unreadable ||
        (revoked.state == CredentialFileState::Present && !revoked.data.is_array())) {
        spdlog::error("[ed25519] the revocation list is unreadable or invalid; Ed25519 "
                      "authentication and sessions are refused until it opens");
        revocations_unreadable_ = true;
    } else if (revoked.state == CredentialFileState::Present) {
        for (const auto& pk : revoked.data) {
            if (!pk.is_string()) continue;
            // Repair pre-canonicalization entries so a revoked key stays
            // revoked whichever encoding it was stored in; keep undecodable
            // ones verbatim rather than dropping a revocation.
            auto raw = pk.get<std::string>();
            auto canon = crypto::canonical_key_b64(raw);
            revoked_pubkeys_.insert(canon.empty() ? raw : canon);
            if (auto user_id = user_id_of(canon); !user_id.empty()) {
                revoked_user_ids_.insert(user_id);
            }
        }
    }

    const bool clean = !store_degraded_ && !revocations_unreadable_;
    cache_loaded_.store(clean, std::memory_order_release);
    spdlog::info("[ed25519] Loaded {} Ed25519 identity mappings from disk ({} unreadable "
                 "file(s))",
                 pubkey_to_user_.size(), unreadable);
}

// ============================================================================
// JWT generation
// ============================================================================

std::string Ed25519AuthProvider::generate_jwt(const std::string& user_id,
                                               const std::string& pubkey_b64) {
    auto now = std::chrono::system_clock::now();
    auto token = jwt::create()
        .set_issuer("lemonade-nexus")
        .set_subject(user_id)
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::hours{24})
        .set_payload_claim("pubkey", jwt::claim(pubkey_b64))
        .set_payload_claim("auth_method", jwt::claim(std::string("ed25519")))
        .sign(jwt::algorithm::hs256{jwt_secret_});
    return token;
}

} // namespace nexus::auth
