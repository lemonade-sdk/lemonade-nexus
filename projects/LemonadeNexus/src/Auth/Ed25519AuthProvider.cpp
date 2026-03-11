#include <LemonadeNexus/Auth/Ed25519AuthProvider.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace nexus::auth {

using json = nlohmann::json;

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

json Ed25519AuthProvider::issue_challenge(const std::string& pubkey_b64) {
    // Generate 32 random bytes as the challenge nonce
    std::array<uint8_t, kChallengeSize> nonce{};
    crypto_.random_bytes(std::span<uint8_t>(nonce));

    auto challenge_b64 = crypto::to_base64(std::span<const uint8_t>(nonce));
    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

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
    const auto pubkey_b64    = credentials.value("pubkey", std::string{});
    const auto challenge_b64 = credentials.value("challenge", std::string{});
    const auto signature_b64 = credentials.value("signature", std::string{});

    if (pubkey_b64.empty() || challenge_b64.empty() || signature_b64.empty()) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Missing required fields: pubkey, challenge, signature"
        };
    }

    // Decode the public key
    std::vector<uint8_t> pubkey_bytes;
    try {
        pubkey_bytes = crypto::from_base64(pubkey_b64);
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

    // Validate and consume the challenge
    {
        std::lock_guard lock(challenge_mutex_);
        auto it = pending_challenges_.find(challenge_b64);
        if (it == pending_challenges_.end()) {
            return AuthResult{
                .authenticated = false,
                .error_message = "Unknown or expired challenge"
            };
        }

        auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        if (it->second.expires_at <= now) {
            pending_challenges_.erase(it);
            return AuthResult{
                .authenticated = false,
                .error_message = "Challenge expired"
            };
        }

        // Verify the challenge was issued for this pubkey
        if (it->second.pubkey_b64 != pubkey_b64) {
            return AuthResult{
                .authenticated = false,
                .error_message = "Challenge was not issued for this public key"
            };
        }

        // Consume the challenge (one-time use)
        pending_challenges_.erase(it);
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

// ============================================================================
// Registration
// ============================================================================

AuthResult Ed25519AuthProvider::register_pubkey(const std::string& pubkey_b64,
                                                 const std::string& explicit_user_id) {
    std::vector<uint8_t> pubkey_bytes;
    try {
        pubkey_bytes = crypto::from_base64(pubkey_b64);
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

    // Check if already registered
    auto existing = lookup_user_by_pubkey(pubkey_b64);
    if (!existing.empty()) {
        return AuthResult{
            .authenticated = true,
            .user_id       = existing,
            .session_token = generate_jwt(existing, pubkey_b64),
        };
    }

    // Derive or use explicit user_id
    std::string user_id = explicit_user_id.empty()
        ? derive_user_id(pubkey)
        : explicit_user_id;

    if (!save_ed25519_credential(user_id, pubkey_b64)) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Failed to persist Ed25519 credential"
        };
    }

    {
        std::lock_guard lock(cache_mutex_);
        pubkey_to_user_[pubkey_b64] = user_id;
    }

    spdlog::info("[ed25519] Registered pubkey {} as user '{}'",
                 pubkey_b64.substr(0, 16), user_id);

    return AuthResult{
        .authenticated = true,
        .user_id       = user_id,
        .session_token = generate_jwt(user_id, pubkey_b64),
    };
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

    if (!save_ed25519_credential(user_id, pubkey_b64)) {
        return {};
    }

    {
        std::lock_guard lock(cache_mutex_);
        pubkey_to_user_[pubkey_b64] = user_id;
    }

    return user_id;
}

// ============================================================================
// Credential persistence
// ============================================================================

bool Ed25519AuthProvider::save_ed25519_credential(const std::string& user_id,
                                                    const std::string& pubkey_b64) {
    auto cred_path = storage_.data_root() / "credentials" / (user_id + ".json");

    json file_data;

    // Read existing file if present (may have passkey credentials too)
    {
        std::ifstream ifs(cred_path);
        if (ifs) {
            std::ostringstream ss;
            ss << ifs.rdbuf();
            file_data = json::parse(ss.str(), nullptr, false);
            if (file_data.is_discarded()) {
                file_data = json::object();
            }
        }
    }

    file_data["user_id"] = user_id;

    // Add Ed25519 pubkey to the ed25519_pubkeys array
    if (!file_data.contains("ed25519_pubkeys") || !file_data["ed25519_pubkeys"].is_array()) {
        file_data["ed25519_pubkeys"] = json::array();
    }

    // Check for duplicate
    bool found = false;
    for (const auto& existing : file_data["ed25519_pubkeys"]) {
        if (existing.value("pubkey", "") == pubkey_b64) {
            found = true;
            break;
        }
    }

    if (!found) {
        auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        file_data["ed25519_pubkeys"].push_back(json{
            {"pubkey",     pubkey_b64},
            {"created_at", now},
        });
    }

    try {
        std::filesystem::create_directories(cred_path.parent_path());
        std::ofstream ofs(cred_path, std::ios::trunc);
        if (!ofs) {
            spdlog::error("[ed25519] Failed to open credential file: {}", cred_path.string());
            return false;
        }
        ofs << file_data.dump(2);
        if (!ofs.good()) {
            spdlog::error("[ed25519] Failed to write credential file: {}", cred_path.string());
            return false;
        }
    } catch (const std::exception& e) {
        spdlog::error("[ed25519] Exception writing credential file: {}", e.what());
        return false;
    }

    return true;
}

void Ed25519AuthProvider::load_credentials_from_disk() {
    std::lock_guard lock(cache_mutex_);
    if (cache_loaded_) return;

    auto creds_dir = storage_.data_root() / "credentials";
    if (!std::filesystem::exists(creds_dir)) {
        cache_loaded_.store(true, std::memory_order_release);
        return;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(creds_dir)) {
            if (entry.path().extension() != ".json") continue;

            std::ifstream ifs(entry.path());
            if (!ifs) continue;

            std::ostringstream ss;
            ss << ifs.rdbuf();
            auto file_data = json::parse(ss.str(), nullptr, false);
            if (file_data.is_discarded()) continue;

            auto user_id = file_data.value("user_id", std::string{});
            if (user_id.empty()) continue;

            if (file_data.contains("ed25519_pubkeys") &&
                file_data["ed25519_pubkeys"].is_array()) {
                for (const auto& pk_entry : file_data["ed25519_pubkeys"]) {
                    auto pk = pk_entry.value("pubkey", std::string{});
                    if (!pk.empty()) {
                        pubkey_to_user_[pk] = user_id;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("[ed25519] Error loading credentials from disk: {}", e.what());
    }

    cache_loaded_.store(true, std::memory_order_release);
    spdlog::info("[ed25519] Loaded {} Ed25519 identity mappings from disk",
                 pubkey_to_user_.size());
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
