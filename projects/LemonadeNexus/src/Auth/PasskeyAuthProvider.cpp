#include <LemonadeNexus/Auth/PasskeyAuthProvider.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

// OpenSSL 3.x EVP API for ECDSA-P256 verification
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace nexus::auth {

using json = nlohmann::json;

// ============================================================================
// Constructor
// ============================================================================

PasskeyAuthProvider::PasskeyAuthProvider(storage::FileStorageService& storage,
                                         crypto::SodiumCryptoService& crypto,
                                         std::string rp_id,
                                         std::string jwt_secret)
    : storage_(storage)
    , crypto_(crypto)
    , rp_id_(std::move(rp_id))
    , jwt_secret_(std::move(jwt_secret))
{
}

// ============================================================================
// Base64url decode  (WebAuthn uses base64url, not standard base64)
// ============================================================================

std::vector<uint8_t> PasskeyAuthProvider::base64url_decode(const std::string& input) {
    // Convert base64url to standard base64:
    //   '-' -> '+', '_' -> '/', pad with '='
    std::string b64 = input;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');

    // Add padding
    while (b64.size() % 4 != 0) {
        b64.push_back('=');
    }

    // Use the existing crypto helper (standard base64 via libsodium)
    return crypto::from_base64(b64);
}

// ============================================================================
// Registration
// ============================================================================

AuthResult PasskeyAuthProvider::do_register(const json& registration) {
    const auto user_id       = registration.value("user_id", std::string{});
    const auto credential_id = registration.value("credential_id", std::string{});
    const auto pub_key_x_hex = registration.value("public_key_x", std::string{});
    const auto pub_key_y_hex = registration.value("public_key_y", std::string{});

    if (user_id.empty() || credential_id.empty() ||
        pub_key_x_hex.empty() || pub_key_y_hex.empty()) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Missing required registration fields"
        };
    }

    // Decode hex public key coordinates
    std::vector<uint8_t> pk_x, pk_y;
    try {
        pk_x = crypto::from_hex(pub_key_x_hex);
        pk_y = crypto::from_hex(pub_key_y_hex);
    } catch (const std::exception& e) {
        return AuthResult{
            .authenticated = false,
            .error_message = std::string("Invalid public key hex: ") + e.what()
        };
    }

    if (pk_x.size() != 32 || pk_y.size() != 32) {
        return AuthResult{
            .authenticated = false,
            .error_message = "P-256 public key coordinates must be 32 bytes each"
        };
    }

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    StoredCredential cred;
    cred.credential_id = credential_id;
    cred.user_id       = user_id;
    cred.public_key_x  = std::move(pk_x);
    cred.public_key_y  = std::move(pk_y);
    cred.sign_count    = 0;
    cred.created_at    = now;

    // A credential_id belongs to at most one identity. Reject conflicting
    // ownership before touching disk or cache; the check and the ownership
    // reservation share one critical section so concurrent registrations
    // cannot both win.
    load_credentials_from_disk();
    bool reserved_new_owner = false;
    {
        std::lock_guard lock(cache_mutex_);
        auto existing = credential_cache_.find(credential_id);
        if (existing != credential_cache_.end() &&
            existing->second.user_id != user_id) {
            spdlog::warn("[passkey] rejecting registration of credential '{}' by '{}': "
                         "already owned by another identity",
                         credential_id, user_id);
            return AuthResult{
                .authenticated = false,
                .error_message = "credential_id is already owned by another identity"
            };
        }
        reserved_new_owner = (existing == credential_cache_.end());
        credential_cache_[credential_id] = cred;
    }

    if (!save_credential(cred)) {
        if (reserved_new_owner) {
            std::lock_guard lock(cache_mutex_);
            auto it = credential_cache_.find(credential_id);
            if (it != credential_cache_.end() && it->second.user_id == user_id) {
                credential_cache_.erase(it);
            }
        }
        return AuthResult{
            .authenticated = false,
            .error_message = "Failed to store credential"
        };
    }

    spdlog::info("[passkey] Registered credential '{}' for user '{}'",
                 credential_id, user_id);

    return AuthResult{
        .authenticated = true,
        .user_id       = user_id,
        .session_token = generate_jwt(user_id),
    };
}

// ============================================================================
// Challenge issuance and consumption
// ============================================================================

std::optional<json> PasskeyAuthProvider::issue_challenge(const std::string& user_id) {
    // Bound the stored identifier: challenges are attacker-issuable, so an
    // unbounded user_id would be an unbounded per-entry allocation.
    if (user_id.empty() || user_id.size() > kMaxChallengeUserIdLen) {
        return std::nullopt;
    }

    std::array<uint8_t, kChallengeSize> nonce{};
    crypto_.random_bytes(std::span<uint8_t>(nonce));

    // Key the store on the canonical standard-base64 of the nonce bytes;
    // the wire form is the unpadded base64url spelling of the same bytes.
    const auto store_key = crypto::to_base64(std::span<const uint8_t>(nonce));
    auto challenge_encoded = store_key;
    for (auto& ch : challenge_encoded) {
        if (ch == '+') ch = '-';
        else if (ch == '/') ch = '_';
    }
    // Padding only ever occurs at the end of a base64 string.
    challenge_encoded.erase(std::remove(challenge_encoded.begin(), challenge_encoded.end(), '='),
                            challenge_encoded.end());

    const auto steady_now = std::chrono::steady_clock::now();
    {
        std::lock_guard lock(challenge_mutex_);
        // Evict expired entries, then enforce the cap for real: while every
        // remaining entry is live and the table is full, issuance is refused
        // instead of growing without bound.
        std::erase_if(pending_challenges_,
                      [steady_now](const auto& kv) { return kv.second.deadline <= steady_now; });
        if (pending_challenges_.size() >= kMaxPendingChallenges) {
            spdlog::warn("[passkey] refusing challenge issuance: pending table exhausted");
            return std::nullopt;
        }
        pending_challenges_[store_key] =
            PendingChallenge{user_id, steady_now + std::chrono::seconds{kChallengeTtlSec}};
    }

    const auto expires_at = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count())
        + kChallengeTtlSec;
    spdlog::debug("[passkey] Issued challenge for user '{}'", user_id);
    return json{{"challenge", challenge_encoded}, {"expires_at", expires_at}};
}

bool PasskeyAuthProvider::consume_challenge(const std::vector<uint8_t>& challenge,
                                            const std::string& credential_user_id) {
    // Only issued challenges are 32 bytes; anything else cannot match and is
    // refused before it costs a hash or a lookup.
    if (challenge.size() != kChallengeSize) {
        spdlog::warn("[passkey] challenge has the wrong length ({} bytes)", challenge.size());
        return false;
    }

    // Compare decoded bytes, not encoding: clients may present the same nonce
    // as standard or url-safe base64, padded or not.
    const auto key = crypto::to_base64(std::span<const uint8_t>(challenge));

    // Check and consume in one critical section: two threads presenting the
    // same challenge concurrently must not both pass. Consumption happens
    // here, before signature verification: a failed assertion still spends
    // the challenge (explicit behavior, pinned by test).
    std::lock_guard lock(challenge_mutex_);
    auto it = pending_challenges_.find(key);
    if (it == pending_challenges_.end()) {
        spdlog::warn("[passkey] challenge was not issued by this server (or already used)");
        return false;
    }

    if (it->second.deadline <= std::chrono::steady_clock::now()) {
        pending_challenges_.erase(it);
        spdlog::warn("[passkey] challenge expired");
        return false;
    }

    // A mismatched presentation is refused but does not burn the challenge:
    // the user it was issued for may still complete the attempt.
    if (it->second.user_id != credential_user_id) {
        spdlog::warn("[passkey] challenge was not issued for this credential's user");
        return false;
    }

    pending_challenges_.erase(it);
    return true;
}

// ============================================================================
// Authentication (WebAuthn assertion verification)
// ============================================================================

AuthResult PasskeyAuthProvider::do_authenticate(const json& credentials) {
    if (!credentials.contains("assertion")) {
        return AuthResult{.authenticated = false, .error_message = "Missing FIDO2 assertion"};
    }

    const auto& assertion = credentials["assertion"];

    // Extract fields
    const auto credential_id_b64  = assertion.value("credential_id", std::string{});
    const auto auth_data_b64      = assertion.value("authenticator_data", std::string{});
    const auto client_data_b64    = assertion.value("client_data_json", std::string{});
    const auto signature_b64      = assertion.value("signature", std::string{});

    if (credential_id_b64.empty() || auth_data_b64.empty() ||
        client_data_b64.empty() || signature_b64.empty()) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Missing assertion fields (credential_id, authenticator_data, client_data_json, signature)"
        };
    }

    // Step (a): Look up stored credential by credential_id
    auto stored = lookup_credential(credential_id_b64);
    if (!stored) {
        spdlog::warn("[passkey] Unknown credential_id: {}", credential_id_b64);
        return AuthResult{
            .authenticated = false,
            .error_message = "Unknown credential"
        };
    }

    // Decode base64/base64url inputs
    std::vector<uint8_t> authenticator_data, client_data_json_bytes, signature_der;
    try {
        authenticator_data    = base64url_decode(auth_data_b64);
        client_data_json_bytes = base64url_decode(client_data_b64);
        signature_der         = base64url_decode(signature_b64);
    } catch (const std::exception& e) {
        return AuthResult{
            .authenticated = false,
            .error_message = std::string("Base64 decode error: ") + e.what()
        };
    }

    // Authenticator data must be at least 37 bytes (32 rp_id_hash + 1 flags + 4 sign_count)
    if (authenticator_data.size() < 37) {
        return AuthResult{
            .authenticated = false,
            .error_message = "Authenticator data too short"
        };
    }

    // Step (e): Verify the RP ID hash in authenticator_data matches expected origin
    if (!verify_rp_id_hash(authenticator_data)) {
        return AuthResult{
            .authenticated = false,
            .error_message = "RP ID hash mismatch"
        };
    }

    // Step (f): Check the UP (user present) flag is set (bit 0 of flags byte)
    if (!verify_user_present_flag(authenticator_data)) {
        return AuthResult{
            .authenticated = false,
            .error_message = "User-present flag not set"
        };
    }

    // Step (W3C 7.2 steps 8-10): Verify clientDataJSON type, origin, and that
    // the challenge was issued by this server for this credential's user.
    if (!verify_client_data_json(client_data_json_bytes, stored->user_id)) {
        return AuthResult{
            .authenticated = false,
            .error_message = "clientDataJSON verification failed (type/origin/challenge)"
        };
    }

    // Step (b): Hash client_data_json with SHA-256
    auto client_data_hash = crypto_.sha256(
        std::span<const uint8_t>(client_data_json_bytes));

    // Step (c): Concatenate authenticator_data || sha256(client_data_json)
    std::vector<uint8_t> signed_data;
    signed_data.reserve(authenticator_data.size() + client_data_hash.size());
    signed_data.insert(signed_data.end(),
                       authenticator_data.begin(), authenticator_data.end());
    signed_data.insert(signed_data.end(),
                       client_data_hash.begin(), client_data_hash.end());

    // Step (d): Verify the ECDSA-P256 signature
    if (!verify_ecdsa_p256(stored->public_key_x, stored->public_key_y,
                            signed_data, signature_der)) {
        spdlog::warn("[passkey] ECDSA signature verification failed for credential '{}'",
                     credential_id_b64);
        return AuthResult{
            .authenticated = false,
            .error_message = "FIDO2 assertion signature verification failed"
        };
    }

    // Update sign count (bytes 33-36 of authenticator_data, big-endian)
    uint32_t new_sign_count =
        (static_cast<uint32_t>(authenticator_data[33]) << 24) |
        (static_cast<uint32_t>(authenticator_data[34]) << 16) |
        (static_cast<uint32_t>(authenticator_data[35]) << 8)  |
        (static_cast<uint32_t>(authenticator_data[36]));

    if (new_sign_count > 0 && new_sign_count <= stored->sign_count) {
        spdlog::warn("[passkey] Sign count regression for credential '{}': stored={}, received={}",
                     credential_id_b64, stored->sign_count, new_sign_count);
        return AuthResult{
            .authenticated = false,
            .error_message = "Possible authenticator cloning detected (sign count regression)"
        };
    }

    // Update the stored sign count (cache + disk)
    {
        std::lock_guard lock(cache_mutex_);
        auto it = credential_cache_.find(credential_id_b64);
        if (it != credential_cache_.end()) {
            it->second.sign_count = new_sign_count;
        }
    }
    persist_sign_count(credential_id_b64, new_sign_count);

    spdlog::info("[passkey] Authenticated user '{}' via credential '{}'",
                 stored->user_id, credential_id_b64);

    // Step (g): Generate JWT session token
    return AuthResult{
        .authenticated = true,
        .user_id       = stored->user_id,
        .session_token = generate_jwt(stored->user_id),
    };
}

// ============================================================================
// RP ID hash verification
// ============================================================================

bool PasskeyAuthProvider::verify_rp_id_hash(const std::vector<uint8_t>& authenticator_data) {
    // First 32 bytes of authenticator_data = SHA-256(rp_id)
    auto expected_hash = crypto_.sha256(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(rp_id_.data()), rp_id_.size()));

    if (authenticator_data.size() < 32) return false;

    return std::equal(authenticator_data.begin(), authenticator_data.begin() + 32,
                      expected_hash.begin(), expected_hash.end());
}

// ============================================================================
// User-present flag verification
// ============================================================================

bool PasskeyAuthProvider::verify_user_present_flag(const std::vector<uint8_t>& authenticator_data) {
    // Flags byte is at offset 32 (after the 32-byte RP ID hash)
    // Bit 0 = User Present (UP)
    if (authenticator_data.size() < 33) return false;
    return (authenticator_data[32] & 0x01) != 0;
}

// ============================================================================
// ECDSA-P256 signature verification using OpenSSL
// ============================================================================

bool PasskeyAuthProvider::verify_ecdsa_p256(const std::vector<uint8_t>& public_key_x,
                                             const std::vector<uint8_t>& public_key_y,
                                             const std::vector<uint8_t>& signed_data,
                                             const std::vector<uint8_t>& der_signature) {
    if (public_key_x.size() != 32 || public_key_y.size() != 32) {
        spdlog::error("[passkey] Invalid P-256 key coordinate size");
        return false;
    }

    // Build uncompressed point: 0x04 || X || Y  (65 bytes)
    std::vector<uint8_t> uncompressed_point;
    uncompressed_point.reserve(65);
    uncompressed_point.push_back(0x04);
    uncompressed_point.insert(uncompressed_point.end(),
                               public_key_x.begin(), public_key_x.end());
    uncompressed_point.insert(uncompressed_point.end(),
                               public_key_y.begin(), public_key_y.end());

    // Build EVP_PKEY from raw EC point using the OpenSSL 3.x provider API
    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
        spdlog::error("[passkey] Failed to create OSSL_PARAM_BLD");
        return false;
    }

    OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                      uncompressed_point.data(), uncompressed_point.size());

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
    OSSL_PARAM_BLD_free(param_bld);
    if (!params) {
        spdlog::error("[passkey] Failed to build OSSL_PARAM");
        return false;
    }

    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pkey_ctx) {
        OSSL_PARAM_free(params);
        spdlog::error("[passkey] Failed to create EVP_PKEY_CTX");
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    bool ok = false;

    if (EVP_PKEY_fromdata_init(pkey_ctx) <= 0 ||
        EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
        !pkey) {
        spdlog::error("[passkey] Failed to import EC public key via EVP_PKEY_fromdata");
        EVP_PKEY_CTX_free(pkey_ctx);
        OSSL_PARAM_free(params);
        return false;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_PARAM_free(params);

    // Verify the DER-encoded ECDSA signature over signed_data using EVP_DigestVerify.
    // EVP_DigestVerify with EVP_sha256() hashes internally, so pass the raw signed_data.
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        spdlog::error("[passkey] Failed to create EVP_MD_CTX");
        return false;
    }

    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
        int rc = EVP_DigestVerify(md_ctx,
                                   der_signature.data(), der_signature.size(),
                                   signed_data.data(), signed_data.size());
        ok = (rc == 1);
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// ============================================================================
// JWT generation
// ============================================================================

std::string PasskeyAuthProvider::generate_jwt(const std::string& user_id) {
    auto now = std::chrono::system_clock::now();
    auto token = jwt::create()
        .set_issuer("lemonade-nexus")
        .set_subject(user_id)
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::hours{24})
        .sign(jwt::algorithm::hs256{jwt_secret_});
    return token;
}

// ============================================================================
// Credential persistence
// ============================================================================

bool PasskeyAuthProvider::save_credential(const StoredCredential& cred) {
    // Build or update the credential file for this user
    auto cred_path = storage_.data_root() / "credentials" / (cred.user_id + ".json");

    json file_data;

    // Read existing file if present
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

    file_data["user_id"] = cred.user_id;

    if (!file_data.contains("credentials") || !file_data["credentials"].is_array()) {
        file_data["credentials"] = json::array();
    }

    // Check for duplicate credential_id
    bool found = false;
    for (auto& existing : file_data["credentials"]) {
        if (existing.value("credential_id", "") == cred.credential_id) {
            // Update existing
            existing["public_key_x"] = crypto::to_hex(std::span<const uint8_t>(cred.public_key_x));
            existing["public_key_y"] = crypto::to_hex(std::span<const uint8_t>(cred.public_key_y));
            existing["sign_count"]   = cred.sign_count;
            existing["created_at"]   = cred.created_at;
            found = true;
            break;
        }
    }

    if (!found) {
        json cred_json;
        cred_json["credential_id"] = cred.credential_id;
        cred_json["public_key_x"]  = crypto::to_hex(std::span<const uint8_t>(cred.public_key_x));
        cred_json["public_key_y"]  = crypto::to_hex(std::span<const uint8_t>(cred.public_key_y));
        cred_json["sign_count"]    = cred.sign_count;
        cred_json["created_at"]    = cred.created_at;
        file_data["credentials"].push_back(std::move(cred_json));
    }

    // Write back
    try {
        std::filesystem::create_directories(cred_path.parent_path());
        std::ofstream ofs(cred_path, std::ios::trunc);
        if (!ofs) {
            spdlog::error("[passkey] Failed to open credential file for writing: {}",
                          cred_path.string());
            return false;
        }
        ofs << file_data.dump(2);
        if (!ofs.good()) {
            spdlog::error("[passkey] Failed to write credential file: {}", cred_path.string());
            return false;
        }
    } catch (const std::exception& e) {
        spdlog::error("[passkey] Exception writing credential file: {}", e.what());
        return false;
    }

    // Update in-memory cache
    {
        std::lock_guard lock(cache_mutex_);
        credential_cache_[cred.credential_id] = cred;
    }

    return true;
}

std::optional<StoredCredential> PasskeyAuthProvider::lookup_credential(const std::string& credential_id) {
    // Lazy-load all credentials from disk on first lookup (double-checked locking)
    if (!cache_loaded_.load(std::memory_order_acquire)) {
        load_credentials_from_disk();
    }

    std::lock_guard lock(cache_mutex_);
    auto it = credential_cache_.find(credential_id);
    if (it != credential_cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void PasskeyAuthProvider::load_credentials_from_disk() {
    std::lock_guard lock(cache_mutex_);
    if (cache_loaded_) return; // double-check under lock

    auto creds_dir = storage_.data_root() / "credentials";
    if (!std::filesystem::exists(creds_dir)) {
        cache_loaded_.store(true, std::memory_order_release);
        return;
    }

    struct FileCredentials {
        std::string user_id;
        std::vector<StoredCredential> credentials;
    };
    std::vector<FileCredentials> files;

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

            if (!file_data.contains("credentials") || !file_data["credentials"].is_array()) {
                continue;
            }

            FileCredentials fc;
            fc.user_id = std::move(user_id);
            for (const auto& cred_json : file_data["credentials"]) {
                StoredCredential cred;
                cred.credential_id = cred_json.value("credential_id", std::string{});
                cred.user_id       = fc.user_id;
                cred.sign_count    = cred_json.value("sign_count", 0u);
                cred.created_at    = cred_json.value("created_at", uint64_t{0});

                try {
                    cred.public_key_x = crypto::from_hex(cred_json.value("public_key_x", ""));
                    cred.public_key_y = crypto::from_hex(cred_json.value("public_key_y", ""));
                } catch (const std::exception& e) {
                    spdlog::warn("[passkey] Skipping malformed credential in {}: {}",
                                 entry.path().string(), e.what());
                    continue;
                }

                if (cred.public_key_x.size() != 32 || cred.public_key_y.size() != 32) {
                    spdlog::warn("[passkey] Skipping credential with wrong key size in {}",
                                 entry.path().string());
                    continue;
                }

                if (!cred.credential_id.empty()) {
                    fc.credentials.push_back(std::move(cred));
                }
            }
            files.push_back(std::move(fc));
        }
    } catch (const std::exception& e) {
        spdlog::error("[passkey] Error loading credentials from disk: {}", e.what());
    }

    // A credential_id persisted under more than one identity is a conflict
    // (left over from a pre-fix registration race). Restart must not pick an
    // owner from conflicting entries: refuse those credentials instead.
    std::map<std::string, std::set<std::string>> owners_by_credential;
    for (const auto& fc : files) {
        for (const auto& cred : fc.credentials) {
            owners_by_credential[cred.credential_id].insert(fc.user_id);
        }
    }
    std::set<std::string> conflicted;
    for (const auto& [credential_id, owners] : owners_by_credential) {
        if (owners.size() > 1) {
            conflicted.insert(credential_id);
            spdlog::critical("[passkey] credential_id '{}' is persisted under {} identities; "
                             "refusing to load it",
                             credential_id, owners.size());
        }
    }

    for (auto& fc : files) {
        for (auto& cred : fc.credentials) {
            if (conflicted.count(cred.credential_id)) continue;
            credential_cache_[cred.credential_id] = std::move(cred);
        }
    }

    cache_loaded_.store(true, std::memory_order_release);
    spdlog::info("[passkey] Loaded {} credentials from disk", credential_cache_.size());
}

// ============================================================================
// clientDataJSON verification (W3C WebAuthn Level 2, Section 7.2)
// ============================================================================

bool PasskeyAuthProvider::verify_client_data_json(const std::vector<uint8_t>& client_data_json_bytes,
                                                  const std::string& credential_user_id) {
    try {
        auto cdj = json::parse(
            std::string(client_data_json_bytes.begin(), client_data_json_bytes.end()),
            nullptr, false);
        if (cdj.is_discarded()) {
            spdlog::warn("[passkey] Failed to parse clientDataJSON");
            return false;
        }

        // Step 8: Verify type is "webauthn.get" for authentication
        auto type = cdj.value("type", std::string{});
        if (type != "webauthn.get") {
            spdlog::warn("[passkey] clientDataJSON type mismatch: expected 'webauthn.get', got '{}'", type);
            return false;
        }

        // Step 9: Verify origin matches expected RP origin
        auto origin = cdj.value("origin", std::string{});
        if (origin.empty()) {
            spdlog::warn("[passkey] clientDataJSON missing origin");
            return false;
        }

        // Accept origins that match the RP ID:
        //   - "https://<rp_id>" (standard web origin)
        //   - "https://<rp_id>:<port>" (with port)
        //   - The RP ID itself (for native/non-browser clients)
        bool origin_valid = false;
        if (origin == "https://" + rp_id_ ||
            origin.starts_with("https://" + rp_id_ + ":") ||
            origin == rp_id_) {
            origin_valid = true;
        }

        if (!origin_valid) {
            spdlog::warn("[passkey] clientDataJSON origin '{}' does not match RP ID '{}'",
                         origin, rp_id_);
            return false;
        }

        // Step 10: the challenge must be one this server issued for this
        // credential's user, still inside its TTL, and not yet presented.
        // consume_challenge() performs the check and the single-use removal
        // atomically, so a captured assertion cannot be replayed — not even
        // twice in quick succession.
        auto challenge_b64 = cdj.value("challenge", std::string{});
        if (challenge_b64.empty()) {
            spdlog::warn("[passkey] clientDataJSON missing challenge");
            return false;
        }
        if (challenge_b64.size() > kMaxChallengeEncodedLen) {
            spdlog::warn("[passkey] clientDataJSON challenge too long ({} chars)",
                         challenge_b64.size());
            return false;
        }
        std::vector<uint8_t> challenge;
        try {
            challenge = base64url_decode(challenge_b64);
        } catch (const std::exception& e) {
            spdlog::warn("[passkey] clientDataJSON challenge is not base64: {}", e.what());
            return false;
        }
        return consume_challenge(challenge, credential_user_id);

    } catch (const std::exception& e) {
        spdlog::warn("[passkey] Exception verifying clientDataJSON: {}", e.what());
        return false;
    }
}

// ============================================================================
// Persist sign count to disk
// ============================================================================

void PasskeyAuthProvider::persist_sign_count(const std::string& credential_id,
                                              uint32_t sign_count) {
    // Known concurrency gap (tracked separately, not fixed here): cache_mutex_
    // is released before the file access below, so the read-modify-rewrite of
    // credentials/<user>.json is unlocked even in-process. Two concurrent
    // mutations of the same file (registration plus a sign-count update, or
    // two credentials of one user) can interleave and silently drop an update;
    // the rewrite is also not atomic (no temp-file + rename). cache_mutex_ does
    // NOT serialize file I/O.
    // Find the user_id for this credential
    std::string user_id;
    {
        std::lock_guard lock(cache_mutex_);
        auto it = credential_cache_.find(credential_id);
        if (it == credential_cache_.end()) return;
        user_id = it->second.user_id;
    }

    if (user_id.empty()) return;

    auto cred_path = storage_.data_root() / "credentials" / (user_id + ".json");
    try {
        std::ifstream ifs(cred_path);
        if (!ifs) return;

        std::ostringstream ss;
        ss << ifs.rdbuf();
        ifs.close();

        auto file_data = json::parse(ss.str(), nullptr, false);
        if (file_data.is_discarded() || !file_data.contains("credentials")) return;

        bool updated = false;
        for (auto& cred_json : file_data["credentials"]) {
            if (cred_json.value("credential_id", "") == credential_id) {
                cred_json["sign_count"] = sign_count;
                updated = true;
                break;
            }
        }

        if (updated) {
            std::ofstream ofs(cred_path, std::ios::trunc);
            if (ofs) {
                ofs << file_data.dump(2);
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[passkey] Failed to persist sign count for credential '{}': {}",
                     credential_id, e.what());
    }
}

} // namespace nexus::auth
