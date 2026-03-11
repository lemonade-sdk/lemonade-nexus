#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <chrono>
#include <cstring>

namespace nexus::acl {

using json = nlohmann::json;

static constexpr std::string_view kHkdfSalt = "lemonade-nexus-acl-db-key";

ACLService::ACLService(std::filesystem::path db_path,
                       crypto::SodiumCryptoService& crypto)
    : db_path_{std::move(db_path)}
    , crypto_{crypto}
{
}

ACLService::~ACLService() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void ACLService::set_signing_keypair(const crypto::Ed25519Keypair& kp) {
    signing_keypair_ = kp;
    derive_encryption_key();
}

void ACLService::set_delta_callback(AclDeltaCallback cb) {
    delta_callback_ = std::move(cb);
}

void ACLService::on_start() {
    auto parent = db_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }

    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("[{}] failed to open database {}: {}",
                      name(), db_path_.string(), sqlite3_errmsg(db_));
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    // ACL table with last_modified for conflict resolution
    const char* create_acl =
        "CREATE TABLE IF NOT EXISTS acl ("
        "  user_id TEXT NOT NULL,"
        "  resource TEXT NOT NULL,"
        "  perms_enc BLOB NOT NULL,"
        "  last_modified INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (user_id, resource)"
        ");";

    // Seen deltas for deduplication
    const char* create_seen =
        "CREATE TABLE IF NOT EXISTS acl_seen_deltas ("
        "  delta_id TEXT PRIMARY KEY"
        ");";

    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, create_acl, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("[{}] failed to create acl table: {}", name(), err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return;
    }
    rc = sqlite3_exec(db_, create_seen, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("[{}] failed to create seen deltas table: {}", name(), err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return;
    }

    // Count entries
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM acl;", -1, &stmt, nullptr);
    int64_t count = 0;
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);

    spdlog::info("[{}] started (database: {}, {} entries)", name(), db_path_.string(), count);
}

void ACLService::on_stop() {
    std::lock_guard lock(mutex_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Permission queries
// ---------------------------------------------------------------------------

Permission ACLService::do_get_permissions(std::string_view user_id, std::string_view resource) const {
    std::lock_guard lock(mutex_);
    if (!db_ || !has_key_) return Permission::None;
    return static_cast<Permission>(read_perms_locked(user_id, resource));
}

uint32_t ACLService::read_perms_locked(std::string_view user_id, std::string_view resource) const {
    const char* sql = "SELECT perms_enc FROM acl WHERE user_id = ? AND resource = ?;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_text(stmt, 1, user_id.data(), static_cast<int>(user_id.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, resource.data(), static_cast<int>(resource.size()), SQLITE_STATIC);

    uint32_t result = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto blob_ptr = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
        auto blob_len = sqlite3_column_bytes(stmt, 0);
        if (blob_ptr && blob_len > 0) {
            std::vector<uint8_t> blob(blob_ptr, blob_ptr + blob_len);
            auto dec = decrypt_perms(blob);
            if (dec) result = *dec;
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

bool ACLService::write_perms_locked(std::string_view user_id, std::string_view resource,
                                     uint32_t perms, uint64_t timestamp) {
    if (perms == 0) {
        // Delete the row
        const char* sql = "DELETE FROM acl WHERE user_id = ? AND resource = ?;";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;
        sqlite3_bind_text(stmt, 1, user_id.data(), static_cast<int>(user_id.size()), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, resource.data(), static_cast<int>(resource.size()), SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }

    auto enc = encrypt_perms(perms);
    if (enc.empty()) return false;

    const char* sql =
        "INSERT INTO acl (user_id, resource, perms_enc, last_modified) VALUES (?, ?, ?, ?)"
        " ON CONFLICT(user_id, resource) DO UPDATE SET perms_enc = excluded.perms_enc,"
        " last_modified = excluded.last_modified;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, user_id.data(), static_cast<int>(user_id.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, resource.data(), static_cast<int>(resource.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, enc.data(), static_cast<int>(enc.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, static_cast<int64_t>(timestamp));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

// ---------------------------------------------------------------------------
// Grant / Revoke (local mutations → produce gossip deltas)
// ---------------------------------------------------------------------------

bool ACLService::do_grant(std::string_view user_id, std::string_view resource, Permission perms) {
    auto now = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    AclDelta delta;
    delta.delta_id    = generate_delta_id();
    delta.operation   = "grant";
    delta.user_id     = std::string(user_id);
    delta.resource    = std::string(resource);
    delta.permissions = static_cast<uint32_t>(perms);
    delta.timestamp   = now;
    sign_delta(delta);

    {
        std::lock_guard lock(mutex_);
        if (!db_ || !has_key_) return false;

        uint32_t existing = read_perms_locked(user_id, resource);
        uint32_t updated = existing | static_cast<uint32_t>(perms);

        if (!write_perms_locked(user_id, resource, updated, now)) {
            spdlog::warn("[{}] failed to persist grant for {} on {}", name(), user_id, resource);
            return false;
        }
        mark_delta_seen_locked(delta.delta_id);
    }

    spdlog::debug("[{}] granted permissions to {} on {}", name(), user_id, resource);

    // Notify gossip layer to broadcast (outside lock)
    if (delta_callback_) {
        delta_callback_(delta);
    }
    return true;
}

bool ACLService::do_revoke(std::string_view user_id, std::string_view resource, Permission perms) {
    auto now = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    AclDelta delta;
    delta.delta_id    = generate_delta_id();
    delta.operation   = "revoke";
    delta.user_id     = std::string(user_id);
    delta.resource    = std::string(resource);
    delta.permissions = static_cast<uint32_t>(perms);
    delta.timestamp   = now;
    sign_delta(delta);

    {
        std::lock_guard lock(mutex_);
        if (!db_ || !has_key_) return false;

        uint32_t existing = read_perms_locked(user_id, resource);
        if (existing == 0) return false;

        uint32_t updated = existing & ~static_cast<uint32_t>(perms);

        if (!write_perms_locked(user_id, resource, updated, now)) {
            spdlog::warn("[{}] failed to persist revoke for {} on {}", name(), user_id, resource);
            return false;
        }
        mark_delta_seen_locked(delta.delta_id);
    }

    spdlog::debug("[{}] revoked permissions from {} on {}", name(), user_id, resource);

    if (delta_callback_) {
        delta_callback_(delta);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Remote delta application (from gossip)
// ---------------------------------------------------------------------------

bool ACLService::apply_remote_delta(const AclDelta& delta) {
    // Verify signature
    if (!verify_delta_signature(delta)) {
        spdlog::warn("[{}] rejected ACL delta {} — invalid signature", name(), delta.delta_id);
        return false;
    }

    std::lock_guard lock(mutex_);
    if (!db_ || !has_key_) return false;

    // Deduplication
    if (is_delta_seen_locked(delta.delta_id)) {
        return false;  // already applied
    }

    uint32_t existing = read_perms_locked(delta.user_id, delta.resource);
    uint32_t updated = existing;

    if (delta.operation == "grant") {
        updated = existing | delta.permissions;
    } else if (delta.operation == "revoke") {
        updated = existing & ~delta.permissions;
    } else {
        spdlog::warn("[{}] unknown ACL delta operation: {}", name(), delta.operation);
        return false;
    }

    if (!write_perms_locked(delta.user_id, delta.resource, updated, delta.timestamp)) {
        spdlog::warn("[{}] failed to apply remote ACL delta {}", name(), delta.delta_id);
        return false;
    }

    mark_delta_seen_locked(delta.delta_id);
    spdlog::debug("[{}] applied remote ACL delta {} ({} {} on {})",
                  name(), delta.delta_id, delta.operation, delta.user_id, delta.resource);
    return true;
}

// ---------------------------------------------------------------------------
// Delta deduplication
// ---------------------------------------------------------------------------

bool ACLService::is_delta_seen_locked(const std::string& delta_id) const {
    const char* sql = "SELECT 1 FROM acl_seen_deltas WHERE delta_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, delta_id.data(), static_cast<int>(delta_id.size()), SQLITE_STATIC);
    bool seen = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return seen;
}

void ACLService::mark_delta_seen_locked(const std::string& delta_id) {
    const char* sql = "INSERT OR IGNORE INTO acl_seen_deltas (delta_id) VALUES (?);";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return;

    sqlite3_bind_text(stmt, 1, delta_id.data(), static_cast<int>(delta_id.size()), SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ---------------------------------------------------------------------------
// Delta signing and verification
// ---------------------------------------------------------------------------

std::string ACLService::generate_delta_id() const {
    // 16 random bytes → 32 hex chars
    std::array<uint8_t, 16> buf{};
    crypto_.random_bytes(std::span<uint8_t>{buf});

    std::string hex;
    hex.reserve(32);
    for (auto b : buf) {
        static constexpr char digits[] = "0123456789abcdef";
        hex += digits[b >> 4];
        hex += digits[b & 0x0F];
    }
    return hex;
}

void ACLService::sign_delta(AclDelta& delta) const {
    delta.signer_pubkey = crypto::to_base64(signing_keypair_.public_key);

    // Canonical JSON for signing (sorted keys, no signature field)
    json j;
    j["delta_id"]    = delta.delta_id;
    j["operation"]   = delta.operation;
    j["permissions"] = delta.permissions;
    j["resource"]    = delta.resource;
    j["timestamp"]   = delta.timestamp;
    j["user_id"]     = delta.user_id;

    auto canonical = j.dump();
    auto sig = crypto_.ed25519_sign(
        signing_keypair_.private_key,
        std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size()});
    delta.signature = crypto::to_base64(sig);
}

bool ACLService::verify_delta_signature(const AclDelta& delta) const {
    auto pubkey_bytes = crypto::from_base64(delta.signer_pubkey);
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) return false;

    crypto::Ed25519PublicKey pubkey{};
    std::memcpy(pubkey.data(), pubkey_bytes.data(), crypto::kEd25519PublicKeySize);

    auto sig_bytes = crypto::from_base64(delta.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) return false;

    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

    // Reconstruct canonical JSON
    json j;
    j["delta_id"]    = delta.delta_id;
    j["operation"]   = delta.operation;
    j["permissions"] = delta.permissions;
    j["resource"]    = delta.resource;
    j["timestamp"]   = delta.timestamp;
    j["user_id"]     = delta.user_id;

    auto canonical = j.dump();
    return crypto_.ed25519_verify(
        pubkey,
        std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size()},
        sig);
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

void ACLService::derive_encryption_key() {
    auto salt_bytes = std::vector<uint8_t>(kHkdfSalt.begin(), kHkdfSalt.end());
    auto ikm = std::vector<uint8_t>(signing_keypair_.private_key.begin(),
                                     signing_keypair_.private_key.end());
    auto info = std::vector<uint8_t>{'a', 'c', 'l'};

    auto derived = crypto_.hkdf_sha256(
        std::span<const uint8_t>{ikm},
        std::span<const uint8_t>{salt_bytes},
        std::span<const uint8_t>{info},
        crypto::kAesGcmKeySize);

    if (derived.size() == crypto::kAesGcmKeySize) {
        std::memcpy(encryption_key_.data(), derived.data(), crypto::kAesGcmKeySize);
        has_key_ = true;
    }
}

std::vector<uint8_t> ACLService::encrypt_perms(uint32_t perms) const {
    if (!has_key_) return {};

    std::array<uint8_t, 4> plaintext{};
    plaintext[0] = static_cast<uint8_t>(perms & 0xFF);
    plaintext[1] = static_cast<uint8_t>((perms >> 8) & 0xFF);
    plaintext[2] = static_cast<uint8_t>((perms >> 16) & 0xFF);
    plaintext[3] = static_cast<uint8_t>((perms >> 24) & 0xFF);

    auto ct = crypto_.aes_gcm_encrypt(encryption_key_,
                                       std::span<const uint8_t>{plaintext});

    std::vector<uint8_t> blob;
    blob.reserve(ct.nonce.size() + ct.ciphertext.size());
    blob.insert(blob.end(), ct.nonce.begin(), ct.nonce.end());
    blob.insert(blob.end(), ct.ciphertext.begin(), ct.ciphertext.end());
    return blob;
}

std::optional<uint32_t> ACLService::decrypt_perms(const std::vector<uint8_t>& blob) const {
    if (!has_key_ || blob.size() <= crypto::kAesGcmNonceSize) return std::nullopt;

    crypto::AesGcmCiphertext ct;
    ct.nonce.assign(blob.begin(), blob.begin() + crypto::kAesGcmNonceSize);
    ct.ciphertext.assign(blob.begin() + crypto::kAesGcmNonceSize, blob.end());

    auto plaintext = crypto_.aes_gcm_decrypt(encryption_key_, ct);
    if (!plaintext || plaintext->size() != 4) return std::nullopt;

    auto& pt = *plaintext;
    uint32_t perms = static_cast<uint32_t>(pt[0])
                   | (static_cast<uint32_t>(pt[1]) << 8)
                   | (static_cast<uint32_t>(pt[2]) << 16)
                   | (static_cast<uint32_t>(pt[3]) << 24);
    return perms;
}

} // namespace nexus::acl
