#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstring>

namespace nexus::acl {

using json = nlohmann::json;

static constexpr std::string_view kHkdfSalt = "lemonade-nexus-acl-db-key";

ACLService::ACLService(AclStore& store,
                       crypto::SodiumCryptoService& crypto)
    : store_{store}
    , crypto_{crypto}
{
}

void ACLService::set_signing_keypair(const crypto::Ed25519Keypair& kp) {
    signing_keypair_ = kp;
    derive_encryption_key();
}

void ACLService::set_delta_callback(AclDeltaCallback cb) {
    delta_callback_ = std::move(cb);
}

void ACLService::on_start() {
    std::lock_guard lock(mutex_);
    store_.open();

    // Count entries
    const int64_t count = store_.ready() ? store_.count() : 0;

    spdlog::info("[{}] started (database: {}, {} entries)", name(), store_.db_path().string(), count);
}

void ACLService::on_stop() {
    std::lock_guard lock(mutex_);
    store_.close();
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Permission queries
// ---------------------------------------------------------------------------

Permission ACLService::do_get_permissions(std::string_view user_id, std::string_view resource) const {
    std::lock_guard lock(mutex_);
    if (!store_.ready() || !has_key_) return Permission::None;

    const auto blob = store_.load_perms(user_id, resource);
    if (!blob) return Permission::None;
    auto dec = decrypt_perms(*blob, user_id, resource);
    return dec ? static_cast<Permission>(*dec) : Permission::None;
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
        if (!store_.ready() || !has_key_) return false;

        const auto blob = store_.load_perms(user_id, resource);
        uint32_t existing = 0;
        if (blob) {
            if (auto dec = decrypt_perms(*blob, user_id, resource)) existing = *dec;
        }
        uint32_t updated = existing | static_cast<uint32_t>(perms);

        auto enc = encrypt_perms(updated, user_id, resource);
        if (enc.empty()) return false;
        if (!store_.store_perms(user_id, resource, std::span<const uint8_t>{enc}, now)) {
            spdlog::warn("[{}] failed to persist grant for {} on {}", name(), user_id, resource);
            return false;
        }
        store_.mark_delta_seen(delta.delta_id);
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
        if (!store_.ready() || !has_key_) return false;

        uint32_t existing = 0;
        if (auto blob = store_.load_perms(user_id, resource)) {
            if (auto dec = decrypt_perms(*blob, user_id, resource)) existing = *dec;
        }
        if (existing == 0) return false;

        uint32_t updated = existing & ~static_cast<uint32_t>(perms);

        bool persisted;
        if (updated == 0) {
            persisted = store_.delete_perms(user_id, resource);
        } else {
            auto enc = encrypt_perms(updated, user_id, resource);
            persisted = !enc.empty() &&
                        store_.store_perms(user_id, resource, std::span<const uint8_t>{enc}, now);
        }
        if (!persisted) {
            spdlog::warn("[{}] failed to persist revoke for {} on {}", name(), user_id, resource);
            return false;
        }
        store_.mark_delta_seen(delta.delta_id);
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
    if (!store_.ready() || !has_key_) return false;

    // Deduplication
    if (store_.is_delta_seen(delta.delta_id)) {
        return false;  // already applied
    }

    uint32_t existing = 0;
    if (auto blob = store_.load_perms(delta.user_id, delta.resource)) {
        if (auto dec = decrypt_perms(*blob, delta.user_id, delta.resource)) existing = *dec;
    }
    uint32_t updated = existing;

    if (delta.operation == "grant") {
        updated = existing | delta.permissions;
    } else if (delta.operation == "revoke") {
        updated = existing & ~delta.permissions;
    } else {
        spdlog::warn("[{}] unknown ACL delta operation: {}", name(), delta.operation);
        return false;
    }

    bool persisted;
    if (updated == 0) {
        persisted = store_.delete_perms(delta.user_id, delta.resource);
    } else {
        auto enc = encrypt_perms(updated, delta.user_id, delta.resource);
        persisted = !enc.empty() &&
                    store_.store_perms(delta.user_id, delta.resource,
                                       std::span<const uint8_t>{enc}, delta.timestamp);
    }
    if (!persisted) {
        spdlog::warn("[{}] failed to apply remote ACL delta {}", name(), delta.delta_id);
        return false;
    }

    store_.mark_delta_seen(delta.delta_id);
    spdlog::debug("[{}] applied remote ACL delta {} ({} {} on {})",
                  name(), delta.delta_id, delta.operation, delta.user_id, delta.resource);
    return true;
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
        crypto::kAeadKeySize);

    if (derived.size() == crypto::kAeadKeySize) {
        std::memcpy(encryption_key_.data(), derived.data(), crypto::kAeadKeySize);
        has_key_ = true;
    }
}

std::vector<uint8_t> ACLService::encrypt_perms(uint32_t perms, std::string_view user_id,
                                               std::string_view resource) const {
    if (!has_key_) return {};

    std::array<uint8_t, 4> plaintext{};
    plaintext[0] = static_cast<uint8_t>(perms & 0xFF);
    plaintext[1] = static_cast<uint8_t>((perms >> 8) & 0xFF);
    plaintext[2] = static_cast<uint8_t>((perms >> 16) & 0xFF);
    plaintext[3] = static_cast<uint8_t>((perms >> 24) & 0xFF);

    // The row this permission belongs to is authenticated, so a valid blob
    // lifted out of one row fails in any other.
    const auto aad = crypto::aead_aad(
        crypto::aead_purpose::kAclPermissions,
        {std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(user_id.data()), user_id.size()),
         std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(resource.data()),
                                  resource.size())});
    const auto ct = crypto_.aead_encrypt(encryption_key_, std::span<const uint8_t>{plaintext},
                                         std::span<const uint8_t>{aad});

    // version || nonce || ciphertext. The version leads so a reader names the
    // construction outright instead of inferring it from a field width.
    std::vector<uint8_t> blob;
    blob.reserve(1 + ct.nonce.size() + ct.ciphertext.size());
    blob.push_back(ct.version);
    blob.insert(blob.end(), ct.nonce.begin(), ct.nonce.end());
    blob.insert(blob.end(), ct.ciphertext.begin(), ct.ciphertext.end());
    return blob;
}

std::optional<uint32_t> ACLService::decrypt_perms(const std::vector<uint8_t>& blob,
                                                  std::string_view user_id,
                                                  std::string_view resource) const {
    if (!has_key_) return std::nullopt;

    // version || nonce || ciphertext, with every length checked before any of
    // it reaches the AEAD.
    constexpr std::size_t kMinimum = 1 + crypto::kAeadNonceSize + crypto::kAeadTagSize;
    if (blob.size() < kMinimum) return std::nullopt;
    if (blob[0] != crypto::kEncryptedBlobVersion) return std::nullopt;

    crypto::EncryptedBlob ct;
    ct.version = blob[0];
    const auto nonce_begin = blob.begin() + 1;
    const auto nonce_end = nonce_begin + static_cast<std::ptrdiff_t>(crypto::kAeadNonceSize);
    ct.nonce.assign(nonce_begin, nonce_end);
    ct.ciphertext.assign(nonce_end, blob.end());

    const auto aad = crypto::aead_aad(
        crypto::aead_purpose::kAclPermissions,
        {std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(user_id.data()), user_id.size()),
         std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(resource.data()),
                                  resource.size())});
    auto plaintext = crypto_.aead_decrypt(encryption_key_, ct, std::span<const uint8_t>{aad});
    if (!plaintext || plaintext->size() != 4) return std::nullopt;

    auto& pt = *plaintext;
    uint32_t perms = static_cast<uint32_t>(pt[0])
                   | (static_cast<uint32_t>(pt[1]) << 8)
                   | (static_cast<uint32_t>(pt[2]) << 16)
                   | (static_cast<uint32_t>(pt[3]) << 24);
    return perms;
}

} // namespace nexus::acl
