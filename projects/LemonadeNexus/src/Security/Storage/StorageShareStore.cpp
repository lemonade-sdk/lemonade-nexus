#include <LemonadeNexus/Security/Storage/StorageShareStore.hpp>

#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <cstring>
#include <fstream>
#include <sstream>

namespace nexus::security {

namespace {

using json = nlohmann::json;

constexpr int kFileFormat = 1;
constexpr std::array<uint8_t, 6> kBundleMagic{'L', 'N', 'S', 'B', '0', '1'};
constexpr std::size_t kMaxBundleEntries = 4;
constexpr std::size_t kMaxShareBytes = 16 * 1024;

bool valid_domain(std::string_view domain) {
    if (domain.empty() || domain.size() > 48) {
        return false;
    }
    for (const char c : domain) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

std::optional<std::string> read_all(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

void wipe(std::string& text) {
    if (!text.empty()) {
        sodium_memzero(text.data(), text.size());
    }
    text.clear();
}

void put_u32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

}  // namespace

FileStorageShareStore::FileStorageShareStore(std::filesystem::path directory,
                                             crypto::SodiumCryptoService* crypto,
                                             crypto::KeyWrappingService* wrapping,
                                             crypto::Ed25519PublicKey binding_key)
    : directory_(std::move(directory)),
      crypto_(crypto),
      wrapping_(wrapping),
      binding_key_(binding_key) {}

std::filesystem::path FileStorageShareStore::path_of(std::string_view domain) const {
    return directory_ / (std::string(domain) + ".share");
}

ShareStoreStatus FileStorageShareStore::seal(std::string_view domain,
                                             std::span<const uint8_t> plaintext) {
    if (!valid_domain(domain) || plaintext.empty()) {
        return ShareStoreStatus::Failed;
    }
    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
    if (ec) {
        return ShareStoreStatus::Failed;
    }
    json j;
    j["format"] = kFileFormat;
    j["domain"] = std::string(domain);
    const bool wrapped = crypto_ != nullptr && wrapping_ != nullptr;
    j["wrapped"] = wrapped;
    if (wrapped) {
        // A fresh store key per seal, wrapped with the machine binding. The
        // first 32 bytes key the AEAD over the secret.
        crypto::Ed25519PrivateKey store_key{};
        crypto_->random_bytes(store_key);
        crypto::AeadKey aead_key{};
        std::memcpy(aead_key.data(), store_key.data(), aead_key.size());
        const auto key_blob = wrapping_->wrap_key(store_key, {}, binding_key_);
        sodium_memzero(store_key.data(), store_key.size());
        const auto aad = crypto::aead_aad(
            crypto::aead_purpose::kStorageShareAtRest,
            {std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(domain.data()),
                                      domain.size()),
             std::span<const uint8_t>(binding_key_.data(), binding_key_.size())});
        const auto blob = crypto_->aead_encrypt(aead_key, plaintext, aad);
        sodium_memzero(aead_key.data(), aead_key.size());
        j["key_version"] = static_cast<unsigned>(key_blob.ciphertext.version);
        j["key_ciphertext"] = crypto::to_base64(key_blob.ciphertext.ciphertext);
        j["key_nonce"] = crypto::to_base64(key_blob.ciphertext.nonce);
        j["blob_version"] = static_cast<unsigned>(blob.version);
        j["blob_ciphertext"] = crypto::to_base64(blob.ciphertext);
        j["blob_nonce"] = crypto::to_base64(blob.nonce);
    } else {
        std::string encoded = crypto::to_base64(plaintext);
        j["plaintext"] = encoded;
        wipe(encoded);
    }
    std::string text = j.dump();
    const bool ok = write_durable(path_of(domain), text);
    wipe(text);
    return ok ? ShareStoreStatus::Ok : ShareStoreStatus::Failed;
}

ShareUnsealResult FileStorageShareStore::unseal(std::string_view domain) {
    ShareUnsealResult result;
    if (!valid_domain(domain)) {
        result.status = ShareStoreStatus::Failed;
        return result;
    }
    auto text = read_all(path_of(domain));
    if (!text.has_value()) {
        result.status = ShareStoreStatus::Missing;
        return result;
    }
    json j = json::parse(*text, nullptr, false);
    wipe(*text);
    result.status = ShareStoreStatus::Corrupt;
    if (!j.is_object() || !j.contains("format") || j["format"] != kFileFormat ||
        !j.contains("domain") || j["domain"] != std::string(domain) || !j.contains("wrapped") ||
        !j["wrapped"].is_boolean()) {
        return result;
    }
    const bool wrapped = j["wrapped"].get<bool>();
    if (!wrapped) {
        if (crypto_ != nullptr || !j.contains("plaintext") || !j["plaintext"].is_string()) {
            // A store that wraps never accepts a plaintext file: a planted
            // share must not replace a sealed one.
            return result;
        }
        std::string encoded = j["plaintext"].get<std::string>();
        auto bytes = crypto::from_base64(encoded);
        wipe(encoded);
        j["plaintext"] = "";
        if (bytes.empty()) {
            return result;
        }
        result.plaintext = crypto::SecureBuffer(std::span<const uint8_t>(bytes));
        sodium_memzero(bytes.data(), bytes.size());
        result.status = ShareStoreStatus::Ok;
        return result;
    }
    if (crypto_ == nullptr || wrapping_ == nullptr) {
        result.status = ShareStoreStatus::Unavailable;
        return result;
    }
    for (const char* field : {"key_ciphertext", "key_nonce", "blob_ciphertext", "blob_nonce"}) {
        if (!j.contains(field) || !j[field].is_string()) {
            return result;
        }
    }
    if (!j.contains("key_version") || j["key_version"] != crypto::kEncryptedBlobVersion ||
        !j.contains("blob_version") || j["blob_version"] != crypto::kEncryptedBlobVersion) {
        return result;
    }
    crypto::WrappedKey key_blob;
    key_blob.ciphertext.version = crypto::kEncryptedBlobVersion;
    key_blob.ciphertext.ciphertext = crypto::from_base64(j["key_ciphertext"].get<std::string>());
    key_blob.ciphertext.nonce = crypto::from_base64(j["key_nonce"].get<std::string>());
    crypto::EncryptedBlob blob;
    blob.version = crypto::kEncryptedBlobVersion;
    blob.ciphertext = crypto::from_base64(j["blob_ciphertext"].get<std::string>());
    blob.nonce = crypto::from_base64(j["blob_nonce"].get<std::string>());
    if (key_blob.ciphertext.nonce.size() != crypto::kAeadNonceSize ||
        blob.nonce.size() != crypto::kAeadNonceSize) {
        return result;
    }
    auto store_key = wrapping_->unwrap_key(key_blob, {}, binding_key_);
    if (!store_key.has_value()) {
        return result;
    }
    crypto::AeadKey aead_key{};
    std::memcpy(aead_key.data(), store_key->data(), aead_key.size());
    sodium_memzero(store_key->data(), store_key->size());
    const auto aad = crypto::aead_aad(
        crypto::aead_purpose::kStorageShareAtRest,
        {std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(domain.data()), domain.size()),
         std::span<const uint8_t>(binding_key_.data(), binding_key_.size())});
    auto plaintext = crypto_->aead_decrypt(aead_key, blob, aad);
    sodium_memzero(aead_key.data(), aead_key.size());
    if (!plaintext.has_value() || plaintext->empty()) {
        return result;
    }
    result.plaintext = crypto::SecureBuffer(std::span<const uint8_t>(*plaintext));
    sodium_memzero(plaintext->data(), plaintext->size());
    result.status = ShareStoreStatus::Ok;
    return result;
}

bool FileStorageShareStore::remove(std::string_view domain) {
    if (!valid_domain(domain)) {
        return false;
    }
    std::error_code ec;
    std::filesystem::remove(path_of(domain), ec);
    return !std::filesystem::exists(path_of(domain), ec);
}

crypto::SecureBuffer encode_share_bundle(const StorageShareBundle& bundle) {
    if (bundle.size() > kMaxBundleEntries) {
        return {};
    }
    std::vector<uint8_t> out(kBundleMagic.begin(), kBundleMagic.end());
    put_u32(out, static_cast<uint32_t>(bundle.size()));
    for (const auto& [plan, share] : bundle) {
        if (share.empty() || share.size() > kMaxShareBytes) {
            sodium_memzero(out.data(), out.size());
            return {};
        }
        out.insert(out.end(), plan.begin(), plan.end());
        put_u32(out, static_cast<uint32_t>(share.size()));
        out.insert(out.end(), share.data(), share.data() + share.size());
    }
    crypto::SecureBuffer secure{std::span<const uint8_t>(out)};
    sodium_memzero(out.data(), out.size());
    return secure;
}

std::optional<StorageShareBundle> decode_share_bundle(std::span<const uint8_t> bytes) {
    std::size_t offset = 0;
    const auto u32 = [&](uint32_t& value) {
        if (bytes.size() - offset < 4) return false;
        value = 0;
        for (int i = 0; i < 4; ++i) {
            value |= static_cast<uint32_t>(bytes[offset + i]) << (8 * i);
        }
        offset += 4;
        return true;
    };
    if (bytes.size() < kBundleMagic.size() ||
        std::memcmp(bytes.data(), kBundleMagic.data(), kBundleMagic.size()) != 0) {
        return std::nullopt;
    }
    offset = kBundleMagic.size();
    uint32_t count = 0;
    if (!u32(count) || count > kMaxBundleEntries) {
        return std::nullopt;
    }
    StorageShareBundle bundle;
    for (uint32_t i = 0; i < count; ++i) {
        Digest plan{};
        if (bytes.size() - offset < plan.size()) {
            return std::nullopt;
        }
        std::memcpy(plan.data(), bytes.data() + offset, plan.size());
        offset += plan.size();
        uint32_t length = 0;
        if (!u32(length) || length == 0 || length > kMaxShareBytes ||
            bytes.size() - offset < length) {
            return std::nullopt;
        }
        if (!bundle.emplace(plan, crypto::SecureBuffer(bytes.subspan(offset, length))).second) {
            return std::nullopt;
        }
        offset += length;
    }
    if (offset != bytes.size()) {
        return std::nullopt;
    }
    return bundle;
}

}  // namespace nexus::security
