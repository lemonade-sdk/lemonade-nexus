#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <cstring>
#include <filesystem>
#include <fstream>

namespace nexus::crypto {

namespace fs = std::filesystem;

static constexpr std::string_view kHkdfSalt = "lemonade-nexus-mgmt-key";

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

KeyWrappingService::KeyWrappingService(SodiumCryptoService& crypto,
                                       storage::FileStorageService& storage)
    : crypto_(crypto)
    , storage_(storage)
{
}

// ---------------------------------------------------------------------------
// IService
// ---------------------------------------------------------------------------

void KeyWrappingService::on_start() {
    auto pub = load_identity_pubkey();
    if (pub) {
        spdlog::info("[{}] identity public key loaded: {}...",
                     name(), to_hex(std::span<const uint8_t>(pub->data(), 4)));
    } else {
        spdlog::info("[{}] no identity keypair found on disk", name());
    }
}

void KeyWrappingService::on_stop() {
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Wrap / Unwrap
// ---------------------------------------------------------------------------

WrappedKey KeyWrappingService::wrap_key(const Ed25519PrivateKey& privkey,
                                         std::span<const uint8_t> passphrase,
                                         const Ed25519PublicKey& pubkey) {
    auto aes_key = derive_wrapping_key(passphrase, pubkey);

    // Encrypt the 64-byte Ed25519 private key
    auto ct = crypto_.aes_gcm_encrypt(
        aes_key,
        std::span<const uint8_t>(privkey.data(), privkey.size()),
        std::span<const uint8_t>(pubkey.data(), pubkey.size())); // pubkey as AAD

    WrappedKey result;
    result.ciphertext = std::move(ct);
    return result;
}

std::optional<Ed25519PrivateKey> KeyWrappingService::unwrap_key(
        const WrappedKey& wrapped,
        std::span<const uint8_t> passphrase,
        const Ed25519PublicKey& pubkey) {
    auto aes_key = derive_wrapping_key(passphrase, pubkey);

    auto plaintext = crypto_.aes_gcm_decrypt(
        aes_key,
        wrapped.ciphertext,
        std::span<const uint8_t>(pubkey.data(), pubkey.size())); // pubkey as AAD

    if (!plaintext || plaintext->size() != kEd25519PrivateKeySize) {
        return std::nullopt;
    }

    Ed25519PrivateKey privkey{};
    std::memcpy(privkey.data(), plaintext->data(), kEd25519PrivateKeySize);
    return privkey;
}

// ---------------------------------------------------------------------------
// Identity management
// ---------------------------------------------------------------------------

Ed25519Keypair KeyWrappingService::generate_and_store_identity(
        std::span<const uint8_t> passphrase) {
    auto keypair = crypto_.ed25519_keygen();

    // Wrap the private key
    auto wrapped = wrap_key(keypair.private_key, passphrase, keypair.public_key);

    // Store public key
    auto identity_dir = storage_.data_root() / "identity";
    fs::create_directories(identity_dir);

    {
        auto pub_path = identity_dir / "keypair.pub";
        std::ofstream ofs(pub_path, std::ios::binary);
        auto hex = to_hex(std::span<const uint8_t>(keypair.public_key));
        ofs << hex;
        ofs.close();
        // Owner read/write only
        std::error_code ec;
        fs::permissions(pub_path,
            fs::perms::owner_read | fs::perms::owner_write,
            fs::perm_options::replace, ec);
        spdlog::info("[{}] wrote public key to {}", name(), pub_path.string());
    }

    {
        // Store wrapped private key as: nonce_hex + ":" + ciphertext_hex
        auto enc_path = identity_dir / "keypair.enc";
        std::ofstream ofs(enc_path, std::ios::binary);
        auto nonce_hex = to_hex(std::span<const uint8_t>(
            wrapped.ciphertext.nonce.data(), wrapped.ciphertext.nonce.size()));
        auto ct_hex = to_hex(std::span<const uint8_t>(wrapped.ciphertext.ciphertext));
        ofs << nonce_hex << ":" << ct_hex;
        ofs.close();
        // Owner read/write only — encrypted key material
        std::error_code ec;
        fs::permissions(enc_path,
            fs::perms::owner_read | fs::perms::owner_write,
            fs::perm_options::replace, ec);
        spdlog::info("[{}] wrote encrypted private key to {}", name(), enc_path.string());
    }

    return keypair;
}

std::optional<Ed25519PublicKey> KeyWrappingService::load_identity_pubkey() const {
    auto pub_path = storage_.data_root() / "identity" / "keypair.pub";
    if (!fs::exists(pub_path)) {
        return std::nullopt;
    }

    std::ifstream ifs(pub_path);
    if (!ifs) {
        return std::nullopt;
    }

    std::string hex_str;
    ifs >> hex_str;

    auto bytes = from_hex(hex_str);
    if (bytes.size() != kEd25519PublicKeySize) {
        spdlog::warn("[{}] invalid public key size: {} (expected {})",
                     name(), bytes.size(), kEd25519PublicKeySize);
        return std::nullopt;
    }

    Ed25519PublicKey pubkey{};
    std::memcpy(pubkey.data(), bytes.data(), kEd25519PublicKeySize);
    return pubkey;
}

std::optional<Ed25519PrivateKey> KeyWrappingService::unlock_identity(
        std::span<const uint8_t> passphrase) {
    auto pubkey = load_identity_pubkey();
    if (!pubkey) {
        spdlog::warn("[{}] cannot unlock: no public key found", name());
        return std::nullopt;
    }

    auto enc_path = storage_.data_root() / "identity" / "keypair.enc";
    if (!fs::exists(enc_path)) {
        spdlog::warn("[{}] cannot unlock: no encrypted key found", name());
        return std::nullopt;
    }

    std::ifstream ifs(enc_path);
    if (!ifs) {
        return std::nullopt;
    }

    std::string content;
    std::getline(ifs, content);

    auto colon = content.find(':');
    if (colon == std::string::npos) {
        spdlog::warn("[{}] invalid encrypted key format", name());
        return std::nullopt;
    }

    auto nonce_bytes = from_hex(content.substr(0, colon));
    auto ct_bytes = from_hex(content.substr(colon + 1));

    if (nonce_bytes.size() != kAesGcmNonceSize) {
        spdlog::warn("[{}] invalid nonce size in encrypted key: {}", name(), nonce_bytes.size());
        return std::nullopt;
    }

    WrappedKey wrapped;
    wrapped.ciphertext.nonce = std::move(nonce_bytes);
    wrapped.ciphertext.ciphertext = std::move(ct_bytes);

    return unwrap_key(wrapped, passphrase, *pubkey);
}

// ---------------------------------------------------------------------------
// Key delegation
// ---------------------------------------------------------------------------

DelegationResult KeyWrappingService::delegate_key(
        std::span<const uint8_t> parent_passphrase) {
    DelegationResult result;

    // Generate child Ed25519 keypair
    result.child_keypair = crypto_.ed25519_keygen();

    // Generate random wrapping key (WK)
    AesGcmKey wk{};
    crypto_.random_bytes(std::span<uint8_t>(wk));

    // Wrap child private key with WK
    result.wrapped_child_key.ciphertext = crypto_.aes_gcm_encrypt(
        wk,
        std::span<const uint8_t>(result.child_keypair.private_key.data(),
                                 result.child_keypair.private_key.size()),
        {}); // no AAD for delegation wrapping

    // Convert child's Ed25519 public key to X25519 for hybrid encryption
    auto child_x25519_pk = SodiumCryptoService::ed25519_pk_to_x25519(
        result.child_keypair.public_key);

    // Generate ephemeral X25519 keypair for encrypting WK
    auto ephemeral = crypto_.x25519_keygen();

    // DH: ephemeral_priv * child_x25519_pk → shared secret
    auto shared = crypto_.x25519_dh(ephemeral.private_key, child_x25519_pk);

    // Derive AES key from shared secret
    auto derived = crypto_.hkdf_sha256(
        std::span<const uint8_t>(shared.data(), shared.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(parent_passphrase.data()),
                                 parent_passphrase.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("lemonade-nexus-delegation"),
                                 22),
        kAesGcmKeySize);

    AesGcmKey delegation_key{};
    std::memcpy(delegation_key.data(), derived.data(), kAesGcmKeySize);

    // Encrypt WK with the derived key, include ephemeral pubkey as AAD
    result.encrypted_wk = crypto_.aes_gcm_encrypt(
        delegation_key,
        std::span<const uint8_t>(wk.data(), wk.size()),
        std::span<const uint8_t>(ephemeral.public_key.data(),
                                 ephemeral.public_key.size()));

    // Store ephemeral pubkey so the child can derive the same shared secret
    result.ephemeral_pubkey = ephemeral.public_key;

    // Zero sensitive material
    sodium_memzero(wk.data(), wk.size());
    sodium_memzero(delegation_key.data(), delegation_key.size());

    result.success = true;
    spdlog::info("[{}] delegated new child key", name());
    return result;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

AesGcmKey KeyWrappingService::derive_wrapping_key(
        std::span<const uint8_t> passphrase,
        const Ed25519PublicKey& pubkey) const {
    auto derived = crypto_.hkdf_sha256(
        passphrase,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kHkdfSalt.data()),
                                 kHkdfSalt.size()),
        std::span<const uint8_t>(pubkey.data(), pubkey.size()),
        kAesGcmKeySize);

    AesGcmKey key{};
    std::memcpy(key.data(), derived.data(), kAesGcmKeySize);
    return key;
}

} // namespace nexus::crypto
