#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/ACL/IACLProvider.hpp>
#include <LemonadeNexus/ACL/AclStore.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <functional>
#include <mutex>
#include <optional>
#include <string_view>
#include <vector>

namespace nexus::acl {

/// Signed ACL delta for gossip propagation.
struct AclDelta {
    std::string delta_id;
    std::string operation;     // "grant" or "revoke"
    std::string user_id;
    std::string resource;
    uint32_t    permissions{0};
    uint64_t    timestamp{0};
    std::string signer_pubkey;
    std::string signature;
};

/// Callback type: called when a local ACL mutation needs to be broadcast via gossip.
using AclDeltaCallback = std::function<void(const AclDelta&)>;

/// SQLite-backed ACL service with XChaCha20-Poly1305 encrypted permission values
/// and distributed sync via gossip ACL deltas.
///
/// Database: data/acl.db
/// Tables:
///   acl(user_id, resource, perms_enc BLOB, last_modified INTEGER)
///   acl_seen_deltas(delta_id TEXT PRIMARY KEY)   — deduplication
class ACLService : public core::IService<ACLService>,
                   public IACLProvider<ACLService> {
    friend class core::IService<ACLService>;
    friend class IACLProvider<ACLService>;
public:
    explicit ACLService(AclStore& store, crypto::SodiumCryptoService& crypto);

    ACLService(const ACLService&) = delete;
    ACLService& operator=(const ACLService&) = delete;

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "ACLService"; }

    Permission do_get_permissions(std::string_view user_id, std::string_view resource) const;
    bool do_grant(std::string_view user_id, std::string_view resource, Permission perms);
    bool do_revoke(std::string_view user_id, std::string_view resource, Permission perms);

    /// Set the Ed25519 keypair used for signing deltas and deriving the encryption key.
    void set_signing_keypair(const crypto::Ed25519Keypair& kp);

    /// Register a callback invoked when a local ACL mutation needs gossip broadcast.
    void set_delta_callback(AclDeltaCallback cb);

    /// Apply a remote ACL delta received via gossip. Returns true if applied
    /// (new delta), false if already seen (duplicate).
    bool apply_remote_delta(const AclDelta& delta);

private:
    void derive_encryption_key();
    /// The row identity is authenticated, so a permission blob cannot be moved
    /// to another (user, resource) pair.
    std::vector<uint8_t> encrypt_perms(uint32_t perms, std::string_view user_id,
                                       std::string_view resource) const;
    [[nodiscard]] std::optional<uint32_t> decrypt_perms(const std::vector<uint8_t>& blob,
                                                        std::string_view user_id,
                                                        std::string_view resource) const;

    [[nodiscard]] std::string generate_delta_id() const;
    void sign_delta(AclDelta& delta) const;
    [[nodiscard]] bool verify_delta_signature(const AclDelta& delta) const;

    AclStore&                    store_;
    crypto::SodiumCryptoService& crypto_;
    crypto::Ed25519Keypair       signing_keypair_{};
    crypto::AeadKey            encryption_key_{};
    bool                         has_key_{false};

    mutable std::mutex           mutex_;
    AclDeltaCallback             delta_callback_;
};

} // namespace nexus::acl
