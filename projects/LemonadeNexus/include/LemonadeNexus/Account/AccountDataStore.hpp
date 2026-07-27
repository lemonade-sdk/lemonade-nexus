#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace nexus::crypto { class SodiumCryptoService; }
namespace nexus::tree   { class PermissionTreeService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::account {

/// Result of an account-data operation: an HTTP-style status plus a JSON body
/// (a `{"error":...}` object on failure). The HTTP handler is a thin translator
/// over this — all authorization and storage logic lives here so it is testable
/// without standing up the full ApiContext.
struct Result {
    int            status{200};
    nlohmann::json body;
};

/// Zero-knowledge, per-account store for opaque client-encrypted data over the
/// private mesh API. The server never decrypts anything; it only enforces WHO
/// may read/write and persists opaque blobs.
///
/// Ownership is structural: the on-disk category is derived from the caller's
/// OWN Customer group (its Endpoint node's parent), never from client input, so
/// a caller can only ever address its own group's data. Every op is additionally
/// gated by tree Read/Write on the Customer node. Cross-group access returns 404
/// (never 403 — do not leak existence).
class AccountDataStore {
public:
    // Raw request bodies are opaque ciphertext; cap so one write can't exhaust
    // disk. 4 MiB covers a large conversation with headroom.
    static constexpr std::size_t kMaxBlobBytes = 4u * 1024 * 1024;

    AccountDataStore(crypto::SodiumCryptoService& crypto,
                     tree::PermissionTreeService& tree,
                     storage::FileStorageService& storage);

    // --- Encrypted chat blobs ---
    [[nodiscard]] Result create_chat(const std::string& caller_node,
                                     const std::string& caller_pubkey,
                                     const nlohmann::json& blob, std::size_t body_size);
    [[nodiscard]] Result list_chats(const std::string& caller_node,
                                    const std::string& caller_pubkey) const;
    [[nodiscard]] Result get_chat(const std::string& caller_node,
                                  const std::string& caller_pubkey,
                                  const std::string& chat_id) const;
    [[nodiscard]] Result update_chat(const std::string& caller_node,
                                     const std::string& caller_pubkey,
                                     const std::string& chat_id,
                                     const nlohmann::json& blob, std::size_t body_size);
    [[nodiscard]] Result delete_chat(const std::string& caller_node,
                                     const std::string& caller_pubkey,
                                     const std::string& chat_id);

    // --- Group-key envelopes (opaque; the server never sees the key) ---
    [[nodiscard]] Result put_envelope(const std::string& caller_node,
                                      const std::string& caller_pubkey,
                                      const nlohmann::json& body, std::size_t body_size);
    [[nodiscard]] Result get_envelope(const std::string& caller_node,
                                      const std::string& caller_pubkey) const;
    [[nodiscard]] Result pending_envelopes(const std::string& caller_node,
                                           const std::string& caller_pubkey) const;

private:
    // Caller's owning Customer group (Endpoint node's parent); nullopt if the
    // caller has no node or is topless (root).
    [[nodiscard]] std::optional<std::string> group_of(const std::string& caller_node) const;
    [[nodiscard]] bool can_read(const std::string& caller_pubkey, const std::string& group) const;
    [[nodiscard]] bool can_write(const std::string& caller_pubkey, const std::string& group) const;

    [[nodiscard]] std::string hex_sha256(const std::string& s) const;
    [[nodiscard]] std::string chat_category(const std::string& group) const;   // "chat-"+hash
    [[nodiscard]] std::string keyenv_category(const std::string& group) const; // "keyenv-"+hash
    // Stable, spelling-independent hash of a device pubkey (canonicalized).
    [[nodiscard]] std::string principal_hash(const std::string& pubkey) const;

    crypto::SodiumCryptoService&  crypto_;
    tree::PermissionTreeService&  tree_;
    storage::FileStorageService&  storage_;
};

/// True if `s` is 1..64 lowercase hex chars (a server-generated chat id). Used
/// to reject client-supplied ids before they reach the path layer.
[[nodiscard]] bool is_hex_id(std::string_view s);

/// Ensure the "ed25519:" prefix (tree ACL principal form).
[[nodiscard]] std::string with_ed25519_prefix(const std::string& pk);

} // namespace nexus::account
