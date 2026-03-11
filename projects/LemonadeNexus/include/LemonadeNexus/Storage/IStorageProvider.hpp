#pragma once

#include <concepts>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::storage {

/// A signed envelope wrapping any JSON data on disk.
struct SignedEnvelope {
    uint32_t    version{1};
    std::string type;           // "tree_node", "delta", "credential", "ipam", etc.
    std::string data;           // JSON string of actual content
    std::string signer_pubkey;  // "ed25519:base64..."
    std::string signature;      // base64 Ed25519 signature
    uint64_t    timestamp{0};   // Unix timestamp
};

/// A signed delta in the delta log.
struct SignedDelta {
    uint64_t    sequence{0};
    std::string operation;       // "create_node", "update_node", "delete_node", etc.
    std::string target_node_id;
    std::string data;            // JSON delta payload
    std::string signer_pubkey;
    std::string required_permission;
    std::string signature;
    uint64_t    timestamp{0};
};

/// CRTP base for storage operations.
/// Derived must implement:
///   bool do_write_node(std::string_view node_id, const SignedEnvelope& envelope)
///   std::optional<SignedEnvelope> do_read_node(std::string_view node_id) const
///   bool do_delete_node(std::string_view node_id)
///   std::vector<std::string> do_list_nodes() const
///   uint64_t do_append_delta(const SignedDelta& delta)
///   std::optional<SignedDelta> do_read_delta(uint64_t seq) const
///   uint64_t do_latest_delta_seq() const
///   std::vector<SignedDelta> do_read_deltas_since(uint64_t seq) const
///   bool do_write_file(std::string_view category, std::string_view name, const SignedEnvelope&)
///   std::optional<SignedEnvelope> do_read_file(std::string_view category, std::string_view name) const
///   void do_ensure_directories()
template <typename Derived>
class IStorageProvider {
public:
    [[nodiscard]] bool write_node(std::string_view node_id, const SignedEnvelope& envelope) {
        return self().do_write_node(node_id, envelope);
    }

    [[nodiscard]] std::optional<SignedEnvelope> read_node(std::string_view node_id) const {
        return self().do_read_node(node_id);
    }

    [[nodiscard]] bool delete_node(std::string_view node_id) {
        return self().do_delete_node(node_id);
    }

    [[nodiscard]] std::vector<std::string> list_nodes() const {
        return self().do_list_nodes();
    }

    [[nodiscard]] uint64_t append_delta(const SignedDelta& delta) {
        return self().do_append_delta(delta);
    }

    [[nodiscard]] std::optional<SignedDelta> read_delta(uint64_t seq) const {
        return self().do_read_delta(seq);
    }

    [[nodiscard]] uint64_t latest_delta_seq() const {
        return self().do_latest_delta_seq();
    }

    [[nodiscard]] std::vector<SignedDelta> read_deltas_since(uint64_t seq) const {
        return self().do_read_deltas_since(seq);
    }

    // Generic file storage for credentials, ipam, certs, etc.
    [[nodiscard]] bool write_file(std::string_view category, std::string_view name,
                                   const SignedEnvelope& envelope) {
        return self().do_write_file(category, name, envelope);
    }

    [[nodiscard]] std::optional<SignedEnvelope> read_file(std::string_view category,
                                                           std::string_view name) const {
        return self().do_read_file(category, name);
    }

    void ensure_directories() {
        self().do_ensure_directories();
    }

protected:
    ~IStorageProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IStorageProvider implementation.
template <typename T>
concept StorageProviderType = requires(T t, const T ct,
                                        std::string_view sv,
                                        const SignedEnvelope& env,
                                        const SignedDelta& delta,
                                        uint64_t seq) {
    { t.do_write_node(sv, env) } -> std::same_as<bool>;
    { ct.do_read_node(sv) } -> std::same_as<std::optional<SignedEnvelope>>;
    { t.do_delete_node(sv) } -> std::same_as<bool>;
    { ct.do_list_nodes() } -> std::same_as<std::vector<std::string>>;
    { t.do_append_delta(delta) } -> std::same_as<uint64_t>;
    { ct.do_read_delta(seq) } -> std::same_as<std::optional<SignedDelta>>;
    { ct.do_latest_delta_seq() } -> std::same_as<uint64_t>;
    { ct.do_read_deltas_since(seq) } -> std::same_as<std::vector<SignedDelta>>;
    { t.do_write_file(sv, sv, env) } -> std::same_as<bool>;
    { ct.do_read_file(sv, sv) } -> std::same_as<std::optional<SignedEnvelope>>;
    { t.do_ensure_directories() } -> std::same_as<void>;
};

} // namespace nexus::storage
