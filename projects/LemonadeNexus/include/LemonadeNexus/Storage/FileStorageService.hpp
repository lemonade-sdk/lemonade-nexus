#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Storage/IStorageProvider.hpp>

#include <filesystem>
#include <mutex>
#include <string>

namespace nexus::storage {

/// File-based storage service. All state is stored as signed JSON files.
///
/// Directory layout under data_root:
///   tree/nodes/<node_id>.json     — permission tree nodes
///   tree/deltas/<sequence>.json   — sequential delta log
///   identity/                     — server keypair, peers
///   credentials/<user_id>.json    — WebAuthn credentials
///   ipam/allocations.json         — IP allocations
///   certs/<domain>/               — TLS certificates
class FileStorageService : public core::IService<FileStorageService>,
                            public IStorageProvider<FileStorageService> {
    friend class core::IService<FileStorageService>;
    friend class IStorageProvider<FileStorageService>;

public:
    explicit FileStorageService(std::filesystem::path data_root);

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "FileStorageService"; }

    // IStorageProvider — tree nodes
    [[nodiscard]] bool do_write_node(std::string_view node_id, const SignedEnvelope& envelope);
    [[nodiscard]] std::optional<SignedEnvelope> do_read_node(std::string_view node_id) const;
    [[nodiscard]] bool do_delete_node(std::string_view node_id);
    [[nodiscard]] std::vector<std::string> do_list_nodes() const;

    // IStorageProvider — delta log
    [[nodiscard]] uint64_t do_append_delta(const SignedDelta& delta);
    [[nodiscard]] std::optional<SignedDelta> do_read_delta(uint64_t seq) const;
    [[nodiscard]] uint64_t do_latest_delta_seq() const;
    [[nodiscard]] std::vector<SignedDelta> do_read_deltas_since(uint64_t seq) const;

    // IStorageProvider — generic file storage
    [[nodiscard]] bool do_write_file(std::string_view category, std::string_view name,
                                      const SignedEnvelope& envelope);
    [[nodiscard]] std::optional<SignedEnvelope> do_read_file(std::string_view category,
                                                              std::string_view name) const;
    void do_ensure_directories();

    [[nodiscard]] const std::filesystem::path& data_root() const { return data_root_; }

private:
    [[nodiscard]] std::filesystem::path node_path(std::string_view node_id) const;
    [[nodiscard]] std::filesystem::path delta_path(uint64_t seq) const;
    [[nodiscard]] std::filesystem::path file_path(std::string_view category,
                                                    std::string_view file_name) const;

    /// Validate that a user-supplied path component contains no traversal sequences.
    [[nodiscard]] static bool is_safe_path_component(std::string_view component);

    [[nodiscard]] static std::string envelope_to_json(const SignedEnvelope& envelope);
    [[nodiscard]] static std::optional<SignedEnvelope> json_to_envelope(std::string_view json);
    [[nodiscard]] static std::string delta_to_json(const SignedDelta& delta);
    [[nodiscard]] static std::optional<SignedDelta> json_to_delta(std::string_view json);

    std::filesystem::path data_root_;
    mutable std::mutex    mutex_;
    uint64_t              next_delta_seq_{1};
};

} // namespace nexus::storage
