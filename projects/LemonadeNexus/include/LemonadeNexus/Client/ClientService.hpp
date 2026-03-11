#pragma once

#include <LemonadeNexus/Client/IClientProvider.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <nlohmann/json.hpp>

#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::client {

/// Client-side service used by endpoints to join the Lemonade-Nexus network,
/// discover servers / relays, and modify the permission tree.
///
/// Combines IService (lifecycle) and IClientProvider (client operations).
/// All HTTP communication uses cpp-httplib (temporary Client per request).
class ClientService : public core::IService<ClientService>,
                       public IClientProvider<ClientService> {
    friend class core::IService<ClientService>;
    friend class IClientProvider<ClientService>;

public:
    ClientService(storage::FileStorageService& storage,
                   crypto::SodiumCryptoService& crypto);

    // -- IService -----------------------------------------------------------
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "ClientService"; }

    // -- IClientProvider ----------------------------------------------------
    [[nodiscard]] std::vector<ServerEndpoint>
    do_discover_servers(const std::vector<ServerEndpoint>& bootstrap_endpoints);

    [[nodiscard]] JoinResult
    do_join_network(const ServerEndpoint& server, const nlohmann::json& credentials_json);

    [[nodiscard]] bool do_leave_network();

    [[nodiscard]] TreeModifyResult do_submit_delta(const tree::TreeDelta& delta);

    [[nodiscard]] TreeModifyResult
    do_create_child_node(const std::string& parent_id, const tree::TreeNode& child_node);

    [[nodiscard]] TreeModifyResult
    do_update_node(const std::string& node_id, const nlohmann::json& updates_json);

    [[nodiscard]] std::vector<relay::RelayNodeInfo>
    do_get_available_relays(const relay::RelaySelectionCriteria& criteria);

    [[nodiscard]] std::vector<std::string>
    do_get_my_permissions(const std::string& node_id);

private:
    // -- HTTP helpers -------------------------------------------------------
    /// POST JSON to a coordination server, returning the parsed response body.
    [[nodiscard]] std::optional<nlohmann::json>
    http_post(const ServerEndpoint& server,
              const std::string& path,
              const nlohmann::json& body);

    /// GET from a coordination server, returning the parsed response body.
    [[nodiscard]] std::optional<nlohmann::json>
    http_get(const ServerEndpoint& server,
             const std::string& path);

    // -- Internal helpers ---------------------------------------------------
    /// Load or generate the client identity keypair from storage.
    void load_identity();

    /// Persist the identity keypair to storage.
    void save_identity();

    /// Load the list of known servers from storage.
    void load_known_servers();

    /// Persist the list of known servers to storage.
    void save_known_servers();

    // -- State --------------------------------------------------------------
    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;
    crypto::Ed25519Keypair       identity_keypair_{};
    std::string                  my_node_id_;
    std::vector<ServerEndpoint>  known_servers_;
    mutable std::mutex           mutex_;
};

} // namespace nexus::client
