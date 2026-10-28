#pragma once

#include <LemonadeNexus/Network/ApiTypes.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/TreeOpPool.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <concepts>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Forward declarations — handlers only need references
namespace nexus::core {
    struct ServerConfig;
    class BinaryAttestationService;
    class ServerAdmissionService;
}
namespace nexus::auth { class AuthService; }
namespace nexus::tree {
    class PermissionTreeService;
    class TreeOpSubmitter;
}
namespace nexus::ipam { class IPAMService; }
namespace nexus::gossip { class GossipService; }
namespace nexus::crypto {
    class SodiumCryptoService;
    class KeyWrappingService;
}
namespace nexus::storage { class FileStorageService; }
namespace nexus::security { class StorageVault; }
namespace nexus::acme { class AcmeService; }
namespace nexus::network {
    class HttpServer;
    class DdnsService;
    class DnsService;
}
namespace nexus::relay {
    class RelayService;
    class RelayDiscoveryService;
}
namespace nexus::boringtun {
    class BoringtunService;
}
namespace nexus::routing {
    class RoutingCoordinationService;
}

namespace nexus::api {

/// What this server can sign as a current Tier 1 member (GET /api/tier1/proof).
struct Tier1Identity {
    std::array<uint8_t, 32> network_id{};
    uint64_t epoch = 0;
};

/// Aggregate context holding references to all services and computed state.
/// Passed to request handler constructors so they can access what they need.
struct ApiContext {
    core::ServerConfig&               config;
    auth::AuthService&                auth;
    tree::PermissionTreeService&      tree;
    ipam::IPAMService&                ipam;
    gossip::GossipService&            gossip;
    crypto::SodiumCryptoService&      crypto;
    crypto::KeyWrappingService&       key_wrapping;
    storage::FileStorageService&      storage;
    acme::AcmeService&                acme;
    network::HttpServer&              http_server;
    network::DdnsService&             ddns;
    relay::RelayService&              relay;
    relay::RelayDiscoveryService&     relay_discovery;
    routing::RoutingCoordinationService& routing;
    core::BinaryAttestationService&   attestation;
    core::ServerAdmissionService&     admission;
    boringtun::BoringtunService*      boringtun{nullptr};
    network::DnsService*              dns{nullptr};
    std::string                       server_fqdn;
    std::string                       server_seip_fqdn;     // <id>.<region>.seip.<domain>
    std::string                       server_private_fqdn;  // private.<id>.<region>.seip.<domain>
    std::string                       server_public_ip;
    std::string                       tunnel_bind_ip;
    /// Tree-operation submitter (not owned): the only tree write path. The
    /// tree write routes answer 500 without it.
    tree::TreeOpSubmitter*            tree_ops{nullptr};
    /// Answers GET /api/tree/op/{op_id} with a submitted op's status. Set with
    /// a consensus submitter (TreeConsensus::status); unset, the route answers
    /// 404 for every op id.
    std::function<std::optional<tree::TreeOpOutcome>(const std::string&)> tree_op_status;
    /// Answers GET /api/tree/sync with the tree log and its replication
    /// state. Unset, the route answers 404.
    std::function<nlohmann::json()>   tree_log_status;
    /// POST /api/tree/merge/export: the status and body that answer a tree
    /// export request signed by the root management key (TreeMerge.hpp,
    /// verify_tree_export_request). 200 carries this server's signed export;
    /// a server that does not await the merge answers 409. Thread-safe.
    /// Unset, the route answers 404.
    std::function<std::pair<int, nlohmann::json>(const nlohmann::json&)> tree_merge_export;
    /// POST /api/tree/merge/commit: the status and body after the signed tree
    /// merge commit in the request went through the replication checks
    /// (TreeConsensus::receive_replicated). The sender is not trusted; only
    /// the root management key's signature gives the commit authority.
    /// Thread-safe. Unset, the route answers 404.
    std::function<std::pair<int, nlohmann::json>(const nlohmann::json&)> tree_merge_commit;
    /// Files under the data key (Phase 7), or nullptr. Not owned. The admin
    /// storage routes answer 404 without it. In the assembled server it is
    /// always set; nullptr is the state for handlers built without a vault.
    security::StorageVault*           storage_vault{nullptr};
    /// GET /api/tier1/authority: one encoded authority chain page after the
    /// given epoch (encode_authority_chain_page), or empty when this server
    /// stores nothing to add. Thread-safe. Unset, the route answers 404.
    std::function<std::vector<uint8_t>(uint64_t have_epoch)> authority_chain_page;
    /// GET /api/tier1/proof: the network and epoch, only while this server is
    /// a current Tier 1 member by finalized membership; nullopt otherwise.
    /// Thread-safe. Unset counts as not a member.
    std::function<std::optional<Tier1Identity>()> tier1_identity;
    /// POST /api/mesh/heartbeat: the epoch at which this server leaves Tier 1
    /// because the finalized next-epoch plan does not name it, or nullopt
    /// while it stays. The response carries it as "tier1_departure" so a
    /// client moves its session before this server's authority ends. A hint:
    /// the client verifies the new membership itself. Thread-safe. Unset
    /// means no departure is reported.
    std::function<std::optional<uint64_t>()> tier1_departure;
    /// Answers GET /api/upgrade/rollout-proof with this server's rollout
    /// proof (Security/Upgrade/RolloutProof.hpp), or nullopt when it holds
    /// none. Public, self-verifying data; unset, the route answers 404.
    std::function<std::optional<std::string>()> rollout_proof;
};

// ---------------------------------------------------------------------------
// Free helper functions (formerly protected statics on IRequestHandler).
// Usable from any handler without dependent-base-class lookup issues.
// ---------------------------------------------------------------------------

/// Parse JSON request body. Returns nullopt and sets 400 on failure.
inline std::optional<nlohmann::json> parse_body(
        const httplib::Request& req, httplib::Response& res) {
    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded()) {
        res.status = 400;
        nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
        res.set_content(j.dump(), "application/json");
        return std::nullopt;
    }
    return body;
}

/// Send a JSON response with the given status code.
inline void json_response(httplib::Response& res, const nlohmann::json& j,
                           int status = 200) {
    res.status = status;
    res.set_content(j.dump(), "application/json");
}

/// Send an error response.
inline void error_response(httplib::Response& res, const std::string& error,
                            int status = 400) {
    res.status = status;
    nlohmann::json j = network::ErrorResponse{.error = error};
    res.set_content(j.dump(), "application/json");
}

/// Ensure a pubkey string has the "ed25519:" prefix for tree storage.
[[nodiscard]] inline std::string normalize_pubkey(const std::string& pk) {
    constexpr std::string_view prefix = "ed25519:";
    if (pk.starts_with(prefix)) return pk;
    return std::string(prefix) + pk;
}

/// Current Unix epoch timestamp in seconds.
[[nodiscard]] inline uint64_t epoch_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

/// CRTP base for HTTP request handler groups.
/// Derived must implement:
///   void do_register_routes(httplib::Server& pub, httplib::Server& priv)
template <typename Derived>
class IRequestHandler {
public:
    /// Register this handler's routes on the public and private servers.
    void register_routes(httplib::Server& pub, httplib::Server& priv) {
        self().do_register_routes(pub, priv);
    }

protected:
    ~IRequestHandler() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IRequestHandler-derived CRTP class.
template <typename T>
concept RequestHandlerType = requires(T t, httplib::Server& s) {
    t.do_register_routes(s, s);
};

} // namespace nexus::api
