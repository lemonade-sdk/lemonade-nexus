#pragma once

#include <LemonadeNexus/Network/ApiTypes.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <concepts>
#include <optional>
#include <string>

// Forward declarations — handlers only need references
namespace nexus::core {
    struct ServerConfig;
    class BinaryAttestationService;
    class TeeAttestationService;
    class TrustPolicyService;
    class GovernanceService;
}
namespace nexus::auth { class AuthService; }
namespace nexus::tree { class PermissionTreeService; }
namespace nexus::ipam { class IPAMService; }
namespace nexus::gossip { class GossipService; }
namespace nexus::crypto {
    class SodiumCryptoService;
    class KeyWrappingService;
}
namespace nexus::storage { class FileStorageService; }
namespace nexus::acme { class AcmeService; }
namespace nexus::network {
    class HttpServer;
    class DdnsService;
}
namespace nexus::relay {
    class RelayService;
    class RelayDiscoveryService;
}
namespace nexus::wireguard {
    class WireGuardService;
}

namespace nexus::api {

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
    core::BinaryAttestationService&   attestation;
    core::TeeAttestationService&      tee;
    core::TrustPolicyService&         trust_policy;
    core::GovernanceService&          governance;
    wireguard::WireGuardService*      wireguard{nullptr};
    std::string                       server_fqdn;
    std::string                       server_public_ip;
    std::string                       tunnel_bind_ip;
};

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

    /// Parse JSON request body. Returns nullopt and sets 400 on failure.
    static std::optional<nlohmann::json> parse_body(
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
    static void json_response(httplib::Response& res, const nlohmann::json& j,
                              int status = 200) {
        res.status = status;
        res.set_content(j.dump(), "application/json");
    }

    /// Send an error response.
    static void error_response(httplib::Response& res, const std::string& error,
                               int status = 400) {
        res.status = status;
        nlohmann::json j = network::ErrorResponse{.error = error};
        res.set_content(j.dump(), "application/json");
    }

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
