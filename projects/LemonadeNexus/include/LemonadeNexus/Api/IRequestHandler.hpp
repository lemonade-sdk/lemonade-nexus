#pragma once

#include <LemonadeNexus/Network/ApiTypes.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <concepts>
#include <optional>
#include <string>
#include <string_view>

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
    class DnsService;
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
    network::DnsService*              dns{nullptr};
    std::string                       server_fqdn;
    std::string                       server_seip_fqdn;     // <id>.<region>.seip.<domain>
    std::string                       server_private_fqdn;  // private.<id>.<region>.seip.<domain>
    std::string                       server_public_ip;
    std::string                       tunnel_bind_ip;
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
