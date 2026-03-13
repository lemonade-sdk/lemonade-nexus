#include <LemonadeNexus/Api/PublicApiHandler.hpp>

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>

namespace nexus::api {

void PublicApiHandler::do_register_routes(httplib::Server& pub,
                                          [[maybe_unused]] httplib::Server& priv) {
    // GET /api/health — basic liveness check
    pub.Get("/api/health", [this](const httplib::Request&, httplib::Response& res) {
        network::HealthResponse resp;
        resp.rp_id           = ctx_.config.rp_id;
        resp.dns_base_domain = ctx_.config.dns_base_domain;
        nlohmann::json j = resp;
        json_response(res, j);
    });

    // GET /api/tls/status — TLS configuration info
    pub.Get("/api/tls/status", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json resp = {
            {"tls_enabled",  ctx_.http_server.is_tls()},
            {"cert_path",    ctx_.http_server.tls_cert_path()},
            {"key_path",     ctx_.http_server.tls_key_path()},
            {"server_fqdn",  ctx_.server_fqdn},
            {"auto_tls",     ctx_.config.auto_tls},
        };
        json_response(res, resp);
    });

    // GET /api/stats — service statistics
    pub.Get("/api/stats", [this](const httplib::Request&, httplib::Response& res) {
        auto peers = ctx_.gossip.get_peers();
        nlohmann::json resp = {
            {"service",             "lemonade-nexus"},
            {"peer_count",          peers.size()},
            {"private_api_enabled", !ctx_.tunnel_bind_ip.empty()},
        };
        json_response(res, resp);
    });

    // GET /api/servers — list ourselves plus all gossip peers
    pub.Get("/api/servers", [this](const httplib::Request&, httplib::Response& res) {
        auto peers = ctx_.gossip.get_peers();
        std::vector<network::ServerEntry> entries;

        std::string our_endpoint =
            (!ctx_.server_public_ip.empty() ? ctx_.server_public_ip
                                            : ctx_.config.bind_address)
            + ":" + std::to_string(ctx_.config.http_port);

        entries.push_back({
            .endpoint  = our_endpoint,
            .http_port = ctx_.config.http_port,
            .healthy   = true,
        });

        for (const auto& p : peers) {
            entries.push_back({
                .endpoint  = p.endpoint,
                .pubkey    = p.pubkey,
                .http_port = p.http_port,
                .last_seen = p.last_seen,
                .healthy   = true,
            });
        }

        nlohmann::json j = entries;
        json_response(res, j);
    });
}

} // namespace nexus::api
