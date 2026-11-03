#include <LemonadeNexus/Api/PublicApiHandler.hpp>

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Network/SeipNaming.hpp>
#include <LemonadeNexus/Gossip/DevicePresence.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <algorithm>

namespace nexus::api {

NetworkCounts count_network(const tree::rules::NodeMap& nodes,
                            const gossip::DevicePresence& presence, uint64_t now) {
    NetworkCounts counts;
    for (const auto& [id, node] : nodes) {
        switch (node.type) {
            case tree::NodeType::Endpoint:
                ++counts.devices;
                if (presence.status(id, now).online) ++counts.devices_online;
                break;
            case tree::NodeType::Customer: ++counts.groups; break;
            case tree::NodeType::Relay:    ++counts.relays; break;
            case tree::NodeType::Root:     break;
        }
    }
    return counts;
}

NetworkCounts PublicApiHandler::network_counts(uint64_t now) {
    std::lock_guard lock(counts_mutex_);
    if (counts_at_ == 0 || now >= counts_at_ + kNetworkCountsCacheSec || now < counts_at_) {
        counts_ = count_network(ctx_.tree.nodes_snapshot(), ctx_.gossip.device_presence(), now);
        counts_at_ = now;
    }
    return counts_;
}

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

    // GET /api/upgrade/rollout-proof — the finalized rollout state with the
    // authority chain that proves it. The release workflow verifies it from
    // the Genesis key before it publishes; this server is not trusted for it.
    pub.Get("/api/upgrade/rollout-proof", [this](const httplib::Request&, httplib::Response& res) {
        if (!ctx_.rollout_proof) {
            error_response(res, "rollout proofs are not served", 404);
            return;
        }
        const auto proof = ctx_.rollout_proof();
        if (!proof) {
            error_response(res, "this server holds no complete rollout proof", 503);
            return;
        }
        res.set_content(*proof, "application/json");
    });

    // GET /api/tls/status — TLS configuration info
    pub.Get("/api/tls/status", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json resp = {
            {"tls_enabled",  ctx_.http_server.is_tls()},
            {"cert_path",    ctx_.http_server.tls_cert_path()},
            {"key_path",     ctx_.http_server.tls_key_path()},
            {"server_fqdn",  ctx_.server_fqdn},
        };
        json_response(res, resp);
    });

    // GET /api/stats — service statistics. Aggregate counts only: nothing
    // that names a device, account, group, or address.
    pub.Get("/api/stats", [this](const httplib::Request&, httplib::Response& res) {
        auto peers = ctx_.gossip.get_peers();
        const auto relay_sessions = ctx_.relay.session_count();
        const auto relay_paired = ctx_.relay.paired_session_count();
        nlohmann::json resp = {
            {"service",             "lemonade-nexus"},
            {"peer_count",          peers.size()},
            {"private_api_enabled", !ctx_.tunnel_bind_ip.empty()},
            // This server's relay only.
            {"relay_sessions", {{"paired", relay_paired},
                                {"waiting", relay_sessions - std::min(relay_paired, relay_sessions)}}},
        };
        // Network counts come from the tree and the presence that Tier 1
        // members share, so only a current Tier 1 member reports them.
        if (ctx_.tier1_identity && ctx_.tier1_identity()) {
            const auto now = epoch_seconds();
            const auto counts = network_counts(now);
            resp["network"] = {
                {"devices_registered", counts.devices},
                {"devices_online",     counts.devices_online},
                {"devices_offline",    counts.devices - counts.devices_online},
                {"groups",             counts.groups},
                {"relays",             counts.relays},
            };
        }
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
            // Clients reach the public API by the SEIP FQDN (what the cert covers).
            .fqdn      = !ctx_.server_seip_fqdn.empty() ? ctx_.server_seip_fqdn
                                                        : ctx_.server_fqdn,
            // The node identity a Tier 1 endpoint proof is signed with.
            .pubkey    = crypto::to_base64(ctx_.gossip.keypair().public_key),
            .http_port = ctx_.config.http_port,
            .healthy   = true,
        });

        // Each peer's SEIP FQDN is <cert.server_id>.<region>.seip.<domain> — the
        // same name the peer publishes and its cert covers — so clients can reach
        // it over verified HTTPS. Left empty (and skipped by clients) when the
        // peer has no cert or region.
        for (const auto& p : peers) {
            std::string fqdn;
            if (!p.certificate_json.empty() && !p.region.empty() &&
                !ctx_.config.dns_base_domain.empty()) {
                try {
                    auto sid = nlohmann::json::parse(p.certificate_json).value("server_id", "");
                    if (!sid.empty())
                        fqdn = seip::seipFqdn(sid, p.region, ctx_.config.dns_base_domain);
                } catch (...) {}
            }
            entries.push_back({
                .endpoint  = p.endpoint,
                .fqdn      = fqdn,
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
