#include <LemonadeNexus/Api/RelayApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/GeoRegion.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <unordered_map>

namespace nexus::api {

void RelayApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                         httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // ========================================================================
    // GET /api/relay/list (PRIVATE, auth required)
    // ========================================================================
    priv.Get("/api/relay/list", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res,
               const SessionClaims&) {
        relay::RelaySelectionCriteria criteria;
        criteria.max_results = 50;
        auto relays = ctx_.relay_discovery.discover_relays(criteria);

        std::vector<network::RelayInfoEntry> entries;
        entries.reserve(relays.size());
        for (const auto& r : relays) {
            entries.push_back({
                .relay_id         = r.relay_id,
                .endpoint         = r.endpoint,
                .region           = r.region,
                .reputation_score = r.reputation_score,
                .supports_stun    = r.supports_stun,
                .supports_relay   = r.supports_relay,
            });
        }
        nlohmann::json j = entries;
        res.set_content(j.dump(), "application/json");
    }));

    // ========================================================================
    // GET /api/relay/nearest (PRIVATE, auth required)
    // ========================================================================
    priv.Get("/api/relay/nearest", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto max_str = req.get_param_value("max");
        uint32_t max_results = max_str.empty()
            ? 5
            : static_cast<uint32_t>(std::atoi(max_str.c_str()));
        if (max_results == 0) max_results = 5;
        if (max_results > 50) max_results = 50;

        std::string client_region = req.get_param_value("region");
        auto lat_str = req.get_param_value("lat");
        auto lon_str = req.get_param_value("lon");

        if (client_region.empty() && !lat_str.empty() && !lon_str.empty()) {
            relay::GeoCoord coord{
                std::atof(lat_str.c_str()),
                std::atof(lon_str.c_str()),
            };
            auto nearest = relay::GeoRegion::find_closest_region(coord);
            if (nearest) {
                client_region = nearest->code;
            }
        }

        if (client_region.empty()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{
                .error = "region or lat/lon required",
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        if (!relay::GeoRegion::is_valid_region(client_region)) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{
                .error  = "unknown region",
                .region = client_region,
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        relay::RelaySelectionCriteria criteria;
        criteria.max_results = 200;
        auto relays = ctx_.relay_discovery.discover_relays(criteria);

        std::vector<std::string> relay_regions;
        for (const auto& r : relays) {
            if (!r.region.empty()) {
                relay_regions.push_back(r.region);
            }
        }

        auto sorted_regions = relay::GeoRegion::sort_by_distance(
            client_region, relay_regions);

        std::unordered_map<std::string, int> region_priority;
        for (int i = 0; i < static_cast<int>(sorted_regions.size()); ++i) {
            if (!region_priority.contains(sorted_regions[i])) {
                region_priority[sorted_regions[i]] = i;
            }
        }

        std::sort(relays.begin(), relays.end(),
            [&](const relay::RelayNodeInfo& a, const relay::RelayNodeInfo& b) {
                int pa = region_priority.contains(a.region)
                    ? region_priority[a.region] : 999;
                int pb = region_priority.contains(b.region)
                    ? region_priority[b.region] : 999;
                if (pa != pb) return pa < pb;
                return a.reputation_score > b.reputation_score;
            });

        if (relays.size() > max_results) relays.resize(max_results);

        network::RelayNearestResponse resp;
        resp.client_region = client_region;
        resp.relays.reserve(relays.size());
        for (const auto& r : relays) {
            network::RelayInfoEntry entry{
                .relay_id         = r.relay_id,
                .endpoint         = r.endpoint,
                .region           = r.region,
                .reputation_score = r.reputation_score,
                .supports_stun    = r.supports_stun,
                .supports_relay   = r.supports_relay,
            };
            auto dist = relay::GeoRegion::distance_between_regions(
                client_region, r.region);
            if (dist) entry.distance_km = static_cast<int>(*dist);
            resp.relays.push_back(std::move(entry));
        }

        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // ========================================================================
    // POST /api/relay/ticket (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/relay/ticket", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto ticket_req = body.get<network::RelayTicketRequest>();

        if (ticket_req.peer_id.empty() || ticket_req.relay_id.empty()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{
                .error = "peer_id and relay_id required",
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        relay::RelayTicket ticket;
        ticket.peer_id  = ticket_req.peer_id;
        ticket.relay_id = ticket_req.relay_id;
        ctx_.crypto.random_bytes(std::span<uint8_t>(ticket.session_nonce));

        auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        ticket.issued_at  = now;
        ticket.expires_at = now + 300;

        auto privkey = ctx_.key_wrapping.unlock_identity({});
        if (privkey) {
            std::vector<uint8_t> canonical;
            canonical.insert(canonical.end(),
                             ticket.peer_id.begin(), ticket.peer_id.end());
            canonical.insert(canonical.end(),
                             ticket.relay_id.begin(), ticket.relay_id.end());
            canonical.insert(canonical.end(),
                             ticket.session_nonce.begin(),
                             ticket.session_nonce.end());
            auto push_u64 = [&](uint64_t v) {
                for (int i = 0; i < 8; ++i) {
                    canonical.push_back(static_cast<uint8_t>(v & 0xFF));
                    v >>= 8;
                }
            };
            push_u64(ticket.issued_at);
            push_u64(ticket.expires_at);

            auto sig = ctx_.crypto.ed25519_sign(
                *privkey, std::span<const uint8_t>(canonical));
            std::memcpy(ticket.signature.data(), sig.data(), sig.size());
        }

        network::RelayTicketResponse resp{
            .peer_id       = ticket.peer_id,
            .relay_id      = ticket.relay_id,
            .session_nonce = crypto::to_base64(
                std::span<const uint8_t>(ticket.session_nonce)),
            .issued_at     = ticket.issued_at,
            .expires_at    = ticket.expires_at,
            .signature     = crypto::to_base64(
                std::span<const uint8_t>(ticket.signature)),
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // ========================================================================
    // POST /api/relay/register (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/relay/register", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto reg_req = body.get<network::RelayRegisterRequest>();

        if (reg_req.relay_id.empty() || reg_req.endpoint.empty()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{
                .error = "relay_id and endpoint required",
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        if (!reg_req.region.empty() &&
            !relay::GeoRegion::is_valid_region(reg_req.region)) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{
                .error  = "invalid region code",
                .region = reg_req.region,
                .hint   = "Use format: us-ca, eu-de, ap-jp, etc.",
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        storage::SignedEnvelope envelope;
        envelope.type = "relay_node";
        envelope.data = body.dump();
        envelope.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        (void)ctx_.storage.write_file("relay", reg_req.relay_id, envelope);
        ctx_.relay_discovery.refresh_relay_list();

        network::RelayRegisterResponse resp{
            .success  = true,
            .relay_id = reg_req.relay_id,
            .region   = reg_req.region,
        };
        if (!reg_req.hostname.empty()) {
            resp.dns_names.push_back(
                reg_req.hostname + ".relays." + ctx_.config.dns_base_domain);
            if (!reg_req.region.empty()) {
                resp.dns_names.push_back(
                    reg_req.hostname + "." + reg_req.region
                    + ".relays." + ctx_.config.dns_base_domain);
            }
            resp.dns_names.push_back(
                reg_req.hostname + ".relay." + ctx_.config.dns_base_domain);
        }

        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));
}

} // namespace nexus::api
