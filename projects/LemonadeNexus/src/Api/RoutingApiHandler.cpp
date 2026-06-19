#include <LemonadeNexus/Api/RoutingApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>
#include <LemonadeNexus/Routing/ConnectionTicket.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>

namespace nexus::api {
namespace {

const char* phase_str(routing::SessionPhase p) {
    switch (p) {
        case routing::SessionPhase::Requested:      return "requested";
        case routing::SessionPhase::EndpointReady:  return "endpoint_ready";
        case routing::SessionPhase::ClientNotified: return "client_notified";
        case routing::SessionPhase::Failed:         return "failed";
    }
    return "unknown";
}

const char* path_str(routing::DataPath p) {
    return p == routing::DataPath::DirectP2P ? "direct" : "relay";
}

nlohmann::json candidates_json(const std::vector<routing::Candidate>& cands) {
    auto arr = nlohmann::json::array();
    for (const auto& c : cands) arr.push_back({{"endpoint", c.endpoint}, {"verified", c.verified}});
    return arr;
}

// Decode a base64 16-byte connection nonce; false if absent/wrong size.
bool decode_nonce(const std::string& b64, std::array<uint8_t, 16>& out) {
    auto bytes = crypto::from_base64(b64);
    if (bytes.size() != out.size()) return false;
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return true;
}

} // namespace

void RoutingApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                           httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // ── GET /api/routing/profile ────────────────────────────────────────────
    // The caller's identity + the endpoints it may reach (its parent group's
    // subtree, ACL-filtered), as identifiers. Paginated, capped at 200.
    priv.Get("/api/routing/profile", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        const std::string caller_node_id = claims.user_id;
        const auto caller_pubkey = normalize_pubkey(claims.pubkey);

        auto self = ctx_.tree.get_node(caller_node_id);
        if (!self) { error_response(res, "caller node not found", 404); return; }

        std::size_t page = 0, page_size = 200;
        if (req.has_param("page"))      { try { page = std::stoul(req.get_param_value("page")); } catch (...) {} }
        if (req.has_param("page_size")) { try { page_size = std::stoul(req.get_param_value("page_size")); } catch (...) {} }
        page_size = std::min<std::size_t>(std::max<std::size_t>(page_size, 1), 200);

        std::vector<tree::TreeNode> eps;
        if (!self->parent_id.empty()) {
            for (auto& n : ctx_.tree.collect_subtree(self->parent_id)) {
                if (n.type != tree::NodeType::Endpoint) continue;
                if (n.id == caller_node_id) continue;
                if (n.endpoint_identifier.empty()) continue;
                if (!ctx_.tree.check_permission(caller_pubkey, n.id, acl::Permission::ConnectPrivate) &&
                    !ctx_.tree.check_permission(caller_pubkey, n.id, acl::Permission::ConnectShared)) {
                    continue;
                }
                eps.push_back(std::move(n));
            }
        }
        std::sort(eps.begin(), eps.end(), [](const auto& a, const auto& b) {
            return a.endpoint_identifier < b.endpoint_identifier;
        });

        const std::size_t total = eps.size();
        const std::size_t start = std::min(page * page_size, total);
        const std::size_t end   = std::min(start + page_size, total);

        auto list = nlohmann::json::array();
        for (std::size_t i = start; i < end; ++i) {
            const auto& n = eps[i];
            list.push_back({
                {"identifier",   n.endpoint_identifier},
                {"node_id",      n.id},
                {"hostname",     n.hostname},
                {"region",       n.region},
                {"is_inference", n.is_inference},
                {"tunnel_ip",    n.tunnel_ip},
            });
        }

        nlohmann::json j = {
            {"identity", {
                {"node_id",             self->id},
                {"pubkey",              self->mgmt_pubkey},
                {"endpoint_identifier", self->endpoint_identifier},
                {"hostname",            self->hostname},
            }},
            {"access_chain", {{"parent_id", self->parent_id}}},
            {"authorized_endpoints", list},
            {"total",     total},
            {"page",      page},
            {"page_size", page_size},
        };
        json_response(res, j);
    }));

    // ── POST /api/routing/request ───────────────────────────────────────────
    // Request a connection to an endpoint BY IDENTIFIER. Authz runs through the
    // single resolve_authorized chokepoint; caps are enforced server-side.
    priv.Post("/api/routing/request", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        const std::string caller_node_id = claims.user_id;
        const auto caller_pubkey = normalize_pubkey(claims.pubkey);
        const auto identifier = body.value("identifier", std::string{});
        if (identifier.empty()) { error_response(res, "identifier required"); return; }

        auto target = ctx_.tree.resolve_authorized(caller_pubkey, caller_node_id, identifier);
        if (!target) {
            // Uniform response for unknown and unauthorized — avoids leaking
            // which identifiers exist outside the caller's scope.
            error_response(res, "endpoint not found or not authorized", 403);
            return;
        }

        routing::ConnectionRequestInput in;
        in.client_node_id   = caller_node_id;
        in.client_pubkey    = caller_pubkey;
        in.client_wg_pub    = body.value("client_wg_pub", std::string{});
        in.target_node_id   = target->id;
        in.target_identifier= identifier;
        in.source_ip        = req.remote_addr;
        if (!decode_nonce(body.value("conn_nonce", std::string{}), in.conn_nonce)) {
            error_response(res, "conn_nonce must be 16 bytes base64");
            return;
        }
        if (body.contains("client_candidates") && body["client_candidates"].is_array()) {
            for (auto& c : body["client_candidates"]) {
                if (c.is_string()) in.candidates.push_back(c.get<std::string>());
            }
        }

        auto result = ctx_.routing.create_request(in);
        if (!result.ok) { error_response(res, result.error, result.status); return; }
        json_response(res, {{"connection_id", result.connection_id}, {"state", "requested"}},
                      result.status);
    }));

    // ── POST /api/routing/endpoint/register ─────────────────────────────────
    // Endpoint records its control association + reflexive candidate, and gets
    // back any pending connection ids to act on.
    priv.Post("/api/routing/endpoint/register", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        const std::string node_id = claims.user_id;
        auto node = ctx_.tree.get_node(node_id);
        if (!node) { error_response(res, "node not found", 404); return; }

        // Hardware-bind check: the presented cpu_id/net_mac must re-derive to the
        // node's stored, signed identifier.
        const auto cpu_id  = body.value("cpu_id", std::string{});
        const auto net_mac = body.value("net_mac", std::string{});
        const auto derived = routing::derive_endpoint_identifier(
                node_id, node->region, cpu_id, net_mac, node->is_inference);
        if (derived != node->endpoint_identifier) {
            error_response(res, "identifier/hardware mismatch", 403);
            return;
        }

        routing::EndpointRegistration reg;
        reg.node_id             = node_id;
        reg.endpoint_identifier = node->endpoint_identifier;
        reg.wg_pubkey           = body.value("wg_pubkey", node->wg_pubkey);
        reg.mgmt_pubkey         = node->mgmt_pubkey;
        reg.stun_endpoint       = body.value("stun_endpoint", std::string{});
        reg.source_ip           = req.remote_addr;
        ctx_.routing.register_endpoint(reg);

        auto pending = ctx_.routing.take_pending_for_endpoint(node_id);
        json_response(res, {
            {"success", true},
            {"endpoint_identifier", node->endpoint_identifier},
            {"pending", pending},
        });
    }));

    // ── POST /api/routing/endpoint/ready ────────────────────────────────────
    // Endpoint signals readiness for a specific connection.
    priv.Post("/api/routing/endpoint/ready", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        const std::string node_id = claims.user_id;
        auto node = ctx_.tree.get_node(node_id);
        if (!node) { error_response(res, "node not found", 404); return; }

        const auto cpu_id  = body.value("cpu_id", std::string{});
        const auto net_mac = body.value("net_mac", std::string{});
        if (routing::derive_endpoint_identifier(node_id, node->region, cpu_id, net_mac,
                                                node->is_inference) != node->endpoint_identifier) {
            error_response(res, "identifier/hardware mismatch", 403);
            return;
        }

        routing::EndpointReadyInput in;
        in.connection_id   = body.value("connection_id", std::string{});
        in.endpoint_node_id= node_id;
        in.endpoint_wg_pub = body.value("endpoint_wg_pub", node->wg_pubkey);
        in.source_ip       = req.remote_addr;
        if (body.contains("endpoint_candidates") && body["endpoint_candidates"].is_array()) {
            for (auto& c : body["endpoint_candidates"]) {
                if (c.is_string()) in.candidates.push_back(c.get<std::string>());
            }
        }

        std::string err;
        if (!ctx_.routing.endpoint_ready(in, err)) {
            error_response(res, err, err == "unknown connection" ? 404 : 400);
            return;
        }
        json_response(res, {{"success", true}});
    }));

    // ── POST /api/routing/connect ───────────────────────────────────────────
    // Client fetches the directive once the endpoint is ready. NOTE: the
    // peer_binding and ticket are unsigned in M3 — M3.5 wraps the peer's Noise
    // static in a root-signed IdentityBinding and signs the ConnectionTicket.
    priv.Post("/api/routing/connect", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        const auto connection_id = body_opt->value("connection_id", std::string{});

        auto d = ctx_.routing.build_client_directive(connection_id, claims.user_id);
        if (!d) { error_response(res, "connection not ready or not yours", 409); return; }

        // Coordinator-signed ConnectionTicket (authorizes the connection; carries
        // NO Noise static). M4 wraps the peer's Noise static in a root-signed
        // IdentityBinding so a coordinator signature can never substitute a key.
        routing::ConnectionTicket ticket;
        ticket.connection_id    = d->connection_id;
        ticket.client_node_id   = d->client_node_id;
        ticket.endpoint_node_id = d->endpoint_node_id;
        ticket.conn_nonce       = d->conn_nonce;
        ticket.data_path        = d->data_path;
        ticket.issued_at        = epoch_seconds();
        ticket.expires_at       = ticket.issued_at + 30;
        bool ticket_signed = false;
        if (auto privkey = ctx_.key_wrapping.unlock_identity({})) {
            routing::sign_connection_ticket(ticket, ctx_.crypto, *privkey);
            ticket_signed = true;
        }

        nlohmann::json j = {
            {"connection_id", d->connection_id},
            {"peer_binding", {                       // M4: root-signed IdentityBinding
                {"identifier",  d->endpoint_identifier},
                {"mgmt_pubkey", d->endpoint_mgmt_pubkey},
                {"wg_pubkey",   d->endpoint_wg_pub},  // the E2E Noise static
                {"signed",      false},
            }},
            {"endpoint_candidates", candidates_json(d->endpoint_candidates)},
            {"conn_nonce", crypto::to_base64(std::span<const uint8_t>(d->conn_nonce))},
            {"data_path",  path_str(d->data_path)},
            {"relay_endpoint", d->relay_endpoint},
            {"punch_at", d->punch_at},
            {"ticket", {
                {"connection_id",    ticket.connection_id},
                {"client_node_id",   ticket.client_node_id},
                {"endpoint_node_id", ticket.endpoint_node_id},
                {"conn_nonce", crypto::to_base64(std::span<const uint8_t>(ticket.conn_nonce))},
                {"data_path",  path_str(ticket.data_path)},
                {"issued_at",  ticket.issued_at},
                {"expires_at", ticket.expires_at},
                {"signature",  crypto::to_base64(std::span<const uint8_t>(ticket.signature))},
                {"signed",     ticket_signed},
            }},
        };
        json_response(res, j);
    }));

    // ── GET /api/routing/session/{id} ───────────────────────────────────────
    priv.Get(R"(/api/routing/session/([a-fA-F0-9]+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        const std::string connection_id = req.matches[1];
        auto v = ctx_.routing.get_session(connection_id, claims.user_id);
        if (!v) { error_response(res, "session not found", 404); return; }
        json_response(res, {
            {"connection_id", v->connection_id},
            {"phase",      phase_str(v->phase)},
            {"data_path",  path_str(v->data_path)},
            {"created_at", v->created_at},
            {"expires_at", v->expires_at},
        });
    }));
}

} // namespace nexus::api
