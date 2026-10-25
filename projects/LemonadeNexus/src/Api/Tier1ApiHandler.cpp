#include <LemonadeNexus/Api/Tier1ApiHandler.hpp>

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>

#include <cctype>
#include <optional>
#include <string>

namespace nexus::api {

namespace {

/// A decimal epoch with no sign, no leading space, and no overflow.
[[nodiscard]] std::optional<uint64_t> parse_epoch(const std::string& text) {
    if (text.empty() || text.size() > 20) return std::nullopt;
    uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return std::nullopt;
        value = value * 10 + digit;
    }
    return value;
}

[[nodiscard]] std::optional<std::vector<uint8_t>> parse_nonce(const std::string& text) {
    if (text.size() != 2 * security::kTier1EndpointNonceBytes) return std::nullopt;
    for (const char c : text) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return std::nullopt;
    }
    return crypto::from_hex(text);
}

}  // namespace

void Tier1ApiHandler::do_register_routes(httplib::Server& pub,
                                         [[maybe_unused]] httplib::Server& priv) {
    pub.Get("/api/tier1/authority", [this](const httplib::Request& req, httplib::Response& res) {
        if (!ctx_.authority_chain_page) {
            error_response(res, "the authority chain is not available", 404);
            return;
        }
        uint64_t have_epoch = 0;
        if (req.has_param("have_epoch")) {
            const auto parsed = parse_epoch(req.get_param_value("have_epoch"));
            if (!parsed) {
                error_response(res, "have_epoch must be a decimal epoch number");
                return;
            }
            have_epoch = *parsed;
        }
        const auto page = ctx_.authority_chain_page(have_epoch);
        if (page.empty()) {
            error_response(res, "no authority chain after this epoch", 404);
            return;
        }
        json_response(res, nlohmann::json{{"have_epoch", have_epoch},
                                          {"page", crypto::to_base64(page)}});
    });

    pub.Get("/api/tier1/proof", [this](const httplib::Request& req, httplib::Response& res) {
        const auto nonce = parse_nonce(req.get_param_value("nonce"));
        if (!nonce) {
            error_response(res, "nonce must be 64 hexadecimal characters");
            return;
        }
        const auto identity =
            ctx_.tier1_identity ? ctx_.tier1_identity() : std::optional<Tier1Identity>{};
        if (!identity) {
            // No redirect and no data: the client finds Tier 1 through the
            // verified membership, never through this answer.
            error_response(res, "this server is not a Tier 1 member", 421);
            return;
        }
        // The name the public certificate covers (see main: public_cert_fqdn).
        const std::string host =
            !ctx_.server_seip_fqdn.empty() ? ctx_.server_seip_fqdn : ctx_.server_fqdn;
        if (host.empty()) {
            error_response(res, "this server has no public name to prove", 503);
            return;
        }
        security::NetworkId network{};
        std::copy(identity->network_id.begin(), identity->network_id.end(), network.begin());
        const auto proof = security::sign_tier1_endpoint_proof(
            network, security::EpochId{identity->epoch}, host, ctx_.config.http_port, *nonce,
            ctx_.gossip.keypair());
        json_response(res, nlohmann::json{
                               {"node_id", crypto::to_base64(proof.node.bytes)},
                               {"epoch", proof.epoch.underlying()},
                               {"host", proof.host},
                               {"port", proof.port},
                               {"signature", crypto::to_base64(proof.signature)},
                           });
    });
}

}  // namespace nexus::api
