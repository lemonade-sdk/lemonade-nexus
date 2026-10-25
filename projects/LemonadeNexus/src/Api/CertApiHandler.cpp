#include <LemonadeNexus/Api/CertApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace nexus::api {

using nexus::auth::require_auth;
using nexus::auth::SessionClaims;

namespace {

constexpr std::string_view kScopeDevice        = "device";
constexpr std::string_view kScopeGroupLoopback = "group_loopback";

[[nodiscard]] std::string lowercase(std::string_view in) {
    std::string out(in);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/// True when no endpoint of a key other than `caller_pk` uses `hostname`
/// (compared without case, like DNS). A shared hostname would hand one
/// certificate key to two owners.
[[nodiscard]] bool hostname_unique_to(const tree::PermissionTreeService& tree,
                                      std::string_view hostname,
                                      std::string_view caller_pk) {
    const auto wanted = lowercase(hostname);
    const auto caller = tree::canonical_principal(caller_pk);
    for (const auto& node : tree.get_nodes_by_type(tree::NodeType::Endpoint)) {
        if (lowercase(node.hostname) != wanted) continue;
        if (tree::canonical_principal(node.mgmt_pubkey) != caller) return false;
    }
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Renewal monitor support
// ---------------------------------------------------------------------------

std::vector<std::string> device_certificates_due(acme::AcmeService& acme,
                                                 const tree::PermissionTreeService& tree,
                                                 std::string_view base_domain,
                                                 uint64_t now) {
    std::vector<std::string> due;
    if (base_domain.empty()) return due;
    const auto base       = lowercase(base_domain);
    const auto capi_tail  = ".capi." + base;
    const auto lo_tail    = ".lo." + base;

    for (const auto& domain : acme.stored_certificate_domains()) {
        const auto name = lowercase(domain);
        bool wanted = false;
        if (name.size() > capi_tail.size() && name.ends_with(capi_tail)) {
            const auto hostname = domain.substr(0, domain.size() - capi_tail.size());
            bool exists = false;
            bool single_owner = true;
            std::string owner;
            for (const auto& node : tree.get_nodes_by_type(tree::NodeType::Endpoint)) {
                if (lowercase(node.hostname) != lowercase(hostname)) continue;
                const auto pk = tree::canonical_principal(node.mgmt_pubkey);
                if (exists && pk != owner) single_owner = false;
                exists = true;
                owner = pk;
            }
            wanted = exists && single_owner;
        } else if (name.starts_with("*.") && name.size() > 2 + lo_tail.size() &&
                   name.ends_with(lo_tail)) {
            const auto label = name.substr(2, name.size() - 2 - lo_tail.size());
            wanted = network::groups_with_loopback_label(tree, label).size() == 1;
        }
        if (!wanted) continue;

        const auto bundle = acme.get_certificate(domain);
        if (!bundle) continue;  // vault locked or unreadable: try again later
        if (acme::certificate_renewal_due(*bundle, now)) due.push_back(domain);
    }
    return due;
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void CertApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                        httplib::Server& priv) {
    // /api/tls/reload and /api/tls/renew are intentionally not routed: no
    // accepted authorization rule covers forcing a TLS reload or triggering
    // certificate renewal (a valid session alone is insufficient, and no
    // owner/admin/permission model for server TLS operations exists). Renewal
    // happens only through the local scheduled ACME monitor, which renews
    // and hot-reloads the listener directly.

    // GET /api/certs/{domain} — get certificate status for a domain
    priv.Get(R"(/api/certs/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto domain = req.matches[1].str();
        auto bundle = ctx_.acme.get_certificate(domain);
        if (!bundle) {
            error_response(res, "certificate not found", 404);
            return;
        }
        network::CertStatusResponse resp{
            .domain     = domain,
            .has_cert   = true,
            .expires_at = bundle->expires_at,
        };
        nlohmann::json j = resp;
        json_response(res, j);
    }));

    // POST /api/certs/issue — issue certificate for client (borrowed license)
    priv.Post("/api/certs/issue", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        if (!body_opt->is_object()) {
            error_response(res, "request body must be a JSON object");
            return;
        }
        for (const char* field : {"hostname", "client_pubkey", "scope"}) {
            if (body_opt->contains(field) && !(*body_opt)[field].is_string()) {
                error_response(res, std::string(field) + " must be a string");
                return;
            }
        }

        auto cert_req = body_opt->get<network::CertIssueRequest>();
        const std::string scope = cert_req.scope.empty() ? std::string(kScopeDevice)
                                                         : cert_req.scope;

        if (cert_req.client_pubkey.empty()) {
            error_response(res, "client_pubkey required");
            return;
        }

        // Normalize the JWT pubkey to match tree format
        const auto caller_pk = normalize_pubkey(claims.pubkey);
        const auto node_id = claims.node_id.empty() ? claims.user_id : claims.node_id;

        std::string fqdn;
        if (scope == kScopeDevice) {
            if (cert_req.hostname.empty()) {
                error_response(res, "hostname and client_pubkey required");
                return;
            }

            for (char c : cert_req.hostname) {
                if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
                    error_response(res, "invalid hostname characters");
                    return;
                }
            }

            // Validate hostname ownership: the requesting user must own a node
            // with this hostname. Prevents users from requesting certs for
            // "root" or other users' hostnames.
            bool owns_hostname = false;
            if (!node_id.empty()) {
                // Check the user's node and customer group
                for (const auto& check_id : {node_id, std::string("customer-") + node_id}) {
                    auto node = ctx_.tree.get_node(check_id);
                    if (node && node->hostname == cert_req.hostname &&
                        tree::canonical_principal(node->mgmt_pubkey) ==
                            tree::canonical_principal(caller_pk)) {
                        owns_hostname = true;
                        break;
                    }
                }
            }

            if (!owns_hostname) {
                error_response(res, "hostname ownership required", 403);
                return;
            }

            // Hostnames are not unique in the tree. Refuse a hostname that an
            // endpoint of another key also uses: both owners would otherwise
            // receive the same certificate key.
            if (!hostname_unique_to(ctx_.tree, cert_req.hostname, caller_pk)) {
                error_response(res, "hostname is also used by another owner", 409);
                return;
            }

            fqdn = cert_req.hostname + ".capi." + ctx_.config.dns_base_domain;
        } else if (scope == kScopeGroupLoopback) {
            // The bundle carries the group's shared key: deliver it only to
            // the member's own identity.
            if (tree::canonical_principal(normalize_pubkey(cert_req.client_pubkey)) !=
                tree::canonical_principal(caller_pk)) {
                error_response(res, "client_pubkey must be the caller's key", 403);
                return;
            }

            // Membership follows the tree: the caller's node must be a joined
            // endpoint with the caller's key, placed in a Customer group.
            std::optional<tree::TreeNode> group;
            if (!node_id.empty()) {
                auto endpoint = ctx_.tree.get_node(node_id);
                if (endpoint && endpoint->type == tree::NodeType::Endpoint &&
                    !endpoint->tunnel_ip.empty() &&
                    tree::canonical_principal(endpoint->mgmt_pubkey) ==
                        tree::canonical_principal(caller_pk)) {
                    auto parent = ctx_.tree.get_node(endpoint->parent_id);
                    if (parent && parent->type == tree::NodeType::Customer) {
                        group = std::move(parent);
                    }
                }
            }
            if (!group) {
                error_response(res, "group membership required", 403);
                return;
            }

            const auto label = network::group_loopback_label(group->id);
            if (network::groups_with_loopback_label(ctx_.tree, label).size() != 1) {
                spdlog::warn("[CertIssue] group loopback label {} is not unique; refused", label);
                error_response(res, "group label collision", 409);
                return;
            }
            fqdn = network::group_loopback_wildcard(group->id, ctx_.config.dns_base_domain);
            if (fqdn.empty()) {
                error_response(res, "DNS base domain not configured", 500);
                return;
            }
        } else {
            error_response(res, "unknown certificate scope");
            return;
        }

        std::optional<acme::CertBundle> existing;
        {
            std::lock_guard issue_lock(issue_mutex_);
            existing = ctx_.acme.get_certificate(fqdn);
            const auto now = epoch_seconds();
            if (!existing || acme::certificate_renewal_due(*existing, now)) {
                spdlog::info("[CertIssue] requesting ACME cert for {} ({})", fqdn,
                             existing ? "renewal due" : "none stored");
                auto result = ctx_.acme.request_certificate(fqdn);
                if (result.success) {
                    existing = ctx_.acme.get_certificate(fqdn);
                    if (!existing) {
                        error_response(res, "certificate issued but not found in storage", 500);
                        return;
                    }
                } else if (!existing || now >= existing->expires_at) {
                    error_response(res, "ACME certificate request failed", 502);
                    return;
                } else {
                    // The stored certificate is still valid. Serve it; the
                    // client checks the expiry and asks again later.
                    spdlog::warn("[CertIssue] renewal of {} failed; serving the stored "
                                 "certificate until it expires", fqdn);
                }
            }
        }

        std::string pk_data = cert_req.client_pubkey;
        if (pk_data.starts_with("ed25519:")) {
            pk_data = pk_data.substr(8);
        }
        auto pk_bytes = crypto::from_base64(pk_data);
        if (pk_bytes.size() != crypto::kEd25519PublicKeySize) {
            error_response(res, "invalid client_pubkey size");
            return;
        }
        crypto::Ed25519PublicKey client_ed_pk{};
        std::memcpy(client_ed_pk.data(), pk_bytes.data(), pk_bytes.size());

        auto client_x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(client_ed_pk);
        auto ephemeral = ctx_.crypto.x25519_keygen();

        auto shared_secret = ctx_.crypto.x25519_dh(ephemeral.private_key, client_x_pk);

        const std::string info_str = "lemonade-nexus-cert-issue";
        auto enc_key = ctx_.crypto.hkdf_sha256(shared_secret, {},
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()), 32);
        crypto::AeadKey aes_key{};
        std::memcpy(aes_key.data(), enc_key.data(), std::min(enc_key.size(), aes_key.size()));

        auto privkey_bytes = std::vector<uint8_t>(
            existing->privkey_pem.begin(), existing->privkey_pem.end());
        // Bound to the request it answers: this client and this domain. A
        // bundle cannot be replayed at another client or another name.
        const auto aad = crypto::aead_aad(
            crypto::aead_purpose::kCertBundle,
            {std::span<const uint8_t>(client_ed_pk.data(), client_ed_pk.size()),
             std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(fqdn.data()),
                                      fqdn.size())});
        auto encrypted =
            ctx_.crypto.aead_encrypt(aes_key, privkey_bytes, std::span<const uint8_t>{aad});

        network::CertIssueResponse resp{
            .domain            = fqdn,
            .fullchain_pem     = existing->fullchain_pem,
            .encrypted_privkey = crypto::to_base64(encrypted.ciphertext),
            .crypto_version    = encrypted.version,
            .nonce             = crypto::to_base64(encrypted.nonce),
            .ephemeral_pubkey  = crypto::to_base64(ephemeral.public_key),
            .expires_at        = existing->expires_at,
        };
        spdlog::info("[CertIssue] issued cert for {} to client {}", fqdn, cert_req.client_pubkey.substr(0, 16));
        nlohmann::json j = resp;
        json_response(res, j);
    }));
}

} // namespace nexus::api
