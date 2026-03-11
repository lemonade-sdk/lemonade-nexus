#pragma once

#include <LemonadeNexus/Auth/AuthService.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace nexus::auth {

/// Claims extracted from a validated JWT session token.
struct SessionClaims {
    std::string              user_id;
    std::string              node_id;
    std::string              pubkey;
    std::vector<std::string> permissions;
    int64_t                  issued_at{0};
    int64_t                  expires_at{0};
};

/// Handler type for endpoints that require authentication.
/// Receives the validated claims in addition to the standard request/response.
using AuthenticatedHandler = std::function<void(
    const httplib::Request&,
    httplib::Response&,
    const SessionClaims&)>;

/// Create a cpp-httplib handler that enforces Bearer token authentication.
///
/// Extracts "Authorization: Bearer <token>" from request headers, validates
/// the JWT via AuthService, extracts claims, and passes them to the inner
/// handler.  On failure, responds with 401 (missing/invalid token) or 403
/// (expired/forbidden) and short-circuits.
///
/// Usage:
///   server.Get("/api/protected", require_auth(auth_service, [&](auto& req, auto& res, auto& claims) {
///       // `claims` is guaranteed valid here
///   }));
inline httplib::Server::Handler require_auth(AuthService& auth,
                                              AuthenticatedHandler handler) {
    return [&auth, handler = std::move(handler)](
               const httplib::Request& req, httplib::Response& res) {
        // --- Extract the Authorization header ---
        auto it = req.headers.find("Authorization");
        if (it == req.headers.end()) {
            spdlog::debug("[AuthMiddleware] Missing Authorization header for {}",
                          req.path);
            res.status = 401;
            res.set_content(
                R"({"error":"authorization required","detail":"missing Authorization header"})",
                "application/json");
            return;
        }

        const auto& auth_header = it->second;

        // Must be "Bearer <token>"
        constexpr std::string_view bearer_prefix = "Bearer ";
        if (auth_header.size() <= bearer_prefix.size() ||
            auth_header.compare(0, bearer_prefix.size(), bearer_prefix) != 0) {
            spdlog::debug("[AuthMiddleware] Malformed Authorization header for {}",
                          req.path);
            res.status = 401;
            res.set_content(
                R"({"error":"authorization required","detail":"expected Bearer token"})",
                "application/json");
            return;
        }

        std::string token = auth_header.substr(bearer_prefix.size());

        // --- Validate and extract claims ---
        auto claims = auth.validate_session_claims(token);
        if (!claims) {
            spdlog::debug("[AuthMiddleware] Invalid/expired token for {}", req.path);
            res.status = 401;
            res.set_content(
                R"({"error":"unauthorized","detail":"invalid or expired token"})",
                "application/json");
            return;
        }

        // --- Delegate to the authenticated handler ---
        handler(req, res, *claims);
    };
}

} // namespace nexus::auth
