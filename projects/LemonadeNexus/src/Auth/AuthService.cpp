#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <spdlog/spdlog.h>

namespace nexus::auth {

AuthService::AuthService(storage::FileStorageService& storage,
                         crypto::SodiumCryptoService& crypto,
                         std::string rp_id,
                         std::string jwt_secret)
    : password_provider_{}
    , passkey_provider_{storage, crypto, std::move(rp_id), jwt_secret}
    , token_link_provider_{}
    , ed25519_provider_{storage, crypto, jwt_secret}
    , jwt_secret_{std::move(jwt_secret)}
{
}

AuthResult AuthService::authenticate(const nlohmann::json& request) {
    const auto method = request.value("method", std::string{});

    if (method == "password") {
        return password_provider_.authenticate(request);
    } else if (method == "passkey" || method == "fido2") {
        return passkey_provider_.authenticate(request);
    } else if (method == "token-link") {
        return token_link_provider_.authenticate(request);
    } else if (method == "ed25519") {
        return ed25519_provider_.authenticate(request);
    }

    return AuthResult{.authenticated = false, .error_message = "Unknown auth method: " + method};
}

AuthResult AuthService::register_passkey(const nlohmann::json& registration) {
    return passkey_provider_.do_register(registration);
}

nlohmann::json AuthService::issue_ed25519_challenge(const std::string& pubkey_b64) {
    return ed25519_provider_.issue_challenge(pubkey_b64);
}

AuthResult AuthService::register_ed25519(const nlohmann::json& registration) {
    auto pubkey = registration.value("pubkey", std::string{});
    auto user_id = registration.value("user_id", std::string{});
    if (pubkey.empty()) {
        return AuthResult{.authenticated = false, .error_message = "Missing pubkey"};
    }
    return ed25519_provider_.register_pubkey(pubkey, user_id);
}

bool AuthService::validate_session(std::string_view token) {
    try {
        auto decoded = jwt::decode(std::string(token));
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{jwt_secret_})
            .with_issuer("lemonade-nexus");
        verifier.verify(decoded);
        return true;
    } catch (const std::exception& e) {
        spdlog::debug("[AuthService] JWT validation failed: {}", e.what());
        return false;
    }
}

std::optional<SessionClaims> AuthService::validate_session_claims(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);

        // Verify signature, issuer, and expiry
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{jwt_secret_})
            .with_issuer("lemonade-nexus");
        verifier.verify(decoded);

        SessionClaims claims;

        // Standard claims
        if (decoded.has_subject()) {
            claims.user_id = decoded.get_subject();
        }

        if (decoded.has_issued_at()) {
            claims.issued_at = std::chrono::duration_cast<std::chrono::seconds>(
                decoded.get_issued_at().time_since_epoch()).count();
        }

        if (decoded.has_expires_at()) {
            claims.expires_at = std::chrono::duration_cast<std::chrono::seconds>(
                decoded.get_expires_at().time_since_epoch()).count();
        }

        // Custom claims (set by authentication providers if present)
        if (decoded.has_payload_claim("node_id")) {
            claims.node_id = decoded.get_payload_claim("node_id").as_string();
        }

        if (decoded.has_payload_claim("pubkey")) {
            claims.pubkey = decoded.get_payload_claim("pubkey").as_string();
        }

        if (decoded.has_payload_claim("permissions")) {
            auto perms_claim = decoded.get_payload_claim("permissions");
            auto perms_json = perms_claim.to_json();
            if (perms_json.is_array()) {
                for (const auto& p : perms_json) {
                    if (p.is_string()) {
                        claims.permissions.push_back(p.get<std::string>());
                    }
                }
            }
        }

        spdlog::debug("[AuthService] Validated JWT for user '{}' (expires_at={})",
                       claims.user_id, claims.expires_at);
        return claims;

    } catch (const std::exception& e) {
        spdlog::debug("[AuthService] JWT claims validation failed: {}", e.what());
        return std::nullopt;
    }
}

void AuthService::on_start() {
    spdlog::info("AuthService started — providers: ed25519 (primary), passkey/fido2 (backup), password+2fa, token-link");
}

void AuthService::on_stop() {
    spdlog::info("AuthService stopped");
}

} // namespace nexus::auth
