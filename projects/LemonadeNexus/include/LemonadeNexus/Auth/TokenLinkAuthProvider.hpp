#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>

#include <string_view>
#include <chrono>

namespace nexus::auth {

/// Discord/WhatsApp-style token-link authentication provider.
/// No username/password — generates a short-lived invite/link token that the user
/// confirms out-of-band (e.g. click a link, scan a QR code, accept on another device).
class TokenLinkAuthProvider : public IAuthProvider<TokenLinkAuthProvider> {
    friend class IAuthProvider<TokenLinkAuthProvider>;
public:
    TokenLinkAuthProvider() = default;

    [[nodiscard]] AuthResult do_authenticate(const nlohmann::json& credentials);
    [[nodiscard]] static constexpr std::string_view auth_provider_name() { return "token-link"; }

    /// Generate a pending link token for out-of-band confirmation.
    [[nodiscard]] std::string generate_link_token();

private:
    bool verify_link_token(std::string_view token);
    std::chrono::seconds token_ttl_{300}; // 5 minute expiry
};

} // namespace nexus::auth
