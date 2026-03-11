#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>

#include <string_view>

namespace nexus::auth {

/// Username/Password + 2FA authentication provider.
/// Authenticates via user/pw and validates a TOTP or similar second factor.
class PasswordAuthProvider : public IAuthProvider<PasswordAuthProvider> {
    friend class IAuthProvider<PasswordAuthProvider>;
public:
    PasswordAuthProvider() = default;

    [[nodiscard]] AuthResult do_authenticate(const nlohmann::json& credentials);
    [[nodiscard]] static constexpr std::string_view auth_provider_name() { return "password+2fa"; }

private:
    bool verify_password(std::string_view user, std::string_view password);
    bool verify_2fa(std::string_view user, std::string_view totp_code);
};

} // namespace nexus::auth
