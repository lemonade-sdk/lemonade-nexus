#include <LemonadeNexus/Auth/PasswordAuthProvider.hpp>

#include <spdlog/spdlog.h>

namespace nexus::auth {

AuthResult PasswordAuthProvider::do_authenticate(const nlohmann::json& credentials) {
    const auto username  = credentials.value("username", std::string{});
    const auto password  = credentials.value("password", std::string{});
    const auto totp_code = credentials.value("totp_code", std::string{});

    if (username.empty() || password.empty()) {
        return AuthResult{.authenticated = false, .error_message = "Missing username or password"};
    }

    if (!verify_password(username, password)) {
        return AuthResult{.authenticated = false, .error_message = "Invalid credentials"};
    }

    if (!totp_code.empty() && !verify_2fa(username, totp_code)) {
        return AuthResult{.authenticated = false, .error_message = "Invalid 2FA code"};
    }

    // TODO: generate JWT session token
    return AuthResult{
        .authenticated = true,
        .user_id = username,
        .session_token = "TODO_JWT_TOKEN",
    };
}

bool PasswordAuthProvider::verify_password(std::string_view user, std::string_view password) {
    // TODO: lookup hashed password from PostgreSQL and verify with argon2/bcrypt
    (void)user;
    (void)password;
    return false;
}

bool PasswordAuthProvider::verify_2fa(std::string_view user, std::string_view totp_code) {
    // TODO: TOTP verification
    (void)user;
    (void)totp_code;
    return false;
}

} // namespace nexus::auth
