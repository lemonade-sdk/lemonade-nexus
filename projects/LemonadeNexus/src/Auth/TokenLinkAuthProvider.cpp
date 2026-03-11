#include <LemonadeNexus/Auth/TokenLinkAuthProvider.hpp>

#include <spdlog/spdlog.h>

#include <random>
#include <sstream>
#include <iomanip>

namespace nexus::auth {

AuthResult TokenLinkAuthProvider::do_authenticate(const nlohmann::json& credentials) {
    const auto token = credentials.value("link_token", std::string{});

    if (token.empty()) {
        return AuthResult{.authenticated = false, .error_message = "Missing link token"};
    }

    if (!verify_link_token(token)) {
        return AuthResult{.authenticated = false, .error_message = "Invalid or expired link token"};
    }

    // TODO: lookup user_id associated with this confirmed token from PostgreSQL
    return AuthResult{
        .authenticated = true,
        .user_id = "token_user",
        .session_token = "TODO_JWT_TOKEN",
    };
}

std::string TokenLinkAuthProvider::generate_link_token() {
    // Generate a cryptographically-random hex token
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << dist(gen)
        << std::setw(16) << dist(gen);

    // TODO: store token in PostgreSQL with expiry = now + token_ttl_
    spdlog::debug("Generated link token (TTL={}s)", token_ttl_.count());
    return oss.str();
}

bool TokenLinkAuthProvider::verify_link_token(std::string_view token) {
    // TODO: lookup token in PostgreSQL, check expiry and confirmation status
    (void)token;
    return false;
}

} // namespace nexus::auth
