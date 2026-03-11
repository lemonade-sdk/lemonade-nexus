#pragma once

#include <LemonadeNexus/Core/IService.hpp>

#include <nlohmann/json.hpp>

#include <expected>
#include <string>
#include <string_view>

namespace nexus::auth {

/// Result of an authentication attempt.
struct AuthResult {
    bool        authenticated{false};
    std::string user_id;
    std::string session_token;
    std::string error_message;
};

/// CRTP base for authentication providers.
/// Derived must implement:
///   AuthResult do_authenticate(const nlohmann::json& credentials)
///   std::string_view provider_name() const
template <typename Derived>
class IAuthProvider {
public:
    [[nodiscard]] AuthResult authenticate(const nlohmann::json& credentials) {
        return self().do_authenticate(credentials);
    }

    [[nodiscard]] std::string_view provider_name() const {
        return self().auth_provider_name();
    }

protected:
    ~IAuthProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid auth provider
template <typename T>
concept AuthProviderType = requires(T t, const nlohmann::json& creds) {
    { t.do_authenticate(creds) } -> std::same_as<AuthResult>;
    { t.auth_provider_name() } -> std::convertible_to<std::string_view>;
};

} // namespace nexus::auth
