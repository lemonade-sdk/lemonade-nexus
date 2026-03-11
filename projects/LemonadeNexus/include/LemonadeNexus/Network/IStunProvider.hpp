#pragma once

#include <array>
#include <concepts>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <asio.hpp>

namespace nexus::network {

/// The result of a STUN Binding Request, including optional Ed25519 signature.
struct StunResponse {
    std::string             reflexive_address;
    uint16_t                reflexive_port{0};
    std::string             server_id;        // "central" or relay_id
    uint64_t                timestamp{0};
    std::array<uint8_t, 64> signature{};
    bool                    verified{false};
};

/// CRTP base for STUN providers.
/// Derived must implement:
///   StunResponse do_handle_binding_request(const asio::ip::udp::endpoint& client,
///                                          std::span<const uint8_t> request)
///   void do_sign_response(StunResponse& response)
///   bool do_verify_response(const StunResponse& response, std::string_view server_pubkey)
template <typename Derived>
class IStunProvider {
public:
    [[nodiscard]] StunResponse handle_binding_request(const asio::ip::udp::endpoint& client,
                                                       std::span<const uint8_t> request) {
        return self().do_handle_binding_request(client, request);
    }

    void sign_response(StunResponse& response) {
        self().do_sign_response(response);
    }

    [[nodiscard]] bool verify_response(const StunResponse& response,
                                        std::string_view server_pubkey) const {
        return self().do_verify_response(response, server_pubkey);
    }

protected:
    ~IStunProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IStunProvider implementation.
template <typename T>
concept StunProviderType = requires(T t, const T ct,
                                     const asio::ip::udp::endpoint& ep,
                                     std::span<const uint8_t> data,
                                     StunResponse& resp,
                                     const StunResponse& cresp,
                                     std::string_view sv) {
    { t.do_handle_binding_request(ep, data) } -> std::same_as<StunResponse>;
    { t.do_sign_response(resp) } -> std::same_as<void>;
    { ct.do_verify_response(cresp, sv) } -> std::same_as<bool>;
};

} // namespace nexus::network
