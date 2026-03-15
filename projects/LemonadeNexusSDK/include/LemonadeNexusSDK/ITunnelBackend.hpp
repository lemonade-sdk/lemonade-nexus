#pragma once

#include <LemonadeNexusSDK/Types.hpp>
#include <LemonadeNexusSDK/Error.hpp>

#include <string>

namespace lnsdk {

/// CRTP interface for WireGuard tunnel backends.
///
/// Two implementations:
///   - WgQuickBackend   — shells out to wg-quick (requires WireGuard tools)
///   - BoringTunBackend — userspace via Cloudflare's BoringTun library
template <typename Derived>
class ITunnelBackend {
public:
    StatusResult bring_up(const WireGuardConfig& config) {
        return self().do_bring_up(config);
    }

    StatusResult bring_down() {
        return self().do_bring_down();
    }

    TunnelStatus status() const {
        return self().do_status();
    }

    StatusResult update_endpoint(const std::string& server_pubkey,
                                  const std::string& server_endpoint) {
        return self().do_update_endpoint(server_pubkey, server_endpoint);
    }

    bool is_active() const {
        return self().do_is_active();
    }

protected:
    ~ITunnelBackend() = default;

private:
    Derived& self() { return static_cast<Derived&>(*this); }
    const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept for tunnel backends.
template <typename T>
concept TunnelBackendType = requires(T t, const T ct,
                                      const WireGuardConfig& cfg,
                                      const std::string& s) {
    { t.bring_up(cfg) }         -> std::same_as<StatusResult>;
    { t.bring_down() }          -> std::same_as<StatusResult>;
    { ct.status() }             -> std::same_as<TunnelStatus>;
    { t.update_endpoint(s, s) } -> std::same_as<StatusResult>;
    { ct.is_active() }          -> std::same_as<bool>;
};

} // namespace lnsdk
