#pragma once

/// Keeps the server dataplane's forwarding policy in step with the permission
/// tree.
///
/// The server's userspace dataplane forwards packets between its peers. A
/// client's server peer covers the whole tunnel plane, so without a policy
/// any joined endpoint could reach any other endpoint through the server.
/// The policy allows forwarding from endpoint A to endpoint B only when A's
/// management key may connect to B under the rule of
/// PermissionTreeService::resolve_authorized: B is inside A's parent-group
/// subtree, and A's key holds ConnectPrivate or ConnectShared on B itself
/// (`admin` includes both). Replies from B to A pass under the reply rule of
/// ForwardPolicy. Relays and addresses outside the tunnel plane keep the open
/// rule.
///
/// The policy is rebuilt off the packet path and swapped into the dataplane
/// atomically, so a forwarded packet costs one hash lookup.

#include <LemonadeNexus/Boringtun/IpRouter.hpp>
#include <LemonadeNexus/Boringtun/UserspaceDataplane.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

namespace nexus::boringtun {

/// Build the forwarding policy for the tunnel plane `governed` from the current
/// tree. Uses only the public PermissionTreeService API. An endpoint or relay
/// whose tunnel_ip is not a single address inside `governed` is left out, so
/// traffic to or from it is dropped. Thread-safe with respect to the tree.
[[nodiscard]] std::shared_ptr<const ForwardPolicy> build_forward_policy(
    const tree::PermissionTreeService& tree, const Cidr& governed);

class ForwardAuthorizer {
public:
    /// `tree` and `dataplane` must outlive this object. `poll` is how often the
    /// background thread checks the tree for a change.
    ForwardAuthorizer(const tree::PermissionTreeService& tree, UserspaceDataplane& dataplane,
                      Cidr governed,
                      std::chrono::milliseconds poll = std::chrono::milliseconds(1000));
    ~ForwardAuthorizer();

    ForwardAuthorizer(const ForwardAuthorizer&)            = delete;
    ForwardAuthorizer& operator=(const ForwardAuthorizer&) = delete;

    /// Install a policy built from the current tree, then start the thread that
    /// rebuilds it when the tree hash changes. Call it before the dataplane
    /// accepts peers, so no packet is forwarded without a policy.
    void start();

    /// Stop the background thread. The last policy stays installed.
    void stop();

    /// Rebuild and install the policy now when the tree changed since the last
    /// build, or always when `force` is true. Returns true when it installed a
    /// policy. Thread-safe.
    bool refresh(bool force = false);

private:
    void run();

    const tree::PermissionTreeService& tree_;
    UserspaceDataplane&                dataplane_;
    Cidr                               governed_;
    std::chrono::milliseconds          poll_;

    std::mutex                     refresh_mtx_;  ///< serializes builds
    std::optional<crypto::Hash256> built_hash_;

    std::mutex              wait_mtx_;
    std::condition_variable wait_cv_;
    bool                    stopping_{false};
    std::thread             thread_;
};

} // namespace nexus::boringtun
