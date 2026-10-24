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
/// ForwardPolicy. Addresses outside the tunnel plane keep the open rule, and so
/// does a Relay node whose management key administers the tree root.
///
/// A node's tunnel_ip is a claim, not a binding. A tunnel-plane address maps
/// to a node only when the dataplane peer that holds the address (installed
/// by the server at join) has that node's mesh key. A node that names another
/// device's address therefore never gets that address into the policy.
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
#include <unordered_map>

namespace nexus::boringtun {

/// Primary address (host order) -> peer public key, as
/// UserspaceDataplane::primary_address_peers reports it.
using PlanePeers = std::unordered_map<uint32_t, std::string>;

/// Build the forwarding policy for the tunnel plane `governed` from the current
/// tree and the dataplane's peers. Uses only the public PermissionTreeService
/// API. An endpoint or relay is left out, so traffic to or from its address is
/// dropped, when its tunnel_ip is not a single address inside `governed`, when
/// no peer in `peers` holds that address, when the peer's key is not the
/// node's normalized mesh key, or when another node also matches that address
/// and key. A relay whose management key is not a root admin gets no open
/// rule. Thread-safe
/// with respect to the tree.
[[nodiscard]] std::shared_ptr<const ForwardPolicy> build_forward_policy(
    const tree::PermissionTreeService& tree, const Cidr& governed, const PlanePeers& peers);

/// A policy that forwards nothing between peers: every address is inside its
/// governed range, and it allows no pair and no open address. Install it when
/// the tunnel plane is unknown, so forwarding fails closed.
[[nodiscard]] std::shared_ptr<const ForwardPolicy> deny_forward_policy();

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
    /// rebuilds it when the tree hash or the dataplane's routes change. Call it before the dataplane
    /// accepts peers, so no packet is forwarded without a policy.
    void start();

    /// Stop the background thread. The last policy stays installed.
    void stop();

    /// Rebuild and install the policy now when the tree or the dataplane's
    /// routes changed since the last build, or always when `force` is true. Returns true when it installed a
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
    uint64_t                       built_generation_{0};

    std::mutex              wait_mtx_;
    std::condition_variable wait_cv_;
    bool                    stopping_{false};
    std::thread             thread_;
};

} // namespace nexus::boringtun
