#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace nexus::api {

/// Holds back the dataplane peer removal of a device that removes its own
/// node over its own tunnel, until the answer has left the server.
///
/// A committed removal runs its cleanup inside the tree-op submission, so
/// the peer would go before the route handler writes the response, and the
/// response would die with the tunnel. A route that removes the caller's own
/// node calls hold() for the caller's principal before it submits the op and
/// release() once the response has been written or the connection failed.
/// While a principal is held, remove_or_defer() keeps the peer keys of its
/// nodes; the last release() removes them through `remove`. Principals are
/// compared as given: callers pass tree::canonical_principal. Thread-safe.
class PeerRemovalHold {
public:
    using Remove = std::function<void(const std::string& peer_key)>;

    explicit PeerRemovalHold(Remove remove) : remove_(std::move(remove)) {}

    /// Start one hold for `principal`. Holds for one principal are counted,
    /// so concurrent requests by the same key release only when all ended.
    void hold(const std::string& principal) {
        std::lock_guard lock(mutex_);
        ++held_[principal].count;
    }

    /// Remove the peer now, or keep it while `principal` is held.
    void remove_or_defer(const std::string& principal, const std::string& peer_key) {
        {
            std::lock_guard lock(mutex_);
            if (auto it = held_.find(principal); it != held_.end()) {
                it->second.peers.push_back(peer_key);
                return;
            }
        }
        remove_(peer_key);
    }

    /// End one hold for `principal`; the last one removes the kept peers.
    /// A principal that is not held is left alone.
    void release(const std::string& principal) {
        std::vector<std::string> peers;
        {
            std::lock_guard lock(mutex_);
            auto it = held_.find(principal);
            if (it == held_.end()) return;
            if (--it->second.count > 0) return;
            peers = std::move(it->second.peers);
            held_.erase(it);
        }
        for (const auto& key : peers) remove_(key);
    }

    /// Peers kept for `principal` at this moment.
    [[nodiscard]] std::size_t deferred(const std::string& principal) const {
        std::lock_guard lock(mutex_);
        const auto it = held_.find(principal);
        return it == held_.end() ? 0 : it->second.peers.size();
    }

private:
    struct Held {
        int count = 0;
        std::vector<std::string> peers;
    };
    mutable std::mutex mutex_;
    std::map<std::string, Held> held_;
    Remove remove_;
};

}  // namespace nexus::api
