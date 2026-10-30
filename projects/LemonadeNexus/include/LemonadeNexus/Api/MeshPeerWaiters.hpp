#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace nexus::api {

/// Most GET /api/mesh/peers long-polls (wait_revision) one server holds at
/// once. Every held request occupies one worker thread of the HTTP server
/// (cpp-httplib serves each connection on one pool thread), so the private
/// API pool is sized above this cap (kPrivateApiWorkerThreads). A request
/// beyond the cap gets 429 and the device keeps the heartbeat
/// peers_revision as its signal.
inline constexpr std::size_t kMeshPeerWaitersMax = 256;

/// Most long-polls one device (the JWT subject) holds at once. Two allow a
/// new request while the server has not yet seen that the previous one's
/// connection closed.
inline constexpr std::size_t kMeshPeerWaitersPerCaller = 2;

/// Worker threads of the HTTP server that serves the private routes: room
/// for kMeshPeerWaitersMax held long-polls plus 64 threads for every other
/// private request. Idle stacks cost address space, not memory.
inline constexpr std::size_t kPrivateApiWorkerThreads = kMeshPeerWaitersMax + 64;

/// Longest wait a long-poll may ask for (`timeout`), and the wait when it
/// names none, in seconds. The SDK asks for kMeshPeerWaitDefaultSec.
inline constexpr uint32_t kMeshPeerWaitMaxSec     = 30;
inline constexpr uint32_t kMeshPeerWaitDefaultSec = 25;

/// Longest a held long-poll sleeps before it computes its revision again, in
/// milliseconds. A peer's live session state follows handshake ages, which
/// change without a notify(), so a waiter also checks on this period.
inline constexpr int64_t kMeshPeerRecheckMs = 5000;

/// Change notification and admission for the peer list long-polls of one
/// server.
///
/// Anything that can change a peer list or its peers_revision calls notify():
/// an applied tree change (every Tier 1 server applies the same committed
/// log, so each wakes its own waiters), a changed LAN endpoint list or live
/// session of a device, and runtime state from another Tier 1 server. A
/// waiter then recomputes its own peers_revision and answers only when it
/// differs from the one it waits on, so a change outside its peer set does
/// not answer it. notify() carries no data and decides nothing about access.
///
/// Thread-safe.
class MeshPeerWaiters {
public:
    MeshPeerWaiters() = default;
    MeshPeerWaiters(const MeshPeerWaiters&)            = delete;
    MeshPeerWaiters& operator=(const MeshPeerWaiters&) = delete;

    /// Why try_admit() refused.
    enum class Refusal { None, ServerFull, CallerFull, ShuttingDown };

    /// One admitted waiter. Destroying it frees its place.
    class Slot {
    public:
        Slot(const Slot&)            = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot();

    private:
        friend class MeshPeerWaiters;
        Slot(MeshPeerWaiters& owner, std::string caller)
            : owner_(owner), caller_(std::move(caller)) {}
        MeshPeerWaiters& owner_;
        std::string      caller_;
    };

    /// Admit one waiter for `caller` (the authenticated device). Returns
    /// nullptr and sets `why` when the server holds kMeshPeerWaitersMax
    /// waiters, `caller` holds kMeshPeerWaitersPerCaller, or shutdown() ran.
    /// The slot must not outlive this object.
    [[nodiscard]] std::unique_ptr<Slot> try_admit(const std::string& caller, Refusal& why);

    /// A counter that notify() increments. Read it before computing the
    /// revision a wait compares with, so a change in between is not lost.
    [[nodiscard]] uint64_t generation() const;

    /// Wake every waiter.
    void notify();

    /// Block until generation() differs from `seen`, shutdown() runs, or
    /// `max_wait` passes. Returns generation().
    uint64_t wait(uint64_t seen, std::chrono::milliseconds max_wait) const;

    /// Make every wait return at once and refuse new waiters (server
    /// shutdown). Permanent.
    void shutdown();

    /// True after shutdown().
    [[nodiscard]] bool shutting_down() const;

    /// Waiters admitted now.
    [[nodiscard]] std::size_t waiting() const;

    /// Replace the caps (tests only; production uses the constants).
    void set_limits_for_testing(std::size_t max_waiters, std::size_t per_caller);

private:
    void release(const std::string& caller);

    mutable std::mutex                           mtx_;
    mutable std::condition_variable              cv_;
    uint64_t                                     generation_{0};
    bool                                         shutdown_{false};
    std::size_t                                  waiting_{0};
    std::unordered_map<std::string, std::size_t> per_caller_;
    std::size_t                                  max_waiters_{kMeshPeerWaitersMax};
    std::size_t                                  max_per_caller_{kMeshPeerWaitersPerCaller};
};

} // namespace nexus::api
