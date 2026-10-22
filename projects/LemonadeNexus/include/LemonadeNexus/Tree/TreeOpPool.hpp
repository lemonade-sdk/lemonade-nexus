#pragma once

// The bounded pool of tree operations waiting for consensus (design A2), and
// the tickets an API request waits on.
//
// Ops are keyed by op id and kept in arrival order. The pool limits the total
// count, the count per submitting server (author), and the count per
// principal, so one server or one user cannot fill it. An op leaves the pool
// when it commits, when it is refused against committed state, or when it
// expires; each of those settles its ticket.
//
// Thread-safe: API threads add ops and wait on tickets while the consensus
// thread reads and settles them.

#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace nexus::tree {

/// Where a submitted op stands.
enum class TreeOpStatus : uint8_t {
    Pending,    ///< in a pool, not yet committed
    Committed,  ///< in a committed block; applied on this server
    Refused,    ///< refused; `verdict` says why
};

struct TreeOpOutcome {
    TreeOpStatus  status = TreeOpStatus::Pending;
    TreeOpVerdict verdict;
    /// Tree log height of the block that committed the op (Committed only).
    uint64_t      log_height = 0;
};

/// One submitted op's outcome, which a request can wait for. The first
/// settle() wins; later ones are ignored.
class TreeOpTicket {
public:
    explicit TreeOpTicket(std::string op_id) : op_id_(std::move(op_id)) {}

    [[nodiscard]] const std::string& op_id() const { return op_id_; }

    /// The outcome once settled, or Pending after `timeout`.
    [[nodiscard]] TreeOpOutcome wait_for(std::chrono::milliseconds timeout);

    [[nodiscard]] TreeOpOutcome current() const;

    /// Run `fn` once with the final outcome: now, on this thread, when already
    /// settled; otherwise on the thread that settles the ticket. `fn` must not
    /// call back into the pool.
    void on_settled(std::function<void(const TreeOpOutcome&)> fn);

    /// Record the final outcome (Committed or Refused) and wake waiters.
    void settle(TreeOpOutcome outcome);

private:
    const std::string op_id_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    TreeOpOutcome outcome_;
    std::vector<std::function<void(const TreeOpOutcome&)>> continuations_;
};

/// The answer to handing a sealed op to the consensus path: a refusal (the op
/// was not queued), or a ticket for the queued op.
struct TreeOpAdmission {
    TreeOpVerdict                 verdict;
    std::shared_ptr<TreeOpTicket> ticket;  ///< set exactly when verdict is ok
};

/// Hands a sealed op to the consensus path (TreeConsensus::submit). Must be
/// thread-safe; API threads call it.
using TreeOpGateway = std::function<TreeOpAdmission(TreeOp sealed)>;

struct TreeOpPoolLimits {
    std::size_t total = 1024;
    std::size_t per_author = 512;
    std::size_t per_principal = 32;
    /// Settled outcomes kept for status queries.
    std::size_t remembered_outcomes = 4096;
};

class TreeOpPool {
public:
    explicit TreeOpPool(TreeOpPoolLimits limits = {}) : limits_(limits) {}

    enum class Admit : uint8_t { Added, Duplicate, Full, AuthorLimit, PrincipalLimit };

    /// Add a sealed op. `ticket` may be null (an op another server forwarded).
    /// A duplicate op id keeps the existing entry.
    [[nodiscard]] Admit add(TreeOp op, std::shared_ptr<TreeOpTicket> ticket);

    /// Every pending op, in arrival order.
    [[nodiscard]] std::vector<TreeOp> pending() const;

    [[nodiscard]] bool contains(const std::string& op_id) const;
    [[nodiscard]] std::size_t size() const;

    /// Remove the op and settle its ticket with `outcome`, and remember the
    /// outcome. An unknown op id is remembered only.
    void settle(const std::string& op_id, const TreeOpOutcome& outcome);

    /// The pending or remembered outcome of an op id, or nullopt when this
    /// pool never saw it (or forgot it).
    [[nodiscard]] std::optional<TreeOpOutcome> status(const std::string& op_id) const;

private:
    struct Entry {
        TreeOp op;
        std::shared_ptr<TreeOpTicket> ticket;
        uint64_t sequence = 0;
    };

    void remember_locked(const std::string& op_id, const TreeOpOutcome& outcome);

    const TreeOpPoolLimits limits_;
    mutable std::mutex mutex_;
    std::map<std::string, Entry> entries_;
    std::map<std::string, std::size_t> per_author_;
    std::map<std::string, std::size_t> per_principal_;
    uint64_t next_sequence_ = 0;
    std::map<std::string, TreeOpOutcome> outcomes_;
    std::deque<std::string> outcome_order_;
};

}  // namespace nexus::tree
