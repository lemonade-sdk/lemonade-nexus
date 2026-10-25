#pragma once

/// Whether this server holds the permission tree.
///
/// Only current Tier 1 members hold the tree. A Tier 2 server is a pure proxy
/// of end-to-end encrypted data and connections: it does not store,
/// replicate, read, write, redirect, or forward the tree, does not serve the
/// tree API, and does not terminate or vouch for a client tree session.
///
/// The role follows finalized epoch membership, never local configuration:
///   - Member: the server loads the tree and starts the tree services.
///   - NonMember: the server stops them and deletes its tree files. Finalized
///     state names the current epoch, so a server that is a non-member now
///     has seen its last epoch as a member end.
///   - Unknown (before Epoch 1 activates, or before the persisted epoch state
///     verifies): the server holds no tree role and serves no tree, but it
///     deletes nothing. Unknown is not evidence that the server left Tier 1.
///
/// The owner calls update() from one thread (the io thread). holds_tree() is
/// safe from any thread.

#include <atomic>
#include <cstdint>
#include <functional>
#include <string_view>

namespace nexus::tree {

/// What finalized epoch membership says about this server.
enum class MembershipView : uint8_t {
    Unknown,
    Member,
    NonMember,
};

enum class TreeRoleState : uint8_t {
    /// No finalized membership seen yet: no tree, nothing deleted.
    Pending,
    /// A current Tier 1 member: the tree is loaded and served.
    Tier1,
    /// Not a current Tier 1 member: no tree, and the tree files are deleted.
    Tier2,
};

[[nodiscard]] std::string_view tree_role_state_name(TreeRoleState state);

class TreeRole {
public:
    struct Hooks {
        /// Load the tree and start the tree services. Return false to stay
        /// out of Tier 1 and try again on the next update.
        std::function<bool()> enter;
        /// Stop the tree services and drop the tree from memory. Called
        /// after holds_tree() already reports false, so no new request passes
        /// the gate while the services stop. Called on every move to Tier2,
        /// also from Pending, so it must be safe when nothing was started.
        std::function<void()> leave;
        /// Delete the tree files (best-effort overwrite, then remove).
        std::function<void()> purge;
    };

    explicit TreeRole(Hooks hooks);

    TreeRole(const TreeRole&) = delete;
    TreeRole& operator=(const TreeRole&) = delete;

    /// Applies the latest membership view. `files_ready` is false while the
    /// data key is locked; the tree cannot load then, so the server does not
    /// enter Tier 1 until a later update. Leaving and deleting never wait for
    /// the data key. Call from one thread only.
    void update(MembershipView view, bool files_ready);

    /// True only in Tier1. Thread-safe.
    [[nodiscard]] bool holds_tree() const noexcept {
        return state_.load(std::memory_order_acquire) == TreeRoleState::Tier1;
    }

    [[nodiscard]] TreeRoleState state() const noexcept {
        return state_.load(std::memory_order_acquire);
    }

private:
    Hooks hooks_;
    std::atomic<TreeRoleState> state_{TreeRoleState::Pending};
};

}  // namespace nexus::tree
