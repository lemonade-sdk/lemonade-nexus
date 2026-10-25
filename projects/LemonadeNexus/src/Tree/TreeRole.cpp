#include <LemonadeNexus/Tree/TreeRole.hpp>

#include <spdlog/spdlog.h>

namespace nexus::tree {

std::string_view tree_role_state_name(TreeRoleState state) {
    switch (state) {
        case TreeRoleState::Pending: return "pending";
        case TreeRoleState::Tier1: return "tier1";
        case TreeRoleState::Tier2: return "tier2";
    }
    return "unknown";
}

TreeRole::TreeRole(Hooks hooks) : hooks_(std::move(hooks)) {}

void TreeRole::update(MembershipView view, bool files_ready) {
    const TreeRoleState current = state_.load(std::memory_order_acquire);
    switch (view) {
        case MembershipView::Member: {
            if (current == TreeRoleState::Tier1 || !files_ready) return;
            // The gate opens only after the tree is loaded.
            if (hooks_.enter && hooks_.enter()) {
                state_.store(TreeRoleState::Tier1, std::memory_order_release);
                spdlog::info("[tree-role] this server is a Tier 1 member: it now holds and "
                             "serves the tree");
            }
            return;
        }
        case MembershipView::NonMember: {
            if (current == TreeRoleState::Tier2) return;
            // Close the gate first, then stop the services and delete. A
            // server that never held the tree closes too: whatever an older
            // release or a racing request left open is closed before the
            // files go.
            state_.store(TreeRoleState::Tier2, std::memory_order_release);
            if (hooks_.leave) hooks_.leave();
            if (hooks_.purge) hooks_.purge();
            spdlog::info("[tree-role] this server is not a Tier 1 member: it holds no tree and "
                         "refuses every tree request");
            return;
        }
        case MembershipView::Unknown: {
            // No finalized membership: stop serving, delete nothing.
            if (current != TreeRoleState::Tier1) return;
            state_.store(TreeRoleState::Pending, std::memory_order_release);
            if (hooks_.leave) hooks_.leave();
            spdlog::warn("[tree-role] finalized membership is not known; the tree is not served "
                         "until it is");
            return;
        }
    }
}

}  // namespace nexus::tree
