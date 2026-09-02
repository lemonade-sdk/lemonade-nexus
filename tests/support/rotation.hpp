#pragma once

// Rotation helpers over the driver mesh: one place that turns "run an epoch
// boundary on the production path" into a call, shared by the multi-epoch
// scenarios and the larger-population integration tests.

#include "support/lifecycle_mesh.hpp"

namespace lifecycle_test {

struct RotatingMeshBase : DriverMeshBase {
    using DriverMeshBase::DriverMeshBase;

    /// Continuity and participation for `pool` under the current members.
    /// Every current member first learns the reachable reserves: a member
    /// promoted last epoch challenges candidates exactly like a founder.
    void observe(const std::vector<Node*>& members, const std::vector<Node*>& pool,
                 EpochId epoch) {
        for (Node* member : members) {
            for (Node* reserve : reserves) {
                if (!mesh.offline.contains(reserve->id)) {
                    member->driver->on_peer(reserve->id, mesh.now_ms);
                }
            }
        }
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            run_reattest_cadence(round, pool, members, epoch);
        }
        // Participation witnessing accumulates one leader rotation at a time;
        // a real epoch has an hour of views, the compressed one gets commits
        // until every pool subject met its witness bar on every member.
        for (int i = 0; i < 40; ++i) {
            bool complete = true;
            for (Node* member : members) {
                const auto& service = member->driver->eligibility();
                for (Node* subject : pool) {
                    if (subject == member) continue;
                    const auto evidence =
                        service.ledger().evaluate(subject->id, 1, service.context());
                    if (!evidence.mesh_health_valid || !evidence.uptime_valid) {
                        complete = false;
                        break;
                    }
                }
                if (!complete) break;
            }
            if (complete) return;
            advance_commit(members);
        }
    }

    /// Ages the epoch and steps until every online member opened a transition.
    void run_to_plan(const std::vector<Node*>& members, int max_steps = 1500) {
        mesh.now_ms += constants::kTargetEpochSeconds * 1000;
        for (int i = 0; i < max_steps; ++i) {
            step(1, members);
            const bool planned = std::all_of(members.begin(), members.end(), [](Node* m) {
                return m->runtime->epochs() != nullptr &&
                       m->runtime->epochs()->transition() != nullptr &&
                       m->runtime->epochs()->transition()->phase !=
                           EpochTransitionPhase::Aborted;
            });
            if (planned) return;
        }
        FAIL() << "no plan committed within " << max_steps << " steps";
    }

    [[nodiscard]] std::vector<Node*> selected_nodes(const Node& member) const {
        std::vector<Node*> out;
        if (member.runtime->epochs() == nullptr) {
            ADD_FAILURE() << "member holds no epoch state";
            return out;
        }
        const auto* transition = member.runtime->epochs()->transition();
        EXPECT_NE(transition, nullptr);
        if (transition != nullptr) {
            for (const auto& id : transition->selected_members) {
                out.push_back(mesh.nodes.at(id));
            }
        }
        return out;
    }

    /// Steps until every selected node can present its next-epoch vote key,
    /// which for an outside candidate means its state sync completed.
    void wait_for_keys(const std::vector<Node*>& members, const std::vector<Node*>& selected,
                       EpochId target, int max_steps = 600) {
        for (int i = 0; i < max_steps; ++i) {
            step(1, members);
            const bool keyed = std::all_of(selected.begin(), selected.end(), [&](Node* node) {
                return mesh.offline.contains(node->id) ||
                       node->driver->vote_key_for_epoch(target).has_value();
            });
            if (keyed) return;
        }
        FAIL() << "selected nodes could not register keys within " << max_steps << " steps";
    }

    void run_to_activation(const std::vector<Node*>& members,
                           const std::vector<Node*>& expect_active, EpochId target,
                           int max_steps = 1500) {
        for (int i = 0; i < max_steps; ++i) {
            step(1, members);
            const bool active =
                std::all_of(expect_active.begin(), expect_active.end(), [&](Node* n) {
                    return n->driver->current_epoch() == target;
                });
            if (active) return;
        }
        FAIL() << "epoch " << target << " did not activate within " << max_steps << " steps";
    }

    /// One full rotation on the production path. `pool` is who the mesh
    /// observes this epoch; selection decides from there. Returns the new
    /// member set.
    std::vector<Node*> rotate(const std::vector<Node*>& members, const std::vector<Node*>& pool,
                              EpochId from_epoch) {
        observe(members, pool, from_epoch);
        run_to_plan(members);
        const auto selected = selected_nodes(*members.front());
        if (::testing::Test::HasFatalFailure() || selected.empty()) {
            return members;  // The failure is recorded; do not compound it.
        }
        wait_for_keys(members, selected, from_epoch + 1);
        if (::testing::Test::HasFatalFailure()) {
            return members;
        }
        final_attest_subjects(9, selected, members);
        run_to_activation(members, selected, from_epoch + 1);
        return selected;
    }

    [[nodiscard]] static std::vector<NodeId> ids_of(const std::vector<Node*>& nodes_in) {
        std::vector<NodeId> ids;
        for (const Node* node : nodes_in) ids.push_back(node->id);
        std::sort(ids.begin(), ids.end());
        return ids;
    }
};

}  // namespace lifecycle_test
